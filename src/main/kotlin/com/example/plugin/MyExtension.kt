package com.example.plugin

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import java.io.File
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// Результат проверки ответа сервера на наличие утечек
enum class ResponseCheckResult {
    SAFE,           // Нормальный ответ, нет признаков ошибок
    ERROR_GENERIC,  // Стандартная ошибка (401, 403, 404), не содержит полезных данных
    INFO_LEAK       // Ошибка с утечкой данных (Stack trace, SQL error, внутренние пути)
}

// =========================================================================
// УРОВНИ ВЕРДИКТА IDOR: иерархия результатов анализа мутаций
// sealed class гарантирует исчерпывающий match при обработке результата
// =========================================================================
sealed class IdorVerdict(val severity: String, val label: String) {
    object CriticalModification : IdorVerdict("Critical", "CRITICAL: Data Modification")
    object HighExposure : IdorVerdict("High", "HIGH: Data Exposure")
    object MediumPotential : IdorVerdict("Medium", "MEDIUM: Potential Exposure")
    object SafeDenied : IdorVerdict("Info", "SAFE: Access Denied")
    object FalsePositive : IdorVerdict("Low", "LOW: False Positive / No Impact")
}

// Результат анализа одной мутации: вердикт + метрики для detailsMessage
data class IdorAnalysisResult(
    val verdict: IdorVerdict,
    val statusCode: Int,
    val containsVictimId: Boolean,
    val containsSensitiveData: Boolean,
    val similarityPercentage: Double, // Процент РАЗЛИЧИЯ тел ответов (0.0 == идентичны)
    val detailsMessage: String        // Готовый многострочный текст для колонки Details
) {
    companion object {
        // Порог семантической идентичности: различие ответов не выше 1% трактуется как "ответы совпадают"
        const val IDENTICAL_SIMILARITY_THRESHOLD_PERCENT = 99.0
    }

    // Признак того, что baseline и мутированный ответ практически не различаются
    val isResponseIdentical: Boolean get() = similarityPercentage <= 100.0 - IDENTICAL_SIMILARITY_THRESHOLD_PERCENT
}

class MyExtension : BurpExtension {

    // Fail-fast флаг: ошибка запуска внешнего инструмента выводится однократно за сессию,
    // чтобы отсутствие бинарника в PATH не генерировало дубликаты на каждый запрос.
    // Сбрасывается при сохранении настроек — пользователю даётся шанс проверить исправление пути без перезагрузки Burp
    @Volatile
    private var nucleiUnavailableLogged = false

    // Повторная инициализация оркестрации после изменения пути к внешнему инструменту
    fun resetExternalToolsState() {
        nucleiUnavailableLogged = false
    }

    // Снимок полного аудита для экспорта: копирует потокобезопасный буфер в обычный список для сериализации Jackson
    fun auditSnapshot(): List<AuditStep> = auditLog.toList()

    companion object {
        // Порог значимого различия тел ответов: > 15% правок Левенштейна = ответ изменён
        const val DIFF_THRESHOLD_PERCENT = 15.0

        // Геттер активного экземпляра: позволяет диалогу настроек сбросить fail-fast флаг без передачи ссылки через конструктор
        val currentInstance: MyExtension? get() = INSTANCE

        @Volatile
        private var INSTANCE: MyExtension? = null
    }

    // Потокобезопасный список для хранения уникальных перехваченных запросов
    private val trackedRequests = CopyOnWriteArrayList<TrackedRequest>()
    private lateinit var dashboard: AutoScannerDashboardPanel

    // Множество для предотвращения спама одинаковых сообщений об утечках в консоль
    private val loggedInfoLeaks = mutableSetOf<String>()

    // Полные тексты всех успешных векторов по URL находки.
    // Хранятся вне UI-модели, чтобы не раздувать таблицу; используются только при подробном экспорте.
    private val allVectorsByFinding = ConcurrentHashMap<String, List<String>>()

    // Буфер полного аудита: каждая проверенная мутация (включая отклонённые вердикты).
    // Потокобезопасная коллекция: фоновые потоки сканера пишут в буфер параллельно с чтением при экспорте.
    private val auditLog = CopyOnWriteArrayList<AuditStep>()

    // Активные скан-сессии (URL -> latch) для корректного определения момента полного завершения
    private val activeSessions = ConcurrentHashMap<String, CountDownLatch>()

    override fun initialize(api: MontoyaApi) {
        // Регистрация экземпляра для обратных вызовов из UI (например, сброс fail-fast флага после сохранения настроек)
        INSTANCE = this

        // Инициализация имени плагина и приветственных логов
        api.extension().setName("Burp AutoScanner Pro")
        api.logging().logToOutput("========================================")
        api.logging().logToOutput("[+] Burp AutoScanner Pro загружен!")
        api.logging().logToOutput("[+] Режим: Async + Safe JSON Mutation + Nuclei Orchestration + UI Dashboard")
        api.logging().logToOutput("========================================")

        // Регистрация кастомной вкладки графического интерфейса
        dashboard = AutoScannerDashboardPanel(api)
        api.userInterface().registerSuiteTab("AutoScanner Dashboard", dashboard)

        // Монитор завершения сканирования: фоновый поток дожидается окончания всех активных сессий
        // и только затем переводит статус-бар в состояние "Завершено" (см. awaitAllScansAndFinalize)
        thread(start = true, isDaemon = true) { awaitAllScansAndFinalize(api) }

        // Регистрация обработчика HTTP-трафика
        api.http().registerHttpHandler(object : HttpHandler {
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
                // Фильтр 1: Обрабатываем только трафик из браузера (Proxy), игнорируя внутренние запросы Burp
                if (requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
                    val cookieHeader = requestToBeSent.headerValue("Cookie")
                    val url = requestToBeSent.url()

                    if (cookieHeader != null) {
                        // Фильтр 2: Проверка наличия маркеров аутентификации
                        val isAuthRequest = ScannerConfig.authMarkers.any { marker ->
                            cookieHeader.contains(marker, ignoreCase = true)
                        }

                        // Фильтр 3: Allowlist (белый список) целевых API-эндпоинтов
                        val isTargetApi = url.contains("/api/") || url.contains("/rest/") ||
                                url.contains("/profile") || url.contains("/basket") ||
                                url.contains("/ftp/") || url.contains("/admin")

                        // Фильтр 4: Игнорирование артефактов фронтенда (NaN, undefined)
                        if (isAuthRequest && isTargetApi && !url.contains("/NaN") && !url.contains("/undefined")) {

                            // Парсинг и извлечение потенциальных векторов для мутации
                            val tracked = TrackedRequest(
                                url = url,
                                method = requestToBeSent.method(),
                                originalRequest = requestToBeSent,
                                pathParams = extractPathParams(url),
                                queryParams = extractQueryParams(url),
                                jsonBodyFields = extractJsonBodyFields(requestToBeSent.bodyToString())
                            )

                            // Проверка на дубликаты, чтобы не анализировать один и тот же запрос дважды
                            if (trackedRequests.none { it.url == tracked.url && it.method == tracked.method }) {
                                trackedRequests.add(tracked)
                                api.logging().logToOutput("[INFO] Целевой запрос сохранен: ${tracked.method} ${tracked.url}")

                                // Обновляем счетчик очереди в UI
                                dashboard.updateQueueSize(trackedRequests.size)

                                // Асинхронный запуск анализа в фоновом потоке (Daemon), чтобы не блокировать UI Burp
                                // Сессия регистрируется до старта потока, чтобы финальный мониторинг
                                // не увидел ноль активных сессий между созданием потока и его запуском
                                val latch = CountDownLatch(1)
                                activeSessions[tracked.url] = latch
                                thread(start = true, isDaemon = true) {
                                    try {
                                        testIdorAdvanced(api, tracked)
                                    } finally {
                                        // Уменьшаем счетчик очереди после завершения анализа
                                        dashboard.updateQueueSize(trackedRequests.size - 1)
                                        latch.countDown()
                                        activeSessions.remove(tracked.url)
                                    }
                                }
                            }
                        }
                    }
                }
                // Пропускаем запрос дальше без изменений
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }

            override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction =
                ResponseReceivedAction.continueWith(responseReceived)
        })
    }

    // =========================================================================
    // СИНХРОНИЗАЦИЯ СОСТОЯНИЯ UI: финализация статуса после завершения всех потоков сканирования
    // Текст "Завершено" выставляется только когда счётчик активных сессий достигает нуля,
    // что исключает преждевременное появление статуса между запуском и окончанием фоновых задач.
    // =========================================================================
    private fun awaitAllScansAndFinalize(api: MontoyaApi) {
        try {
            var idleRounds = 0 // Счётчик пустых проверок подряд: защита от "мёртвого" ожидания при старте
            while (true) {
                val pending = activeSessions.values.toList()
                if (pending.isEmpty()) {
                    if (trackedRequests.isNotEmpty() && ++idleRounds >= 2) {
                        // Все известные сессии завершены, новых перехватов нет: фиксируем итог в UI-потоке
                        dashboard.finalizeScanStatus(trackedRequests.size)
                        return
                    }
                    Thread.sleep(200)
                    continue
                }
                idleRounds = 0
                // Ожидаем окончания текущих сессий; новый URL может появиться во время ожидания —
                // тогда цикл повторяет проверку и ждёт уже расширенный набор latch-ей
                pending.forEach { it.await(500, TimeUnit.MILLISECONDS) }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            api.logging().logToOutput("[!] Монитор завершения сканирования прерван")
        }
    }

    // =========================================================================
    // БЛОК ПАРСИНГА: Извлечение параметров из запроса для последующей мутации
    // =========================================================================

    // Извлекает числовые значения, UUID и префиксные ID из пути URL
    private fun extractPathParams(url: String): List<String> {
        val path = url.substringBefore("?")
        val results = mutableListOf<String>()

        // 1. Обычные числа
        results.addAll(Regex("/(\\d+)(?=/|$)").findAll(path).map { it.value }.toList())
        // 2. UUID
        results.addAll(ScannerConfig.uuidRegex.findAll(path).map { it.value }.toList())
        // 3. Префиксные ID (например, /cart/user_123 -> извлекаем "user_123")
        results.addAll(ScannerConfig.prefixedIdRegex.findAll(path).map { it.value }.toList())

        return results.distinct()
    }

    // Парсит строку запроса (Query String) в Map, оставляя только потенциально опасные параметры
    private fun extractQueryParams(url: String): Map<String, String> {
        val queryPart = url.substringAfter("?", "")
        if (queryPart.isEmpty()) return emptyMap()

        return queryPart.split("&")
            .map { it.split("=", limit = 2) }
            .filter { it.size == 2 }
            // Фильтруем, оставляя только параметры из ScannerConfig.sensitiveFields
            .filter { (key, _) -> ScannerConfig.sensitiveFields.any { field -> key.contains(field, ignoreCase = true) } }
            .associate { it[0] to it[1] }
    }

    // Анализирует JSON-тело и извлекает поля, которые с высокой вероятностью являются идентификаторами или параметрами прав
    private fun extractJsonBodyFields(body: String): Map<String, Any?> {
        if (body.isBlank()) return emptyMap()
        return try {
            val json = ObjectMapper().readTree(body)
            val fields = mutableMapOf<String, Any?>()
            json.fields().forEach { (key, value) ->
                // Эвристика: ищем ключевые слова, характерные для ID-полей и ролей
                if (ScannerConfig.sensitiveFields.any { field -> key.contains(field, ignoreCase = true) }) {
                    fields[key] = when {
                        value.isNumber -> value.asInt()
                        value.isTextual -> value.asText()
                        value.isBoolean -> value.asBoolean()
                        else -> value.toString()
                    }
                }
            }
            fields
        } catch (_: Exception) {
            emptyMap() // Возвращаем пустую карту при невалидном JSON
        }
    }

    // =========================================================================
    // БЛОК МУТАЦИИ: Генерация модифицированных запросов для проверки IDOR и эскалации
    // =========================================================================

    private fun generateMutatedRequests(original: HttpRequest, tracked: TrackedRequest): List<Pair<String, HttpRequest>> {
        val mutations = mutableListOf<Pair<String, HttpRequest>>()

        // 1. Мутация Cookie (базовая проверка на обход аутентификации)
        mutations.add("Cookie: подмена токена" to prepareModifiedRequest(original, "token=invalid_token_12345"))

        // 2. Мутация Path Parameters (замена ID в URL)
        for (param in tracked.pathParams) {
            for (victimId in ScannerConfig.victimIds) {
                mutations.add("PathParam: $param -> /$victimId" to original.withPath(original.url().replaceFirst(param, "/$victimId")))
            }
        }

        // 3. Мутация Query Parameters (безопасная пересборка URL)
        for ((key, value) in tracked.queryParams) {
            for (victimId in ScannerConfig.victimIds) {
                val urlParts = original.url().split("?", limit = 2)
                val query = if (urlParts.size > 1) urlParts[1] else ""
                val newQueryParams = query.split("&").map { param ->
                    val kv = param.split("=", limit = 2)
                    if (kv.size == 2 && kv[0] == key) "$key=$victimId" else param
                }.joinToString("&")
                val newUrl = if (newQueryParams.isEmpty()) urlParts[0] else "${urlParts[0]}?$newQueryParams"
                mutations.add("QueryParam: $key=$value -> $key=$victimId" to original.withPath(newUrl))
            }
        }

        // 4. Мутация JSON Body (безопасная модификация через AST-дерево ObjectNode)
        if (original.bodyToString().isNotBlank()) {
            try {
                val mapper = ObjectMapper()

                // 4.1. Стандартная мутация ID-полей
                for ((key, value) in tracked.jsonBodyFields) {
                    for (victimId in ScannerConfig.victimIds) {
                        val mutationNode = mapper.readTree(original.bodyToString()) as ObjectNode
                        // Сохраняем оригинальный тип данных (Int или String)
                        if (value is Int) mutationNode.put(key, victimId.toIntOrNull() ?: 1)
                        else mutationNode.put(key, victimId)

                        mutations.add("JsonBody: $key -> $victimId" to original.withBody(mapper.writeValueAsString(mutationNode)))
                    }
                }

                // 4.2. Мутация привилегий и ролей (Вертикальная эскалация)
                val roleFields = tracked.jsonBodyFields.keys.filter { k ->
                    ScannerConfig.sensitiveFields.any { field ->
                        k.contains(field, ignoreCase = true) && (field.contains("role") || field.contains("admin") || field.contains("privilege"))
                    }
                }

                for (field in roleFields) {
                    for (payload in ScannerConfig.privilegePayloads) {
                        val mutationNode = mapper.readTree(original.bodyToString()) as ObjectNode
                        if (payload == "true") mutationNode.put(field, true)
                        else if (payload == "false") mutationNode.put(field, false)
                        else if (payload.toIntOrNull() != null) mutationNode.put(field, payload.toInt())
                        else mutationNode.put(field, payload)

                        mutations.add("PrivilegeEscalation: $field -> $payload" to original.withBody(mapper.writeValueAsString(mutationNode)))
                    }
                }
            } catch (_: Exception) { } // Игнорируем ошибки парсинга
        }

        // 5. Мутация HTTP-заголовков (Header-based IDOR / Access Control Bypass)
        for (headerName in ScannerConfig.idorHeaders) {
            for (victimId in ScannerConfig.victimIds) {
                val mutationDesc = "Header: $headerName -> $victimId"
                val mutatedReq = original.withAddedHeader(headerName, victimId)
                mutations.add(mutationDesc to mutatedReq)
            }
        }

        return mutations
    }

    // =========================================================================
    // БЛОК ВСПОМОГАТЕЛЬНЫХ ФУНКЦИЙ
    // =========================================================================

    // Подготовка запроса: удаление заголовков кэша и подмена Cookie
    private fun prepareModifiedRequest(original: HttpRequest, newCookieValue: String): HttpRequest =
        original.withRemovedHeader("If-None-Match")
            .withRemovedHeader("If-Modified-Since")
            .withUpdatedHeader("Cache-Control", "no-cache")
            .withUpdatedHeader("Pragma", "no-cache")
            .withUpdatedHeader("Cookie", newCookieValue)

    // Обертка для отправки запроса и извлечения только части с ответом
    private fun sendRequest(api: MontoyaApi, request: HttpRequest): HttpResponse = api.http().sendRequest(request).response()

    // Алгоритм Левенштейна для оценки семантической близости двух строк (тел ответов)
    private fun levenshteinDistance(s1: String, s2: String): Int {
        val len1 = s1.length; val len2 = s2.length
        val dp = Array(len1 + 1) { IntArray(len2 + 1) }
        for (i in 0..len1) dp[i][0] = i
        for (j in 0..len2) dp[0][j] = j
        for (i in 1..len1) {
            for (j in 1..len2) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            }
        }
        return dp[len1][len2]
    }

    // Очищает JSON-строку от известных динамических полей перед сравнением (снижает False Negatives)
    private fun stripDynamicFields(jsonString: String): String {
        return try {
            val mapper = ObjectMapper()
            val node = mapper.readTree(jsonString)
            val dynamicKeys = listOf("timestamp", "time", "date", "csrf", "token", "nonce", "requestId")

            fun removeKeys(n: com.fasterxml.jackson.databind.JsonNode) {
                if (n.isObject) {
                    val objectNode = n as ObjectNode
                    val fieldNames = objectNode.fieldNames().asSequence().toList()
                    for (fieldName in fieldNames) {
                        if (dynamicKeys.any { fieldName.contains(it, ignoreCase = true) }) {
                            objectNode.remove(fieldName)
                        } else {
                            removeKeys(objectNode.get(fieldName))
                        }
                    }
                } else if (n.isArray) {
                    n.forEach { removeKeys(it) }
                }
            }
            removeKeys(node)
            mapper.writeValueAsString(node)
        } catch (_: Exception) {
            jsonString // Если не JSON, возвращаем как есть
        }
    }

    // Умная проверка ответа на наличие утечек информации (Info Disclosure)
    private fun checkResponseForLeaks(body: String, statusCode: Int = 0): ResponseCheckResult {
        val lower = body.lowercase()

        // Игнорируем стандартные 401/403 ответы, если они содержат типичный JSON с данными пользователя, а не стек-трейс
        if (statusCode == 401 || statusCode == 403) {
            try {
                val json = ObjectMapper().readTree(body)
                if (json.has("user") && (json.get("user").has("id") || json.get("user").has("email"))) {
                    return ResponseCheckResult.ERROR_GENERIC
                }
                if (json.has("id") && json.has("email")) {
                    return ResponseCheckResult.ERROR_GENERIC
                }
                if (json.has("error") && json.has("message")) {
                    return ResponseCheckResult.ERROR_GENERIC
                }
            } catch (_: Exception) {
                // Не JSON или ошибка парсинга - продолжаем проверку по ключевым словам
            }
        }

        // Строгие паттерны утечек (стек-трейсы, SQL, пути, отладка)
        if (ScannerConfig.infoLeakKeywords.any { lower.contains(it) }) {
            return ResponseCheckResult.INFO_LEAK
        }

        if (ScannerConfig.genericErrors.any { lower.contains(it) }) {
            return ResponseCheckResult.ERROR_GENERIC
        }

        return ResponseCheckResult.SAFE
    }

    // =========================================================================
    // АНАЛИЗАТОР ВЕРДИКТА IDOR: многошаговая классификация ответа на мутацию
    // Чистая функция: не трогает UI и сеть, потокобезопасна по своим данным.
    // Читает config только через локальные val-копии (Set может редактироваться
    // из SettingsDialog в UI-потоке -> снижаем риск ConcurrentModification).
    // =========================================================================
    fun analyzeIdorResponse(
        originalMethod: String,
        victimId: String,
        baselineResponse: HttpResponse,
        mutatedResponse: HttpResponse,
        config: ScannerConfig
    ): IdorAnalysisResult {
        val status: Int = mutatedResponse.statusCode().toInt()
        val mutatedBody = mutatedResponse.bodyToString()
        val method = originalMethod.uppercase()
        val genericErrors = config.genericErrors.toList()   // snapshot вместо итерации по MutableSet
        val sensitiveFields = config.sensitiveFields.toList()

        // Формирование информативного detailsMessage для колонки Details
        fun buildDetails(
            verdict: IdorVerdict,
            diffPct: Double = 0.0,
            victimReflected: Boolean = false,
            sensitiveFound: Boolean = false,
            explanation: String
        ) = """
            [${verdict.label}]
            Status Code: $status
            Method: $method
            Response Diff: ${"%.1f".format(diffPct)}%
            Victim ID Reflected: $victimReflected
            Sensitive Data Found: $sensitiveFound
            $explanation
        """.trimIndent()

        fun result(verdict: IdorVerdict, victim: Boolean = false, sensitive: Boolean = false,
                   diff: Double = 0.0, explanation: String) =
            IdorAnalysisResult(verdict, status, victim, sensitive, diff,
                buildDetails(verdict, diff, victim, sensitive, explanation))

        // --- Шаг 1: доступ запрещён на уровне HTTP-статуса ---
        if (status in setOf(401, 403, 404)) {
            return result(IdorVerdict.SafeDenied,
                explanation = "Сервер корректно отклонил мутированный запрос (HTTP $status). Контроль доступа работает.")
        }

        // Кэш diff-а для state-changing методов: считаем один раз при необходимости
        fun responseDiffPercent(): Double {
            val baseline = stripDynamicFields(baselineResponse.bodyToString())
            val mutated = stripDynamicFields(mutatedBody)
            val distance = levenshteinDistance(baseline, mutated)
            return 100.0 - (distance.toDouble() / maxOf(baseline.length, mutated.length, 1) * 100.0)
        }

        // --- Шаг 2: запись данных чужим объектом (State-Changing методы + 2xx) ---
        if (method in setOf("POST", "PUT", "PATCH", "DELETE") && status in 200..299) {
            val lower = mutatedBody.lowercase()
            val hasGenericError = genericErrors.any { lower.contains(it) }
            if (!hasGenericError) {
                val diff = responseDiffPercent()
                val identical = diff <= 100.0 - IdorAnalysisResult.IDENTICAL_SIMILARITY_THRESHOLD_PERCENT
                val explanation = if (identical) {
                    // Успешный 2xx на модификацию — сам факт отсутствия отказа уже является доказательством
                    // BOLA; идентичность тела не отменяет вердикт
                    "Операция изменения/удаления выполнена успешно (статус $status). " +
                            "Отсутствие ошибок указывает на отсутствие контроля доступа (BOLA)."
                } else {
                    "$method вернул $status без признаков отказа: операция изменения данных " +
                            "над чужим объектом (victim_id='$victimId') выполнена. Вероятна Horizontal/Vertical Privilege Escalation."
                }
                return result(IdorVerdict.CriticalModification, diff = diff, explanation = explanation)
            }
            return result(IdorVerdict.SafeDenied,
                explanation = "$method отклонён на уровне тела ответа (generic error). Запись не произведена.")
        }

        // --- Шаг 3: чтение данных (GET + 2xx) ---
        if (method == "GET" && status in 200..299) {
            // 3а: отказ, «зашитый» в тело 200-го ответа
            val lower = mutatedBody.lowercase()
            if (genericErrors.any { lower.contains(it) }) {
                return result(IdorVerdict.SafeDenied,
                    explanation = "HTTP $status, но тело содержит признак отказа (generic error). Доступ к данным не получен.")
            }

            // 3б: рефлексия идентификатора жертвы в ответе
            val containsVictimId = mutatedBody.contains(victimId)

            // 3в: любые ключи/значения чувствительных полей в теле ответа
            val containsSensitiveData = sensitiveFields.any { field ->
                mutatedBody.contains(field, ignoreCase = true)
            }

            // 3г: сравнение ответов после очистки динамических полей (metric-safe Levenshtein)
            val baseline = stripDynamicFields(baselineResponse.bodyToString())
            val mutated = stripDynamicFields(mutatedBody)
            val distance = levenshteinDistance(baseline, mutated)
            val diffPercentage = 100.0 - (distance.toDouble() / maxOf(baseline.length, mutated.length, 1) * 100.0)

            val hasEvidence = containsVictimId || containsSensitiveData
            val isDifferent = diffPercentage > DIFF_THRESHOLD_PERCENT
            val identical = diffPercentage <= 100.0 - IdorAnalysisResult.IDENTICAL_SIMILARITY_THRESHOLD_PERCENT

            return when {
                // 3д: есть доказательства утечки И ответы существенно различаются
                hasEvidence && isDifferent -> result(
                    IdorVerdict.HighExposure, containsVictimId, containsSensitiveData, diffPercentage,
                    explanation = if (identical) {
                        // Ответы семантически идентичны: совпадение ID/полей в одинаковых шаблонах
                        // не доказывает чтение чужих данных — исключаем ложные утверждения
                        "Ответы семантически идентичны (Diff: ${"%.1f".format(diffPercentage)}%). " +
                                "Возможный False Positive или публичный ресурс."
                    } else {
                        // Формулировка согласована с метрикой: указывается именно процент РАЗЛИЧИЯ ответов
                        "Ответ на мутированный запрос отличается от baseline на ${"%.1f".format(diffPercentage)}% " +
                                "и содержит " + listOfNotNull(
                            if (containsVictimId) "ID жертвы ('$victimId')" else null,
                            if (containsSensitiveData) "чувствительные поля" else null
                        ).joinToString(" и ") + ". Чужие данные прочитаны."
                    }
                )
                // 3е: прямых доказательств нет, но содержимое изменилось — косвенный признак
                !hasEvidence && isDifferent -> result(
                    IdorVerdict.MediumPotential, false, false, diffPercentage,
                    explanation = "Прямых маркеров (victim id / sensitive fields) не найдено, но тело ответа " +
                            "существенно отличается от baseline (Различие ответов: ${"%.1f".format(diffPercentage)}%, " +
                            "${distance} правок Левенштейна). Требуется ручная проверка в Repeater."
                )
                // 3ж: ответы почти идентичны — мутация проигнорирована сервером
                else -> result(
                    IdorVerdict.FalsePositive, containsVictimId, containsSensitiveData, diffPercentage,
                    explanation = if (identical) {
                        // Идентичные ответы: утверждения об утечке чужих данных исключены
                        "Ответы семантически идентичны (Diff: ${"%.1f".format(diffPercentage)}%). " +
                                "Возможный False Positive или публичный ресурс."
                    } else {
                        "Различие ответов <= ${Companion.DIFF_THRESHOLD_PERCENT}%: сервер вернул тот же контент, что и baseline. " +
                                "Параметр/заголовок '$victimId' на обработку не влияет."
                    }
                )
            }
        }

        // --- Фолбэк: нестандартная комбинация метода/статуса ---
        return result(IdorVerdict.FalsePositive,
            explanation = "Комбинация '$method / HTTP $status' не попадает ни под один сценарий эксплуатации. Анализ пропущен.")
    }

    // =========================================================================
    // АГРЕГАЦИЯ ОТЧЁТА: компактный структурированный details без "простыни" векторов
    // Positive verdict = CriticalModification / HighExposure / MediumPotential
    // (SafeDenied и FalsePositive в список успешных не попадают)
    // =========================================================================

    // Проверка принадлежности вердикта к классу подтверждённых находок
    private fun IdorVerdict.isVulnerable(): Boolean = when (this) {
        IdorVerdict.CriticalModification,
        IdorVerdict.HighExposure,
        IdorVerdict.MediumPotential -> true
        else -> false
    }

    /**
     * Генерирует строго форматированный текст для поля details.
     * Агрегация успешных векторов: вывод ограничивается тремя примерами для компактности отчёта;
     * остальные помечаются строкой "... and N more vectors", полный список сохраняется в буфер находок
     * и выгружается только при подробном экспорте.
     */
    fun generateStructuredDetails(
        finding: VulnerabilityFinding,
        analysisResults: List<Pair<String, IdorAnalysisResult>>,
        totalTested: Int = analysisResults.size
    ): String {
        // Статистика берётся из best-вектора (максимальная критичность, при равенстве — максимальный diff)
        val severityRank = mapOf("Critical" to 4, "High" to 3, "Medium" to 2, "Low" to 1, "Info" to 0)
        val best = analysisResults.maxByOrNull { (severityRank[it.second.verdict.severity] ?: 0) * 1000 + it.second.similarityPercentage.toInt() }
            ?.second

        return buildString {
            appendLine("=== IDOR FINDING ===")
            appendLine(best?.verdict?.label ?: "Verdict: ${finding.type} (${finding.severity})")
            appendLine("Severity: ${finding.severity}")
            appendLine("URL: ${finding.url}")
            appendLine()
            appendLine("-- Successful Vectors Preview (${finding.successfulVectors.size}) --")
            if (finding.successfulVectors.isEmpty()) {
                appendLine("(none)")
            } else {
                // Не более 3-х примеров векторов, давших положительный вердикт
                finding.successfulVectors.take(3).forEach { appendLine("* $it") }
                // Скрытые записи: общее число попаданий минус отображённые примеры
                val totalHits = analysisResults.size.coerceAtLeast(finding.successfulVectors.size)
                if (totalHits > 3) {
                    appendLine("... and ${totalHits - 3} more vectors")
                }
            }
            appendLine()
            appendLine("-- Statistics --")
            appendLine("Total Tested: $totalTested")
            appendLine("Successful Hits: ${analysisResults.size}")
            appendLine("Max Response Diff: ${best?.let { "%.1f".format(it.similarityPercentage) + "%" } ?: "N/A"}")
            appendLine("Victim ID Reflected: ${finding.victimIdReflected}")
            appendLine("Sensitive Data Found: ${finding.sensitiveDataFound}")
            appendLine()
            appendLine("-- Analysis --")
            // Текстовый блок анализатора содержит ту же метрику различия, что и поле responseDiff,
            // поэтому дублирование строк Status/Method/Diff из detailsMessage исключено
            val message = best?.detailsMessage.orEmpty()
            appendLine(message.lines().dropWhile { line ->
                line.startsWith("[") || line.startsWith("Status Code:") || line.startsWith("Method:") ||
                        line.startsWith("Response Diff:") || line.startsWith("Victim ID Reflected:") ||
                        line.startsWith("Sensitive Data Found:")
            }.joinToString("\n").trim())
        }.trimEnd()
    }

    /**
     * Second-pass перегенерация компактного отчёта для уже сохранённой находки.
     * Используется при экспорте: позволяет восстановить Statistics/Analysis по полному списку
     * векторов без повторного сетевого анализа.
     */
    fun rebuildDetailsFromFinding(
        finding: VulnerabilityFinding,
        allSuccessfulVectors: List<String>,
        verdictLabel: String? = null
    ): String {
        val displayVectors = allSuccessfulVectors.take(3)
        val diffText = finding.responseDiff?.let { "%.1f".format(it) } ?: "N/A"
        val identical = finding.responseDiff != null &&
                finding.responseDiff <= 100.0 - IdorAnalysisResult.IDENTICAL_SIMILARITY_THRESHOLD_PERCENT

        return buildString {
            appendLine("=== IDOR FINDING ===")
            appendLine(verdictLabel ?: finding.details.lineSequence().firstOrNull { it.startsWith("[") } ?: "Verdict: ${finding.type} (${finding.severity})")
            appendLine("Severity: ${finding.severity}")
            appendLine("URL: ${finding.url}")
            appendLine()
            appendLine("-- Successful Vectors Preview (${allSuccessfulVectors.size}) --")
            if (displayVectors.isEmpty()) {
                appendLine("(none)")
            } else {
                displayVectors.forEach { appendLine("* $it") }
                if (allSuccessfulVectors.size > 3) {
                    appendLine("... and ${allSuccessfulVectors.size - 3} more vectors")
                }
            }
            appendLine()
            appendLine("-- Statistics --")
            appendLine("Total Tested: N/A")
            appendLine("Successful Hits: ${allSuccessfulVectors.size}")
            appendLine("Max Response Diff: $diffText${if (finding.responseDiff != null) "%" else ""}")
            appendLine("Victim ID Reflected: ${finding.victimIdReflected}")
            appendLine("Sensitive Data Found: ${finding.sensitiveDataFound}")
            appendLine()
            appendLine("-- Analysis --")
            appendLine(
                if (identical) {
                    "Ответы семантически идентичны (Diff: $diffText%). Возможный False Positive или публичный ресурс."
                } else if (finding.responseDiff != null) {
                    "Ответ на мутированный запрос отличается от baseline на $diffText%. " +
                            "Чужие данные прочитаны."
                } else {
                    "Метрика различия ответов недоступна."
                }
            )
        }.trimEnd()
    }

    // =========================================================================
    // БЛОК АНАЛИЗА И ОРКЕСТРАЦИИ
    // =========================================================================

    private fun testIdorAdvanced(api: MontoyaApi, tracked: TrackedRequest) {
        try {
            // 1. Формируем "чистый" запрос, очищенный от заголовков кэша браузера
            val cleanOriginalRequest = tracked.originalRequest
                .withRemovedHeader("If-None-Match")
                .withRemovedHeader("If-Modified-Since")
                .withUpdatedHeader("Cache-Control", "no-cache")

            // 2. Получаем базовую линию (Baseline)
            val originalResponse = sendRequest(api, cleanOriginalRequest)

            // 3. Baseline Check: если исходный запрос неуспешен (не 2xx), проверяем его на Info Disclosure, иначе пропускаем
            if (originalResponse.statusCode() !in 200..299) {
                if (checkResponseForLeaks(originalResponse.bodyToString(), originalResponse.statusCode().toInt()) == ResponseCheckResult.INFO_LEAK) {
                    if (loggedInfoLeaks.add(tracked.url)) {
                        api.logging().logToOutput("[!] НАЙДЕНА УТЕЧКА ИНФОРМАЦИИ (в исходном ответе): ${tracked.url}")
                    }
                    dashboard.addFinding(VulnerabilityFinding(
                        url = tracked.url,
                        type = "Info Disclosure",
                        severity = "Medium",
                        details = "Исходный запрос вернул ошибку (${originalResponse.statusCode()}) с признаками утечки",
                        request = cleanOriginalRequest
                    ))
                }
                api.logging().logToOutput("[INFO] Пропуск анализа ${tracked.url}: исходный статус ${originalResponse.statusCode()}")
                return
            }

            // 4. Генерируем мутации СРАЗУ, чтобы знать общее количество для прогресс-бара
            val mutations = generateMutatedRequests(cleanOriginalRequest, tracked)
            val totalMutations = mutations.size

            // Обновляем UI: начинаем сканирование
            dashboard.updateScanStatus(tracked.url, totalMutations, trackedRequests.size)

            val vulnerableMutations = mutableListOf<Pair<String, IdorAnalysisResult>>()
            var testedCount = 0 // Счётчик реально отправленных мутаций для строки Statistics

            // 5. Проверяем все возможные мутации с обновлением прогресса
            for ((index, pair) in mutations.withIndex()) {
                val (mutationType, mutatedRequest) = pair

                // Обновляем прогресс-бар
                dashboard.updateScanProgress(index + 1)
                testedCount++

                val mutatedResponse = sendRequest(api, mutatedRequest)
                val checkResult = checkResponseForLeaks(mutatedResponse.bodyToString(), mutatedResponse.statusCode().toInt())

                // СЦЕНАРИЙ А: Обнаружена утечка информации (Info Disclosure)
                if (checkResult == ResponseCheckResult.INFO_LEAK) {
                    if (loggedInfoLeaks.add(tracked.url)) {
                        api.logging().logToOutput("[!] НАЙДЕНА УТЕЧКА ИНФОРМАЦИИ (Info Disclosure): ${tracked.url}")
                    }
                    dashboard.addFinding(VulnerabilityFinding(
                        url = tracked.url,
                        type = "Info Disclosure",
                        severity = "Medium",
                        details = "Ответ содержит признаки утечки при мутации: $mutationType",
                        request = mutatedRequest,
                        statusCode = mutatedResponse.statusCode().toInt()
                    ))
                }
                // СЦЕНАРИЙ Б: Ответ безопасен, проверяем на IDOR через новый анализатор вердиктов
                else {
                    val extractedVictimId = ScannerConfig.victimIds.firstOrNull { mutationType.contains(it) } ?: ""
                    val analysis = analyzeIdorResponse(
                        originalMethod = tracked.method,
                        victimId = extractedVictimId,
                        baselineResponse = originalResponse,
                        mutatedResponse = mutatedResponse,
                        config = ScannerConfig
                    )

                    // Подробный аудит пишется для каждой мутации только при включённом режиме verboseExport;
                    // в памяти удерживается сниппет тела ответа ограниченной длины
                    if (ScannerConfig.verboseExport) {
                        auditLog.add(
                            AuditStep(
                                url = tracked.url,
                                method = tracked.method,
                                vectorType = mutationType,
                                mutatedRequestRaw = mutatedRequest.toString(),
                                responseStatusCode = analysis.statusCode,
                                responseBodySnippet = mutatedResponse.bodyToString().take(500),
                                verdictLabel = analysis.verdict.label,
                                responseDiffPercent = analysis.similarityPercentage,
                                victimIdReflected = analysis.containsVictimId,
                                sensitiveDataFound = analysis.containsSensitiveData
                            )
                        )
                    }

                    // В уязвимые идут только подтверждённые вердикты (Critical / High / Medium);
                    // SafeDenied / FalsePositive отсекаются и не попадают в список успешных векторов
                    if (analysis.verdict.isVulnerable()) {
                        vulnerableMutations.add(mutationType to analysis)
                    }
                }
            }

            // 6. Формирование вердикта и исключение известных публичных эндпоинтов (False Positives)
            if (vulnerableMutations.isNotEmpty()) {
                val isKnownPublic = ScannerConfig.publicEndpoints.any { endpoint ->
                    tracked.url.contains(endpoint, ignoreCase = true)
                }

                if (isKnownPublic) {
                    api.logging().logToOutput("[*] Игнорировано: Публичный эндпоинт ${tracked.url} (False Positive)")
                } else {
                    // Агрегируем: берём вектор с максимальным уровнем критичности
                    val severityRank = mapOf(
                        "Critical" to 4, "High" to 3, "Medium" to 2, "Low" to 1, "Info" to 0
                    )
                    val (bestVector, bestAnalysis) = vulnerableMutations.maxByOrNull {
                        severityRank[it.second.verdict.severity] ?: 0
                    } ?: vulnerableMutations.first()

                    api.logging().logToOutput("[!] НАЙДЕНА ПОТЕНЦИАЛЬНАЯ IDOR [${bestAnalysis.verdict.severity}]: ${tracked.url}")
                    // В лог консоли выводится не более 3-х векторов; полный список сохраняется в буфер находок
                    api.logging().logToOutput(
                        "[!] Подозрительные векторы (${vulnerableMutations.size}): " +
                                vulnerableMutations.take(3).joinToString(", ") { it.first } +
                                if (vulnerableMutations.size > 3) " ... and ${vulnerableMutations.size - 3} more" else ""
                    )

                    // Полный список успешных векторов сохраняем вне UI-модели для подробного экспорта
                    allVectorsByFinding[tracked.url] = vulnerableMutations.map { it.first }

                    // Находка: severity из вердикта best-вектора, details — компактный структурированный отчёт
                    val finding = VulnerabilityFinding(
                        url = tracked.url,
                        type = "IDOR",
                        severity = bestAnalysis.verdict.severity,   // из вердикта, а не хардкод "High"
                        details = "",                                // заполняется ниже через generateStructuredDetails
                        request = cleanOriginalRequest,
                        // В модель попадает максимум 3 вектора — остальные доступны только через audit-экспорт
                        successfulVectors = vulnerableMutations.map { it.first }.take(3),
                        statusCode = bestAnalysis.statusCode,
                        responseDiff = bestAnalysis.similarityPercentage,
                        victimIdReflected = bestAnalysis.containsVictimId,
                        sensitiveDataFound = bestAnalysis.containsSensitiveData
                    )

                    dashboard.addFinding(
                        finding.copy(
                            details = generateStructuredDetails(finding, vulnerableMutations, totalTested = testedCount)
                        )
                    )
                }
            }

            // 7. Триггер оркестрации: если в запросе есть параметры, запускаем параллельный скан Nuclei
            if (tracked.queryParams.isNotEmpty() || tracked.jsonBodyFields.isNotEmpty() || tracked.method == "POST") {
                thread(start = true, isDaemon = true) { runNucleiScan(api, cleanOriginalRequest) }
            }

        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка при анализе ${tracked.url}: ${e.message}")
        } finally {
            // Сообщаем Dashboard о завершении анализа этого URL для корректной работы прогресс-бара
            // (Важно: используем размер сгенерированных мутаций, а не empty list)
            val mutationsCount = generateMutatedRequests(tracked.originalRequest, tracked).size
            dashboard.completeScanUrl(mutationsCount)
        }
    }

    private fun runNucleiScan(api: MontoyaApi, request: HttpRequest) {
        // Путь к бинарному файлу берётся из конфигурации; пустое значение — фоллбэк на поиск по PATH
        val nucleiPath = ScannerConfig.nucleiExecutablePath.ifBlank { "nuclei" }
        var tempFile: File? = null
        try {
            // Создание временного файла с Raw HTTP запросом
            tempFile = File.createTempFile("autoscan_req_", ".txt").apply { writeText(request.toString()) }

            // Настройка процесса: вывод в NDJSON, таймаут на один запрос
            val processBuilder = ProcessBuilder(listOf(nucleiPath, "-l", tempFile.absolutePath, "-json", "-timeout", "30")).apply {
                redirectErrorStream(true)
            }
            api.logging().logToOutput("[NUCLEI] Запуск сканирования: ${request.url()}")

            val process = processBuilder.start()
            val reader = process.inputStream.bufferedReader()
            val mapper = ObjectMapper()
            var findingsCount = 0
            var line: String?

            // Построчное чтение NDJSON вывода Nuclei
            while (reader.readLine().also { line = it } != null) {
                try {
                    val jsonNode = mapper.readTree(line)
                    val info = jsonNode["info"]
                    val severity = info?.get("severity")?.asText()?.uppercase() ?: "UNKNOWN"

                    // Фильтруем информационные сообщения, оставляем только реальные находки
                    if (severity != "INFO" && severity != "UNKNOWN") {
                        findingsCount++
                        api.logging().logToOutput("[NUCLEI] НАЙДЕНО: [$severity] ${info?.get("name")?.asText() ?: "Unknown"}")
                        dashboard.addFinding(VulnerabilityFinding(
                            url = jsonNode["matched-at"]?.asText() ?: request.url(),
                            type = "Nuclei",
                            severity = severity,
                            details = info?.get("name")?.asText() ?: "Unknown",
                            request = request,
                            statusCode = jsonNode["status-code"]?.asInt() ?: 0
                        ))
                    }
                } catch (_: Exception) { } // Игнорируем служебные строки, не являющиеся JSON
            }

            process.waitFor()
            api.logging().logToOutput("[NUCLEI] Сканирование завершено для: ${request.url()} (Найдено: $findingsCount)")
        } catch (e: IOException) {
            // Выводим ошибку отсутствия Nuclei только один раз за сессию, чтобы избежать спама в консоли Burp
            if (!nucleiUnavailableLogged) {
                nucleiUnavailableLogged = true
                api.logging().logToOutput(
                    "[NUCLEI] Ошибка запуска Nuclei. Проверьте путь в настройках: $nucleiPath. " +
                            "Укажите абсолютный путь к бинарнику (например, /home/kali/go/bin/nuclei или C:\\nuclei\\nuclei.exe) " +
                            "в Settings -> External Tools."
                )
            }
        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка Nuclei: ${e.message}")
        } finally {
            tempFile?.delete() // Очистка временных файлов выполняется при любом исходе
        }
    }
}