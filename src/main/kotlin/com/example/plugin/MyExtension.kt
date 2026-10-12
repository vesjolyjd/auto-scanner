package com.example.plugin

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import java.io.File

// Результат проверки ответа сервера на наличие утечек
enum class ResponseCheckResult {
    SAFE,           // Нормальный ответ, нет признаков ошибок
    ERROR_GENERIC,  // Стандартная ошибка (401, 403, 404), не содержит полезных данных
    INFO_LEAK       // Ошибка с утечкой данных (Stack trace, SQL error, внутренние пути)
}

class MyExtension : BurpExtension {
    // Потокобезопасный список для хранения уникальных перехваченных запросов
    private val trackedRequests = CopyOnWriteArrayList<TrackedRequest>()
    private lateinit var dashboard: AutoScannerDashboardPanel

    override fun initialize(api: MontoyaApi) {
        // Инициализация имени плагина и приветственных логов
        api.extension().setName("Burp AutoScanner Pro")
        api.logging().logToOutput("========================================")
        api.logging().logToOutput("[+] Burp AutoScanner Pro загружен!")
        api.logging().logToOutput("[+] Режим: Async + Safe JSON Mutation + Nuclei Orchestration + UI Dashboard")
        api.logging().logToOutput("========================================")

        // Регистрация кастомной вкладки графического интерфейса
        dashboard = AutoScannerDashboardPanel(api)
        api.userInterface().registerSuiteTab("AutoScanner Dashboard", dashboard)

        // Регистрация обработчика HTTP-трафика
        api.http().registerHttpHandler(object : HttpHandler {
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
                // Фильтр 1: Обрабатываем только трафик из браузера (Proxy), игнорируя внутренние запросы Burp
                if (requestToBeSent.toolSource().isFromTool(burp.api.montoya.core.ToolType.PROXY)) {
                    val cookieHeader = requestToBeSent.headerValue("Cookie")
                    val url = requestToBeSent.url()

                    if (cookieHeader != null) {
                        // Фильтр 2: Проверка наличия маркеров аутентификации
                        val isAuthRequest = ScannerConfig.authMarkers.any { marker ->
                            cookieHeader.contains(marker, ignoreCase = true)
                        }

                        // Фильтр 3: Allowlist (белый список) целевых API-эндпоинтов
                        val isTargetApi = url.contains("/api/") || url.contains("/rest/") || url.contains("/profile") || url.contains("/basket") || url.contains("/ftp/") || url.contains("/admin")

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

                                // Асинхронный запуск анализа в фоновом потоке (Daemon), чтобы не блокировать UI Burp
                                thread(start = true, isDaemon = true) { testIdorAdvanced(api, tracked) }
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
    // БЛОК ПАРСИНГА: Извлечение параметров из запроса для последующей мутации
    // =========================================================================

    // Извлекает числовые значения из пути URL (например, "/users/5" -> ["/5"])
    private fun extractPathParams(url: String): List<String> =
        Regex("/(\\d+)(?=/|$)").findAll(url.substringBefore("?")).map { it.value }.toList()

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
        } catch (_: Exception) { emptyMap() } // Возвращаем пустую карту при невалидном JSON
    }

    // =========================================================================
    // БЛОК МУТАЦИИ: Генерация модифицированных запросов для проверки IDOR и эскалации
    // =========================================================================

    private fun generateMutatedRequests(original: HttpRequest, tracked: TrackedRequest, victimIds: List<String> = listOf("1", "2", "3", "4", "5", "999")): List<Pair<String, HttpRequest>> {
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

        // 4. Мутация JSON Body (безопасная модификация через AST-дерево ObjectNode, а не через String.replace)
        if (original.bodyToString().isNotBlank()) {
            try {
                val mapper = ObjectMapper()

                // 4.1. Стандартная мутация ID-полей
                for ((key, value) in tracked.jsonBodyFields) {
                    for (victimId in victimIds) {
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

    // Проверка ответа на наличие утечек информации (Info Disclosure)
    private fun checkResponseForLeaks(body: String): ResponseCheckResult {
        val lower = body.lowercase()

        if (ScannerConfig.infoLeakKeywords.any { lower.contains(it) }) {
            return ResponseCheckResult.INFO_LEAK
        }

        if (ScannerConfig.genericErrors.any { lower.contains(it) }) {
            return ResponseCheckResult.ERROR_GENERIC
        }

        return ResponseCheckResult.SAFE
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
                if (checkResponseForLeaks(originalResponse.bodyToString()) == ResponseCheckResult.INFO_LEAK) {
                    api.logging().logToOutput("[!] НАЙДЕНА УТЕЧКА ИНФОРМАЦИИ (в исходном ответе): ${tracked.url}")
                    dashboard.addFinding(VulnerabilityFinding(
                        url = tracked.url,
                        type = "Info Disclosure",
                        severity = "Medium",
                        details = "Исходный запрос вернул ошибку (${originalResponse.statusCode()}) с признаками утечки (stack trace, SQL error и т.д.)",
                        request = cleanOriginalRequest
                    ))
                }
                api.logging().logToOutput("[INFO] Пропуск анализа ${tracked.url}: исходный статус ${originalResponse.statusCode()} (требуется 2xx)")
                return
            }

            // 4. Генерируем и проверяем все возможные мутации
            val vulnerableMutations = mutableListOf<String>()
            for ((mutationType, mutatedRequest) in generateMutatedRequests(cleanOriginalRequest, tracked)) {
                val mutatedResponse = sendRequest(api, mutatedRequest)
                val checkResult = checkResponseForLeaks(mutatedResponse.bodyToString())

                // СЦЕНАРИЙ А: Обнаружена утечка информации (Info Disclosure)
                if (checkResult == ResponseCheckResult.INFO_LEAK) {
                    api.logging().logToOutput("[!] НАЙДЕНА УТЕЧКА ИНФОРМАЦИИ (Info Disclosure): ${tracked.url}")
                    dashboard.addFinding(VulnerabilityFinding(
                        url = tracked.url,
                        type = "Info Disclosure",
                        severity = "Medium",
                        details = "Ответ содержит признаки утечки при мутации: $mutationType",
                        request = mutatedRequest
                    ))
                }
                // СЦЕНАРИЙ Б: Ответ безопасен, проверяем на классический IDOR
                else if (checkResult != ResponseCheckResult.ERROR_GENERIC) {
                    if (originalResponse.statusCode() == mutatedResponse.statusCode() &&
                        originalResponse.bodyToString().length == mutatedResponse.bodyToString().length &&
                        levenshteinDistance(originalResponse.bodyToString(), mutatedResponse.bodyToString()) < 50) {
                        vulnerableMutations.add(mutationType)
                    }
                }
            }

            // 5. Формирование вердикта и исключение известных публичных эндпоинтов (False Positives)
            if (vulnerableMutations.isNotEmpty()) {
                val isKnownPublic = ScannerConfig.publicEndpoints.any { endpoint ->
                    tracked.url.contains(endpoint, ignoreCase = true)
                }

                if (isKnownPublic) {
                    api.logging().logToOutput("[*] Игнорировано: Публичный эндпоинт ${tracked.url} (False Positive)")
                } else {
                    api.logging().logToOutput("[!] НАЙДЕНА ПОТЕНЦИАЛЬНАЯ IDOR: ${tracked.url}")
                    api.logging().logToOutput("[!] Подозрительные векторы: ${vulnerableMutations.joinToString(", ")}")

                    dashboard.addFinding(VulnerabilityFinding(
                        url = tracked.url,
                        type = "IDOR",
                        severity = "High",
                        details = "Векторы: ${vulnerableMutations.joinToString(", ")}",
                        request = cleanOriginalRequest
                    ))
                }
            }

            // 6. Триггер оркестрации: если в запросе есть параметры, запускаем параллельный скан Nuclei
            if (tracked.queryParams.isNotEmpty() || tracked.jsonBodyFields.isNotEmpty() || tracked.method == "POST") {
                thread(start = true, isDaemon = true) { runNucleiScan(api, cleanOriginalRequest) }
            }
        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка при анализе ${tracked.url}: ${e.message}")
        }
    }

    private fun runNucleiScan(api: MontoyaApi, request: HttpRequest) {
        try {
            // Создание временного файла с Raw HTTP запросом
            val tempFile = File.createTempFile("autoscan_req_", ".txt").apply { writeText(request.toString()) }

            // Настройка процесса: абсолютный путь к binary, вывод в JSON, таймаут
            val processBuilder = ProcessBuilder(listOf("/home/kali/go/bin/nuclei", "-l", tempFile.absolutePath, "-json", "-timeout", "30")).apply { redirectErrorStream(true) }
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
                            request = request
                        ))
                    }
                } catch (_: Exception) { } // Игнорируем служебные строки, не являющиеся JSON
            }

            process.waitFor()
            tempFile.delete() // Очистка временных файлов
            api.logging().logToOutput("[NUCLEI] Сканирование завершено для: ${request.url()} (Найдено: $findingsCount)")
        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка Nuclei: ${e.message}")
        }
    }
}