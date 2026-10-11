package com.example.plugin

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

// Импорты для безопасной работы с JSON и асинхронности
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread // Асинхронные фоновые потоки
import java.io.File

/**
 * Расширенная модель данных.
 * В отличие от базовой версии, теперь извлекаем и храним параметры из Path, Query и JSON Body
 * для проведения глубокой мутации запроса, а не только подмены Cookie.
 */
data class TrackedRequest(
    val url: String,
    val method: String,
    val originalRequest: HttpRequest,
    val pathParams: List<String> = emptyList(),
    val queryParams: Map<String, String> = emptyMap(),
    val jsonBodyFields: Map<String, Any?> = emptyMap()
)

class MyExtension : BurpExtension {

    private val trackedRequests = CopyOnWriteArrayList<TrackedRequest>()

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("NIRS AutoScanner Pro")
        api.logging().logToOutput("========================================")
        api.logging().logToOutput("[+] NIRS AutoScanner Pro загружен!")
        api.logging().logToOutput("[+] Режим: Async + Safe JSON Mutation + Nuclei Orchestration")
        api.logging().logToOutput("========================================")

        api.http().registerHttpHandler(object : HttpHandler {
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
                if (requestToBeSent.toolSource().isFromTool(burp.api.montoya.core.ToolType.PROXY)) {
                    val cookieHeader = requestToBeSent.headerValue("Cookie")
                    val url = requestToBeSent.url()

                    if (cookieHeader != null) {
                        val isAuthRequest = cookieHeader.contains("token", ignoreCase = true) ||
                                cookieHeader.contains("session", ignoreCase = true)

                        val isTargetApi = url.contains("/api/") || url.contains("/rest/") ||
                                url.contains("/profile") || url.contains("/basket") ||
                                url.contains("/ftp/") || url.contains("/admin")

                        if (isAuthRequest && isTargetApi) {
                            // Извлечение параметров для глубокого анализа
                            val pathParams = extractPathParams(url)
                            val queryParams = extractQueryParams(url)
                            val jsonBodyFields = extractJsonBodyFields(requestToBeSent.bodyToString())

                            val tracked = TrackedRequest(
                                url = url,
                                method = requestToBeSent.method(),
                                originalRequest = requestToBeSent,
                                pathParams = pathParams,
                                queryParams = queryParams,
                                jsonBodyFields = jsonBodyFields
                            )

                            val isDuplicate = trackedRequests.any { it.url == tracked.url && it.method == tracked.method }

                            if (!isDuplicate) {
                                trackedRequests.add(tracked)
                                api.logging().logToOutput("[+] Целевой запрос сохранен: ${tracked.method} ${tracked.url}")

                                // Асинхронный запуск.
                                // Предотвращает блокировку основного потока Burp и браузера при генерации десятков мутаций.
                                thread(start = true, isDaemon = true) {
                                    testIdorAdvanced(api, tracked)
                                }
                            }
                        }
                    }
                }
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }

            override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
                return ResponseReceivedAction.continueWith(responseReceived)
            }
        })
    }

    // ============================================================================
    // ПАРСЕРЫ ПАРАМЕТРОВ ДЛЯ ГЛУБОКОЙ МУТАЦИИ
    // ============================================================================

    private fun extractPathParams(url: String): List<String> {
        val pathOnly = url.substringBefore("?")
        val regex = Regex("/(\\d+)(?=/|$)")
        return regex.findAll(pathOnly).map { it.value }.toList()
    }

    private fun extractQueryParams(url: String): Map<String, String> {
        val queryPart = url.substringAfter("?", "")
        if (queryPart.isEmpty()) return emptyMap()
        return queryPart.split("&")
            .map { it.split("=", limit = 2) } // limit=2 защищает от значений, содержащих символ '='
            .filter { it.size == 2 }
            .associate { it[0] to it[1] }
    }

    private fun extractJsonBodyFields(body: String): Map<String, Any?> {
        if (body.isBlank()) return emptyMap()
        try {
            val mapper = jacksonObjectMapper()
            val json = mapper.readTree(body)
            val fields = mutableMapOf<String, Any?>()

            json.fields().forEach { (key, value) ->
                // Эвристика: ищем поля, которые с высокой вероятностью являются идентификаторами
                if (key.contains("id", ignoreCase = true) || key.contains("user", ignoreCase = true) ||
                    key.contains("account", ignoreCase = true) || key.contains("order", ignoreCase = true) ||
                    key.contains("basket", ignoreCase = true) || key.contains("profile", ignoreCase = true)
                ) {
                    fields[key] = when {
                        value.isNumber -> value.asInt()
                        value.isTextual -> value.asText()
                        value.isBoolean -> value.asBoolean()
                        else -> value.toString()
                    }
                }
            }
            return fields
        } catch (_: Exception) {
            return emptyMap()
        }
    }

    // ============================================================================
    // ГЕНЕРАЦИЯ МУТАЦИЙ (БЕЗОПАСНАЯ)
    // ============================================================================

    private fun generateMutatedRequests(
        original: HttpRequest,
        tracked: TrackedRequest,
        victimIds: List<String> = listOf("1", "2", "3", "4", "5", "999")
    ): List<Pair<String, HttpRequest>> {
        val mutations = mutableListOf<Pair<String, HttpRequest>>()

        // 1. Мутация Cookie (базовая)
        mutations.add("Cookie: подмена токена" to prepareModifiedRequest(original, "token=invalid_token_12345"))

        // 2. Мутация URL Path Parameters
        for (param in tracked.pathParams) {
            for (victimId in victimIds) {
                val newUrl = original.url().replaceFirst(param, "/$victimId")
                mutations.add("PathParam: $param -> /$victimId" to original.withPath(newUrl))
            }
        }

        // 3. Мутация Query Parameters (безопасная пересборка URL)
        for ((key, value) in tracked.queryParams) {
            for (victimId in victimIds) {
                val urlParts = original.url().split("?", limit = 2)
                val basePath = urlParts[0]
                val query = if (urlParts.size > 1) urlParts[1] else ""

                val newQueryParams = query.split("&").map { param ->
                    val kv = param.split("=", limit = 2)
                    if (kv.size == 2 && kv[0] == key) "$key=$victimId" else param
                }.joinToString("&")

                val newUrl = if (newQueryParams.isEmpty()) basePath else "$basePath?$newQueryParams"
                mutations.add("QueryParam: $key=$value -> $key=$victimId" to original.withPath(newUrl))
            }
        }

        // 4. Мутация JSON Body через AST (Abstract Syntax Tree).
        // Использование ObjectNode предотвращает ошибки, которые возникали при простом String.replace()
        // (например, замена "10" на "1" могла случайно изменить "100" на "10").
        if (original.bodyToString().isNotBlank()) {
            try {
                val mapper = jacksonObjectMapper()
                for ((key, value) in tracked.jsonBodyFields) {
                    for (victimId in victimIds) {
                        // Парсим заново для каждой итерации, чтобы получить чистое дерево без сайд-эффектов
                        val mutationNode = mapper.readTree(original.bodyToString()) as ObjectNode

                        if (value is Int) {
                            mutationNode.put(key, victimId.toIntOrNull() ?: 1)
                        } else {
                            mutationNode.put(key, victimId)
                        }

                        val newBody = mapper.writeValueAsString(mutationNode)
                        mutations.add("JsonBody: $key -> $victimId" to original.withBody(newBody))
                    }
                }
            } catch (_: Exception) {
                // Игнорируем невалидный JSON
            }
        }

        return mutations
    }

    // ============================================================================
    // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    // ============================================================================

    private fun prepareModifiedRequest(original: HttpRequest, newCookieValue: String): HttpRequest {
        return original
            .withRemovedHeader("If-None-Match")
            .withRemovedHeader("If-Modified-Since")
            .withUpdatedHeader("Cache-Control", "no-cache")
            .withUpdatedHeader("Pragma", "no-cache")
            .withUpdatedHeader("Cookie", newCookieValue)
    }

    private fun sendRequest(api: MontoyaApi, request: HttpRequest): HttpResponse {
        return api.http().sendRequest(request).response()
    }

    private fun levenshteinDistance(s1: String, s2: String): Int {
        val len1 = s1.length
        val len2 = s2.length
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

    // Детектор "Ложных 200 OK".
    // Многие API возвращают статус 200, но в теле пишут {"error": "Unauthorized"}.
    // Эта функция отсеивает такие ответы, предотвращая ложные срабатывания алгоритма Левенштейна.
    private fun isErrorResponse(body: String): Boolean {
        val lowerBody = body.lowercase()
        return lowerBody.contains("unauthorized") || lowerBody.contains("forbidden") ||
                lowerBody.contains("not found") || lowerBody.contains("invalid") ||
                lowerBody.contains("error") || lowerBody.contains("access denied") ||
                lowerBody.contains("permission")
    }

    // ============================================================================
    // ОРКЕСТРАЦИЯ ВНЕШНИХ ИНСТРУМЕНТОВ (NUCLEI)
    // ============================================================================

    private fun runNucleiScan(api: MontoyaApi, request: HttpRequest) {
        try {
            val tempFile = File.createTempFile("nirs_req_", ".txt")
            tempFile.writeText(request.toString()) // Сохраняем Raw HTTP с заголовками и CRLF

            // ВАЖНО: Указан абсолютный путь, так как ProcessBuilder в Java не всегда видит системный $PATH
            val command = listOf("/home/kali/go/bin/nuclei", "-l", tempFile.absolutePath, "-json", "-timeout", "30")

            val processBuilder = ProcessBuilder(command)
            processBuilder.redirectErrorStream(true) // Объединяем stdout и stderr

            api.logging().logToOutput("[🛡️ NUCLEI] 🚀 Запуск сканирования: ${request.url()}")

            val process = processBuilder.start()
            val reader = process.inputStream.bufferedReader()
            val mapper = jacksonObjectMapper()

            var findingsCount = 0

            // Чтение потока NDJSON (Newline Delimited JSON), который выдает Nuclei
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                try {
                    val jsonNode = mapper.readTree(line)
                    val info = jsonNode["info"]
                    val name = info?.get("name")?.asText() ?: "Unknown"
                    val severity = info?.get("severity")?.asText()?.uppercase() ?: "UNKNOWN"
                    val matchedAt = jsonNode["matched-at"]?.asText() ?: request.url()

                    // Фильтруем информационные сообщения, оставляем только реальные находки
                    if (severity != "INFO" && severity != "UNKNOWN") {
                        findingsCount++
                        api.logging().logToOutput("[🛡️ NUCLEI] 🚨 НАЙДЕНО: [$severity] $name")
                        api.logging().logToOutput("   📍 Цель: $matchedAt")
                    }
                } catch (_: Exception) {
                    // Игнорируем служебные строки Nuclei (например, о загрузке шаблонов), которые не являются JSON
                }
            }

            process.waitFor()
            tempFile.delete() // Очистка временных файлов

            api.logging().logToOutput("[🛡️ NUCLEI] ✅ Сканирование завершено для: ${request.url()} (Найдено: $findingsCount)")

        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка Nuclei: ${e.message}")
        }
    }

    // ============================================================================
    // ИЗМЕНЕНО: РАСШИРЕННЫЙ АЛГОРИТМ ДЕТЕКЦИИ IDOR
    // ============================================================================

    private fun testIdorAdvanced(api: MontoyaApi, tracked: TrackedRequest) {
        try {
            val cleanOriginalRequest = tracked.originalRequest
                .withRemovedHeader("If-None-Match")
                .withRemovedHeader("If-Modified-Since")
                .withUpdatedHeader("Cache-Control", "no-cache")

            val originalResponse = sendRequest(api, cleanOriginalRequest)

            if (originalResponse.statusCode() !in 200..299) return

            // Генерируем не 1, а массив мутаций (Cookie, Path, Query, JSON)
            val mutations = generateMutatedRequests(tracked.originalRequest, tracked)
            val vulnerableMutations = mutableListOf<String>()

            for ((mutationType, mutatedRequest) in mutations) {
                val mutatedResponse = sendRequest(api, mutatedRequest)

                val statusMatch = originalResponse.statusCode() == mutatedResponse.statusCode()
                val lengthMatch = originalResponse.bodyToString().length == mutatedResponse.bodyToString().length
                val distance = levenshteinDistance(originalResponse.bodyToString(), mutatedResponse.bodyToString())

                // Проверка на наличие слов ошибки в теле ответа
                val isError = isErrorResponse(mutatedResponse.bodyToString())

                if (statusMatch && lengthMatch && distance < 50 && !isError) {
                    vulnerableMutations.add(mutationType)
                }
            }

            // Консолидированный вывод. Без спама логов каждой проверкой,
            // а выводим итоговый список подозрительных векторов, если они есть.
            if (vulnerableMutations.isNotEmpty()) {
                val isKnownPublic = tracked.url.contains("/api/Products") ||
                        tracked.url.contains("/rest/languages") ||
                        tracked.url.contains("/application-version") ||
                        tracked.url.contains("/Challenges") ||
                        tracked.url.contains("/products/search")

                if (isKnownPublic) {
                    api.logging().logToOutput("[*] Игнорировано: Публичный эндпоинт ${tracked.url} (False Positive)")
                } else {
                    api.logging().logToOutput("[!] 🚨 НАЙДЕНА ПОТЕНЦИАЛЬНАЯ IDOR: ${tracked.url}")
                    api.logging().logToOutput("[!] Подозрительные векторы:")
                    vulnerableMutations.forEach { api.logging().logToOutput("    ➔ $it") }
                    api.logging().logToOutput("[!] Рекомендуется проверить в Burp Repeater.")
                }
            }

            // Триггер оркестрации. Если в запросе есть параметры, запускаем Nuclei параллельно.
            val hasInjectionPoints = tracked.queryParams.isNotEmpty() || tracked.jsonBodyFields.isNotEmpty() || tracked.method == "POST"
            if (hasInjectionPoints) {
                thread(start = true, isDaemon = true) {
                    runNucleiScan(api, tracked.originalRequest)
                }
            }

        } catch (e: Exception) {
            api.logging().logToOutput("[!] Ошибка при анализе ${tracked.url}: ${e.message}")
        }
    }
}