package com.example.plugin

// ============================================================================
// ИМПОРТЫ MOTOYA API
// ============================================================================
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.* // Интерфейсы HttpHandler, RequestToBeSentAction и др.
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

// ============================================================================
// ИМПОРТЫ СТАНДАРТНОЙ БИБЛИОТЕКИ
// ============================================================================
// CopyOnWriteArrayList: Потокобезопасный список.
// Аналог: list + threading.Lock() в Python или std::vector с std::mutex в C++.
// Обычный ArrayList упал бы с ConcurrentModificationException при параллельных запросах в Burp.
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Data class в Kotlin — аналог @dataclass в Python или struct в C++.
 * Автоматически генерирует конструктор, equals(), hashCode() и toString().
 * Используется как DTO (Data Transfer Object) для хранения состояния запроса.
 */
data class TrackedRequest(
    val url: String,
    val method: String,
    val originalRequest: HttpRequest // Ссылка на иммутабельный объект запроса Montoya API
)

/**
 * Главный класс расширения. ОБЯЗАН реализовывать интерфейс BurpExtension.
 * Метод initialize() вызывается Burp Suite ровно один раз при загрузке плагина.
 */
class MyExtension : BurpExtension {

    // Хранилище для уникальных перехваченных запросов
    private val trackedRequests = CopyOnWriteArrayList<TrackedRequest>()

    override fun initialize(api: MontoyaApi) {
        // 1. Инициализация имени и приветственного лога
        api.extension().setName("NIIRS AutoScanner")
        api.logging().logToOutput("========================================")
        api.logging().logToOutput("[+] NIIRS AutoScanner загружен!")
        api.logging().logToOutput("[+] Режим: Allowlist + Cache-Bypass + Public Check")
        api.logging().logToOutput("========================================")

        // 2. Регистрация обработчика HTTP-трафика
        // object : HttpHandler создает анонимный класс, реализующий интерфейс (аналог замыкания/lambda в Python)
        api.http().registerHttpHandler(object : HttpHandler {

            /**
             * Вызывается Burp ПЕРЕД отправкой запроса от клиента к серверу.
             * Идеальное место для перехвата, анализа и модификации.
             */
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {

                // ФИЛЬТР 1: Реагируем только на трафик из инструмента Proxy (браузера пользователя),
                // игнорируя фоновые запросы самого Burp (Intruder, Scanner и т.д.)
                if (requestToBeSent.toolSource().isFromTool(burp.api.montoya.core.ToolType.PROXY)) {
                    val cookieHeader = requestToBeSent.headerValue("Cookie")
                    val url = requestToBeSent.url()

                    // ФИЛЬТР 2: Проверяем наличие маркеров аутентификации в заголовках
                    if (cookieHeader != null) {
                        val isAuthRequest = cookieHeader.contains("token", ignoreCase = true) ||
                                cookieHeader.contains("session", ignoreCase = true)

                        // ФИЛЬТР 3: БЕЛЫЙ СПИСОК (Allowlist).
                        // Проверяем только целевые API-эндпоинты, игнорируя статику (.css, .png) для снижения шума.
                        val isTargetApi = url.contains("/api/") || url.contains("/rest/") ||
                                url.contains("/profile") || url.contains("/basket") ||
                                url.contains("/ftp/") || url.contains("/admin")

                        if (isAuthRequest && isTargetApi) {
                            // Создаем объект модели данных
                            val tracked = TrackedRequest(
                                url = url,
                                method = requestToBeSent.method(),
                                originalRequest = requestToBeSent
                            )

                            // ФИЛЬТР 4: Проверка на дубликаты.
                            // .any { } — аналог any(x.url == tracked.url for x in trackedRequests) в Python
                            // или std::any_of в C++. 'it' — неявное имя текущего элемента в лямбде.
                            val isDuplicate = trackedRequests.any { it.url == tracked.url && it.method == tracked.method }

                            if (!isDuplicate) {
                                trackedRequests.add(tracked)
                                api.logging().logToOutput("[+] Целевой запрос сохранен: ${tracked.method} ${tracked.url}")

                                // Запускаем алгоритм детекции IDOR для этого запроса
                                testIdorDetection(api, tracked)
                            }
                        }
                    }
                }

                // Возвращаем исходный запрос без изменений, чтобы он продолжил путь к серверу.
                // (Если бы мы хотели его изменить "на лету", вернули бы continueWith(новый_запрос))
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }

            // Метод вызывается при получении ответа от сервера. Пока не используется, но обязателен для интерфейса.
            override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
                return ResponseReceivedAction.continueWith(responseReceived)
            }
        })
    }

    /**
     * Подготовка модифицированного запроса для теста IDOR.
     * ВАЖНО: Объекты HttpRequest в Montoya API ИММУТАБЕЛЬНЫ (как tuple в Python или const объект в C++).
     * Методы .with... НЕ изменяют исходный объект, а возвращают его НОВУЮ копию с примененными изменениями.
     */
    private fun prepareModifiedRequest(original: HttpRequest, newCookieValue: String): HttpRequest {
        return original
            // Удаляем заголовки кэширования, чтобы гарантированно получить честный ответ 200 OK, а не 304 Not Modified
            .withRemovedHeader("If-None-Match")
            .withRemovedHeader("If-Modified-Since")
            // Принудительно требуем от сервера свежий ответ
            .withUpdatedHeader("Cache-Control", "no-cache")
            .withUpdatedHeader("Pragma", "no-cache")
            // Подменяем значение сессионной cookie на заведомо невалидное
            .withUpdatedHeader("Cookie", newCookieValue)
    }

    /**
     * Обёртка над методом отправки запроса Montoya API.
     * api.http().sendRequest() возвращает объект HttpRequestResponse (содержит и запрос, и ответ).
     * Метод .response() извлекает из него только часть с ответом (HttpResponse).
     */
    private fun sendRequest(api: MontoyaApi, request: HttpRequest): HttpResponse {
        return api.http().sendRequest(request).response()
    }

    /**
     * Классическая реализация расстояния Левенштейна через динамическое программирование.
     * Возвращает минимальное количество операций (вставка, удаление, замена) для превращения s1 в s2.
     * Аналог: python-Levenshtein.distance или собственная реализация на C++ через std::vector<std::vector<int>>.
     */
    private fun levenshteinDistance(s1: String, s2: String): Int {
        val len1 = s1.length
        val len2 = s2.length
        // Создаем матрицу (len1+1) x (len2+1), заполненную нулями
        val dp = Array(len1 + 1) { IntArray(len2 + 1) }

        // Базовые случаи: расстояние от пустой строки до строки длины N равно N
        for (i in 0..len1) dp[i][0] = i
        for (j in 0..len2) dp[0][j] = j

        // Заполняем матрицу
        for (i in 1..len1) {
            for (j in 1..len2) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(
                    dp[i - 1][j] + 1,       // Удаление
                    dp[i][j - 1] + 1,       // Вставка
                    dp[i - 1][j - 1] + cost // Замена
                )
            }
        }
        return dp[len1][len2]
    }

    /**
     * Ядро алгоритма обнаружения IDOR.
     */
    private fun testIdorDetection(api: MontoyaApi, tracked: TrackedRequest) {
        api.logging().logToOutput("[*] === АНАЛИЗ IDOR: ${tracked.url} ===")

        try {
            // ШАГ 1: Получение базовой линии (Baseline).
            // Отправляем "чистый" запрос без заголовков кэша, чтобы получить эталонный ответ.
            val cleanOriginalRequest = tracked.originalRequest
                .withRemovedHeader("If-None-Match")
                .withRemovedHeader("If-Modified-Since")
                .withUpdatedHeader("Cache-Control", "no-cache")

            val originalResponse = sendRequest(api, cleanOriginalRequest)

            // ШАГ 2: Проверка базовой линии.
            // Если у нас и так нет доступа к ресурсу (статус не 2xx), искать IDOR бессмысленно.
            if (originalResponse.statusCode() !in 200..299) {
                api.logging().logToOutput("[*] Пропуск: оригинальный запрос не успешен (статус ${originalResponse.statusCode()})")
                api.logging().logToOutput("[*] === КОНЕЦ АНАЛИЗА ===\n")
                return
            }

            // ШАГ 3: Мутация и отправка модифицированного запроса.
            val modifiedRequest = prepareModifiedRequest(tracked.originalRequest, "token=invalid_token_12345")
            val modifiedResponse = sendRequest(api, modifiedRequest)

            // ШАГ 4: Дифференциальный анализ (Diffing).
            val statusMatch = originalResponse.statusCode() == modifiedResponse.statusCode()
            val lengthMatch = originalResponse.bodyToString().length == modifiedResponse.bodyToString().length
            val distance = levenshteinDistance(originalResponse.bodyToString(), modifiedResponse.bodyToString())

            // ШАГ 5: Логирование метрик для отладки и отчета.
            api.logging().logToOutput("[*] Оригинал: ${originalResponse.statusCode()} (${originalResponse.bodyToString().length} байт)")
            api.logging().logToOutput("[*] Модифицированный: ${modifiedResponse.statusCode()} (${modifiedResponse.bodyToString().length} байт)")
            api.logging().logToOutput("[*] Расстояние Левенштейна: $distance")

            // ШАГ 6: Эвристический вердикт.
            // Если статус и длина совпали, а текст почти не изменился (расстояние < 50),
            // высока вероятность, что сервер отдал те же данные чужой сессии.
            val isVulnerable = statusMatch && lengthMatch && distance < 50

            // ШАГ 7: Фильтрация ложных срабатываний (False Positives) на публичных эндпоинтах.
            val isKnownPublic = tracked.url.contains("/api/Products") ||
                    tracked.url.contains("/rest/languages") ||
                    tracked.url.contains("/application-version") ||
                    tracked.url.contains("/Challenges") ||
                    tracked.url.contains("/products/search")

            if (isVulnerable) {
                if (isKnownPublic) {
                    api.logging().logToOutput("[*] Вердикт: Ответы совпадают, но эндпоинт публичный. Это не IDOR (False Positive).")
                } else {
                    api.logging().logToOutput("[!] ВНИМАНИЕ: Возможная IDOR уязвимость! Требуется ручная проверка.")
                }
            } else {
                api.logging().logToOutput("[+] IDOR не обнаружена (защита работает)")
            }
        } catch (e: Exception) {
            // Перехват исключений критически важен, чтобы ошибка в одном запросе не "уронила" весь плагин в Burp
            api.logging().logToOutput("[!] Ошибка при анализе: ${e.message}")
        }
        api.logging().logToOutput("[*] === КОНЕЦ АНАЛИЗА ===\n")
    }
}