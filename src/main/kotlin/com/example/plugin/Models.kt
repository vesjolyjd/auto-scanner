package com.example.plugin

import burp.api.montoya.http.message.requests.HttpRequest

/**
 * Модель данных для хранения перехваченного HTTP-запроса и извлеченных из него параметров.
 * Используется как основа для генерации мутированных запросов при поиске IDOR.
 */
data class TrackedRequest(
    val url: String,
    val method: String,
    val originalRequest: HttpRequest, // Исходный "чистый" запрос для отправки в Repeater
    val pathParams: List<String> = emptyList(), // Извлеченные числовые ID из пути (напр., /users/5)
    val queryParams: Map<String, String> = emptyMap(), // Параметры строки запроса (напр., ?id=5)
    val jsonBodyFields: Map<String, Any?> = emptyMap() // Потенциальные идентификаторы в теле JSON-запроса
)

/**
 * Модель данных для представления найденной уязвимости в графическом интерфейсе (Dashboard).
 */
data class VulnerabilityFinding(
    val url: String,
    val type: String, // Тип обнаруженной проблемы: "IDOR" или "Nuclei"
    val severity: String, // Уровень критичности: CRITICAL, HIGH, MEDIUM, LOW
    val details: String, // Структурированный отчёт: вердикт, метрики, успешные векторы
    val request: HttpRequest, // Ссылка на запрос для быстрой отправки в Burp Repeater
    val timestamp: Long = System.currentTimeMillis(), // Время обнаружения для сортировки и отображения
    val successfulVectors: List<String> = emptyList(), // Векторы мутаций с положительным вердиктом (в отчёт попадает не более 3-х)
    val statusCode: Int = 0, // HTTP-код ответа, зафиксированный при подтверждении находки
    val responseDiff: Double? = null, // Процент РАЗЛИЧИЯ baseline и мутированного ответа (null — метрика неприменима)
    val victimIdReflected: Boolean = false, // Признак рефлексии идентификатора жертвы в теле ответа
    val sensitiveDataFound: Boolean = false // Признак наличия чувствительных полей в теле ответа
)

/**
 * Запись полного аудита одной мутации. Формируется только при включённом режиме
 * подробного экспорта; сериализуется в отдельный файл, не раздувая основной отчёт.
 */
data class AuditStep(
    val url: String,
    val method: String,
    val vectorType: String,
    val mutatedRequestRaw: String,
    val responseStatusCode: Int,
    val responseBodySnippet: String,
    val verdictLabel: String,
    val responseDiffPercent: Double,
    val victimIdReflected: Boolean,
    val sensitiveDataFound: Boolean,
    val timestamp: Long = System.currentTimeMillis()
)