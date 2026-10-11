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
    val details: String, // Краткое описание вектора атаки или название шаблона Nuclei
    val request: HttpRequest, // Ссылка на запрос для быстрой отправки в Burp Repeater
    val timestamp: Long = System.currentTimeMillis() // Время обнаружения для сортировки и отображения
)