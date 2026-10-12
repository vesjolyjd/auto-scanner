package com.example.plugin

/**
 * Централизованная конфигурация сканера.
 * Вынесение всех списков и правил в один объект улучшает читаемость,
 * упрощает настройку и снижает количество ложных срабатываний.
 */
object ScannerConfig {

    // =========================================================================
    // 1. МАРКЕРЫ АУТЕНТИФИКАЦИИ (для фильтрации трафика)
    // =========================================================================
    val authMarkers = mutableSetOf(
        "token", "session", "jwt", "authorization", "apikey", "api_key",
        "access_token", "refresh_token", "auth", "bearer", "connect.sid"
    )

    // =========================================================================
    // 2. ЧУВСТВИТЕЛЬНЫЕ ПОЛЯ (для поиска в JSON и Query Parameters)
    // =========================================================================
    val sensitiveFields = mutableSetOf(
        "id", "user_id", "userid", "uid", "account", "order", "basket",
        "profile", "role", "admin", "is_admin", "privilege", "type", "level",
        "customer_id", "group_id", "tenant_id", "org_id", "company_id",
        "owner_id", "creator_id", "employee_id"
    )

    // =========================================================================
    // 3. ПЕЙЛОАДЫ ДЛЯ ПОВЫШЕНИЯ ПРИВИЛЕГИЙ (Vertical Privilege Escalation)
    // =========================================================================
    val privilegePayloads = mutableSetOf(
        "admin", "administrator", "root", "superuser", "true", "false",
        "1", "0", "yes", "no", "user", "guest"
    )

    // =========================================================================
    // 4. ЖЕРТВЫ ДЛЯ IDOR (Значения для подмены идентификаторов)
    // =========================================================================
    val victimIds = mutableSetOf(
        "1", "2", "3", "4", "5", "999", "0", "-1", "admin", "test",
        "null", "00000000-0000-0000-0000-000000000000"
    )

    // =========================================================================
    // 5. КЛЮЧЕВЫЕ СЛОВА УТЕЧЕК (Info Disclosure) - УНИВЕРСАЛЬНЫЕ
    // =========================================================================
    // Охватывает Java, PHP, Python, .NET и общие паттерны ошибок
    val infoLeakKeywords = mutableSetOf(
        // Общие
        "exception", "fatal", "syntax error", "invalid query", "unexpected",
        "stack", "trace", "traceback", "die(", "throw new", "assertion failed",
        "debug", "error:", "failed to open stream", "undefined index", "undefined variable",
        // Пути к файлам (Windows / Linux)
        "c:\\", "c:/", "/var/www/", "/usr/local/", "/home/", "appdata",
        // Специфичные для языков/фреймворков
        "java.lang.", "at com.", "at org.", "pdoexception", "sqlstate",
        "warning:", "notice:", "system.data", "namespace"
    )

    // =========================================================================
    // 6. БЕЗОПАСНЫЕ ОШИБКИ (Generic Errors) - Игнорируем их при анализе
    // =========================================================================
    val genericErrors = mutableSetOf(
        "unauthorized", "forbidden", "not found", "invalid token",
        "access denied", "permission denied", "csrf", "rate limit",
        "too many requests", "bad request", "method not allowed"
    )

    // =========================================================================
    // 7. ПУБЛИЧНЫЕ ЭНДПОИНТЫ (Для исключения False Positives)
    // =========================================================================
    val publicEndpoints = mutableSetOf(
        // Специфичные для Juice Shop / общих API
        "/api/products", "/rest/languages", "/application-version",
        "/challenges", "/products/search", "/api/quantitys", "/api/feedbacks",
        "/rest/admin/application-configuration", "/rest/admin/application-version",
        "/rest/user/whoami",
        // Общие паттерны публичных ресурсов
        "/public/", "/health", "/status", "/version", "/swagger", "/graphql",
        "/robots.txt", "/sitemap.xml", "/assets/", "/static/", "/.well-known/", "/favicon.ico"
    )
}