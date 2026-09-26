package com.example.plugin

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

// Мы говорим Kotlin: "Этот класс реализует интерфейс BurpExtension"
class MyExtension : BurpExtension {

    // Этот метод Burp вызовет сам, когда ты нажмешь "Load" в интерфейсе
    override fun initialize(api: MontoyaApi) {
        // Задаем имя плагина (будет видно в списке расширений Burp)
        api.extension().setName("NIRS AutoScanner")

        // Пишем в лог Burp (вкладка Extensions -> вкладка нашего плагина)
        api.logging().logToOutput("[+] Плагин успешно загружен!")
        api.logging().logToOutput("[+] Готов к работе.")
    }
}