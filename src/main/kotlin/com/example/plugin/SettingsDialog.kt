package com.example.plugin

import java.awt.*
import javax.swing.*

class SettingsDialog(parent: Frame?) : JDialog(parent as Frame?, "Настройки эвристик сканера", true) {

    init {
        size = Dimension(600, 500)
        setLocationRelativeTo(null)
        layout = BorderLayout(10, 10)
        (contentPane as JComponent).border = BorderFactory.createEmptyBorder(10, 10, 10, 10)

        val tabbedPane = JTabbedPane()

        // Helper-функция для создания вкладки с текстовым полем
        fun createConfigTab(title: String, configSet: MutableSet<String>): JPanel {
            val panel = JPanel(BorderLayout())
            val textArea = JTextArea(configSet.joinToString("\n"))
            textArea.font = Font("Monospaced", Font.PLAIN, 12)
            textArea.lineWrap = true
            textArea.wrapStyleWord = true

            val scrollPane = JScrollPane(textArea).apply {
                preferredSize = Dimension(400, 300)
            }

            panel.add(JLabel(title), BorderLayout.NORTH)
            panel.add(scrollPane, BorderLayout.CENTER)

            // Сохраняем ссылку на textArea, чтобы прочитать данные при нажатии "Сохранить"
            panel.putClientProperty("textArea", textArea)
            panel.putClientProperty("configSet", configSet)
            return panel
        }

        tabbedPane.addTab("Маркеры Auth", createConfigTab("Маркеры аутентификации (Cookie/Headers)", ScannerConfig.authMarkers))
        tabbedPane.addTab("Чувствительные поля", createConfigTab("Поля для поиска в JSON и Query", ScannerConfig.sensitiveFields))
        tabbedPane.addTab("Пейлоады привилегий", createConfigTab("Значения для Vertical Privilege Escalation", ScannerConfig.privilegePayloads))
        tabbedPane.addTab("Жертвы IDOR", createConfigTab("Значения для подмены идентификаторов", ScannerConfig.victimIds))
        tabbedPane.addTab("Ключевые слова утечек", createConfigTab("Слова, указывающие на Info Disclosure", ScannerConfig.infoLeakKeywords))
        tabbedPane.addTab("Безопасные ошибки", createConfigTab("Ошибки, которые игнорируются (False Positive)", ScannerConfig.genericErrors))
        tabbedPane.addTab("Публичные эндпоинты", createConfigTab("URL-адреса, которые не проверяются на IDOR", ScannerConfig.publicEndpoints))

        add(tabbedPane, BorderLayout.CENTER)

        // Кнопки управления
        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))

        val saveBtn = JButton("💾 Сохранить изменения").apply {
            addActionListener {
                // Проходим по всем вкладкам и обновляем конфигурацию
                for (i in 0 until tabbedPane.tabCount) {
                    val panel = tabbedPane.getComponentAt(i) as JPanel
                    val textArea = panel.getClientProperty("textArea") as JTextArea
                    val configSet = panel.getClientProperty("configSet") as MutableSet<String>

                    configSet.clear()
                    configSet.addAll(
                        textArea.text.lines()
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                    )
                }
                JOptionPane.showMessageDialog(this, "Настройки успешно сохранены!\nНовые правила применятся к следующим запросам.", "Успех", JOptionPane.INFORMATION_MESSAGE)
                dispose()
            }
        }

        val cancelBtn = JButton("Отмена").apply {
            addActionListener { dispose() }
        }

        buttonPanel.add(saveBtn)
        buttonPanel.add(cancelBtn)
        add(buttonPanel, BorderLayout.SOUTH)
    }
}