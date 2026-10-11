package com.example.plugin

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.ObjectMapper
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableRowSorter

// =========================================================================
// МОДЕЛИ И РЕНДЕРЕРЫ ТАБЛИЦЫ
// =========================================================================

// Модель данных для JTable. 'findings' сделан публичным (val) для доступа из рендерера фона
class FindingsTableModel(val findings: MutableList<VulnerabilityFinding>) : AbstractTableModel() {
    private val columns = arrayOf("#", "Type", "Severity", "URL", "Details", "Time")

    override fun getRowCount(): Int = findings.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) { 0 -> java.lang.Integer::class.java else -> String::class.java }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val f = findings[rowIndex]
        val time = SimpleDateFormat("HH:mm:ss").format(Date(f.timestamp))
        return when (columnIndex) {
            0 -> rowIndex + 1; 1 -> f.type; 2 -> f.severity; 3 -> f.url; 4 -> f.details; 5 -> time; else -> ""
        }
    }

    fun removeFinding(index: Int) { if (index in findings.indices) { findings.removeAt(index); fireTableRowsDeleted(index, index) } }
    fun clearAll() { val size = findings.size; if (size > 0) { findings.clear(); fireTableRowsDeleted(0, size - 1) } }
}

// Рендерер для раскраски текста уровня критичности (Severity)
class SeverityCellRenderer : javax.swing.table.DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int): Component {
        val component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        val severity = value?.toString()?.uppercase() ?: ""
        if (!isSelected) {
            component.foreground = when {
                severity.contains("CRITICAL") -> Color(220, 20, 60) // Crimson
                severity.contains("HIGH") -> Color(255, 69, 0)     // OrangeRed
                severity.contains("MEDIUM") -> Color(255, 140, 0)  // DarkOrange
                severity.contains("LOW") -> Color(30, 144, 255)    // DodgerBlue
                else -> Color.BLACK
            }
        }
        (component as JLabel).horizontalAlignment = SwingConstants.CENTER
        (component as JLabel).font = Font("SansSerif", Font.BOLD, 11)
        return component
    }
}

// Рендерер для раскраски фона всей строки в зависимости от Severity
class RowBackgroundRenderer(private val table: JTable) : javax.swing.table.DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int): Component {
        val component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        if (!isSelected) {
            val modelRow = table?.convertRowIndexToModel(row) ?: row
            val model = table?.model as? FindingsTableModel
            val severity = model?.let { if (modelRow < it.findings.size) it.findings[modelRow].severity.uppercase() else "" } ?: ""

            component.background = when {
                severity.contains("CRITICAL") -> Color(255, 230, 230) // Light pink
                severity.contains("HIGH") -> Color(255, 240, 220)     // Light orange
                severity.contains("MEDIUM") -> Color(255, 250, 220)   // Light yellow
                severity.contains("LOW") -> Color(230, 240, 255)      // Light blue
                else -> Color.WHITE
            }
        } else {
            component.background = table?.selectionBackground ?: Color(200, 220, 255)
        }
        return component
    }
}

// =========================================================================
// ГЛАВНАЯ ПАНЕЛЬ DASHBOARD
// =========================================================================

class AutoScannerDashboardPanel(private val api: MontoyaApi) : JPanel() {
    private val findingsList = java.util.concurrent.CopyOnWriteArrayList<VulnerabilityFinding>()
    private val tableModel = FindingsTableModel(findingsList)

    // Инициализация и настройка внешнего вида JTable
    private val table = JTable(tableModel).apply {
        autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        rowHeight = 24
        rowSelectionAllowed = true
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION) // Разрешен выбор только одной строки
        tableHeader.reorderingAllowed = false
        gridColor = Color(220, 220, 220)
        setShowGrid(true)
        rowSorter = TableRowSorter(tableModel) // Включаем сортировку по клику на заголовок

        // Применяем кастомные рендереры
        getColumnModel().getColumn(2).cellRenderer = SeverityCellRenderer()
        for (i in 0 until columnCount) getColumnModel().getColumn(i).cellRenderer = RowBackgroundRenderer(this)

        // Настройка ширины колонок
        getColumnModel().getColumn(0).apply { preferredWidth = 40; maxWidth = 50 }
        getColumnModel().getColumn(1).apply { preferredWidth = 70; maxWidth = 100 }
        getColumnModel().getColumn(2).apply { preferredWidth = 80; maxWidth = 100 }
        getColumnModel().getColumn(4).preferredWidth = 200
        getColumnModel().getColumn(5).apply { preferredWidth = 80; maxWidth = 100 }
    }

    private val sorter = table.rowSorter as TableRowSorter<FindingsTableModel>

    // Элементы управления (фильтры и поиск)
    private val searchField = JTextField()
    private val typeFilter = JComboBox(arrayOf("All Types", "IDOR", "Nuclei"))
    private val severityFilter = JComboBox(arrayOf("All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"))

    // Элементы статистики
    private val totalCountLabel = JLabel("Total: 0")
    private val criticalCountLabel = JLabel("Critical: 0")
    private val highCountLabel = JLabel("High: 0")
    private val mediumCountLabel = JLabel("Medium: 0")
    private val lowCountLabel = JLabel("Low: 0")

    init {
        layout = BorderLayout()

        // 1. Верхняя панель инструментов (Toolbar)
        val toolBar = JToolBar().apply { isFloatable = false; border = BorderFactory.createEmptyBorder(5, 5, 5, 5) }
        searchField.toolTipText = "Поиск по URL или деталям"; searchField.columns = 20
        toolBar.add(JLabel("  Search: ")); toolBar.add(searchField); toolBar.add(Box.createHorizontalStrut(10))
        toolBar.add(JLabel("Type: ")); toolBar.add(typeFilter); toolBar.add(Box.createHorizontalStrut(10))
        toolBar.add(JLabel("Severity: ")); toolBar.add(severityFilter); toolBar.add(Box.createHorizontalStrut(10))
        toolBar.add(JButton("Clear All").apply { toolTipText = "Удалить все записи"; addActionListener { clearAllFindings() } })
        toolBar.add(JButton("Export JSON").apply { toolTipText = "Экспортировать находки в JSON-файл"; addActionListener { exportToJson() } })
        add(toolBar, BorderLayout.NORTH)

        // 2. Центральная область с таблицей
        add(JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }, BorderLayout.CENTER)

        // 3. Нижняя панель (Статистика + Кнопки действий)
        val bottomPanel = JPanel(BorderLayout()).apply { border = BorderFactory.createEmptyBorder(5, 5, 5, 5) }
        val statsPanel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 0)).apply {
            totalCountLabel.font = Font("SansSerif", Font.BOLD, 12)
            criticalCountLabel.foreground = Color(220, 20, 60); highCountLabel.foreground = Color(255, 69, 0)
            mediumCountLabel.foreground = Color(255, 140, 0); lowCountLabel.foreground = Color(30, 144, 255)
            add(totalCountLabel); add(JSeparator(SwingConstants.VERTICAL).apply { preferredSize = Dimension(2, 20) })
            add(criticalCountLabel); add(highCountLabel); add(mediumCountLabel); add(lowCountLabel)
        }
        bottomPanel.add(statsPanel, BorderLayout.WEST)

        val buttonsPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0)).apply {
            add(JButton("Open in Repeater").apply { toolTipText = "Открыть (Enter)"; addActionListener { openSelectedInRepeater() } })
            add(JButton("Copy URL").apply { toolTipText = "Копировать URL"; addActionListener { copySelectedUrl() } })
            add(JButton("Delete").apply { toolTipText = "Удалить (Del)"; addActionListener { deleteSelected() } })
        }
        bottomPanel.add(buttonsPanel, BorderLayout.EAST)
        add(bottomPanel, BorderLayout.SOUTH)

        // 4. Обработчики событий (Реактивность UI)
        // Живой поиск при вводе текста
        searchField.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            override fun insertUpdate(e: javax.swing.event.DocumentEvent?) = applyFilters()
            override fun removeUpdate(e: javax.swing.event.DocumentEvent?) = applyFilters()
            override fun changedUpdate(e: javax.swing.event.DocumentEvent?) = applyFilters()
        })
        typeFilter.addActionListener { applyFilters() }
        severityFilter.addActionListener { applyFilters() }

        // Обработка мыши (двойной клик и контекстное меню)
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) { if (e.clickCount == 2) openSelectedInRepeater() }
            override fun mousePressed(e: MouseEvent) = showPopup(e)
            override fun mouseReleased(e: MouseEvent) = showPopup(e)
            private fun showPopup(e: MouseEvent) {
                if (e.isPopupTrigger) {
                    val row = table.rowAtPoint(e.point)
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row)
                        JPopupMenu().apply {
                            add(JMenuItem("Open in Repeater").apply { addActionListener { openSelectedInRepeater() } })
                            add(JMenuItem("Copy URL").apply { addActionListener { copySelectedUrl() } })
                            addSeparator()
                            add(JMenuItem("Delete").apply { addActionListener { deleteSelected() } })
                        }.show(table, e.x, e.y)
                    }
                }
            }
        })

        // Обработка клавиатуры (Enter и Delete)
        table.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyPressed(e: java.awt.event.KeyEvent) {
                when (e.keyCode) {
                    java.awt.event.KeyEvent.VK_ENTER -> openSelectedInRepeater()
                    java.awt.event.KeyEvent.VK_DELETE -> deleteSelected()
                }
            }
        })
    }

    // =========================================================================
    // ЛОГИКА ДЕЙСТВИЙ И ФИЛЬТРАЦИИ
    // =========================================================================

    // Применение комбинированных фильтров (поиск + тип + критичность)
    private fun applyFilters() {
        val searchText = searchField.text.trim().lowercase()
        val selectedType = typeFilter.selectedItem as String
        val selectedSeverity = severityFilter.selectedItem as String
        val filters = mutableListOf<RowFilter<FindingsTableModel, Int>>()

        if (searchText.isNotEmpty()) filters.add(RowFilter.regexFilter("(?i)$searchText", 3, 4)) // Поиск по URL (3) и Details (4)
        if (selectedType != "All Types") filters.add(RowFilter.regexFilter("^$selectedType\$", 1))
        if (selectedSeverity != "All Severities") filters.add(RowFilter.regexFilter("(?i)$selectedSeverity", 2))

        sorter.rowFilter = if (filters.isEmpty()) null else RowFilter.andFilter(filters)
    }

    // Отправка выбранного запроса в Burp Repeater
    private fun openSelectedInRepeater() {
        val selectedRow = table.selectedRow
        if (selectedRow == -1) { JOptionPane.showMessageDialog(this, "Сначала выберите уязвимость.", "Информация", JOptionPane.INFORMATION_MESSAGE); return }
        val finding = findingsList[table.convertRowIndexToModel(selectedRow)]
        try {
            api.repeater().sendToRepeater(finding.request, "AutoScanner Finding")
            JOptionPane.showMessageDialog(this, "Отправлено в Repeater!", "Успех", JOptionPane.INFORMATION_MESSAGE)
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(this, "Ошибка: ${e.message}", "Ошибка", JOptionPane.ERROR_MESSAGE)
        }
    }

    // Копирование URL в системный буфер обмена
    private fun copySelectedUrl() {
        val selectedRow = table.selectedRow; if (selectedRow == -1) return
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(findingsList[table.convertRowIndexToModel(selectedRow)].url), null)
    }

    // Удаление выбранной строки из таблицы и модели
    private fun deleteSelected() {
        val selectedRow = table.selectedRow; if (selectedRow == -1) return
        tableModel.removeFinding(table.convertRowIndexToModel(selectedRow)); updateStats()
    }

    // Полная очистка таблицы с подтверждением
    private fun clearAllFindings() {
        if (JOptionPane.showConfirmDialog(this, "Удалить все записи?", "Подтверждение", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            tableModel.clearAll(); updateStats()
        }
    }

    // Экспорт всех находок в форматированный JSON-файл
    private fun exportToJson() {
        if (findingsList.isEmpty()) { JOptionPane.showMessageDialog(this, "Нет данных.", "Информация", JOptionPane.INFORMATION_MESSAGE); return }
        val chooser = JFileChooser().apply { dialogTitle = "Экспорт"; selectedFile = File("autoscan_findings_${System.currentTimeMillis()}.json") }
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                val json = ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(findingsList.map {
                    mapOf("url" to it.url, "type" to it.type, "severity" to it.severity, "details" to it.details, "timestamp" to it.timestamp)
                })
                FileWriter(chooser.selectedFile).use { it.write(json) }
                JOptionPane.showMessageDialog(this, "Экспорт завершён!", "Успех", JOptionPane.INFORMATION_MESSAGE)
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(this, "Ошибка: ${e.message}", "Ошибка", JOptionPane.ERROR_MESSAGE)
            }
        }
    }

    // Пересчет и обновление счетчиков статистики в нижней панели
    private fun updateStats() {
        totalCountLabel.text = "Total: ${findingsList.size}"
        criticalCountLabel.text = "Critical: ${findingsList.count { it.severity.uppercase().contains("CRITICAL") }}"
        highCountLabel.text = "High: ${findingsList.count { it.severity.uppercase().contains("HIGH") }}"
        mediumCountLabel.text = "Medium: ${findingsList.count { it.severity.uppercase().contains("MEDIUM") }}"
        lowCountLabel.text = "Low: ${findingsList.count { it.severity.uppercase().contains("LOW") }}"
    }

    // Публичный метод для добавления новой находки из фонового потока (безопасно для Swing через invokeLater)
    fun addFinding(finding: VulnerabilityFinding) {
        SwingUtilities.invokeLater {
            findingsList.add(finding)
            tableModel.fireTableRowsInserted(findingsList.size - 1, findingsList.size - 1)
            updateStats()
        }
    }
}