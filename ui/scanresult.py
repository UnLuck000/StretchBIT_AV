"""Окно итогов быстрой и полной проверки (scanner/fullscan.run): открывается само, когда
проверка закончилась или её остановили. У быстрой и полной — свои окна («Итоги быстрой
проверки», «Итоги полной проверки»): итог одной не закрывает окно другой; новая проверка того
же вида заменяет своё окно.

Сверху — вывод (угроз нет / сколько найдено), что и сколько проверено по этапам, ниже —
таблица находок: уровень, этап, что найдено, файл. Двойной щелчок — «Описание»; ПКМ — в
карантин, открыть в сканере, показать в Проводнике (только у находок с файлом). Все находки
и так записаны в журнал защиты — кнопка «Журнал защиты» открывает его."""
import os
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QMenu, QPushButton, QTableWidgetItem, QVBoxLayout,
)

from scanner import fullscan
from ui.widgets import make_table

TITLES = {"quick": "Итоги быстрой проверки", "full": "Итоги полной проверки"}
NAMES = {"quick": "Быстрая проверка", "full": "Полная проверка"}
LEVEL_TEXT = {"threat": "Угроза", "suspicious": "Подозрительно"}
LEVEL_COLOR = {"threat": "#c0392b", "suspicious": "#d68910"}
OK_COLOR = "#2e9e4f"
PATH_ROLE = Qt.ItemDataRole.UserRole + 1

_open: dict[str, "ScanResultWindow"] = {}   # вид проверки -> окно (живёт, пока не закрыто)


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} с"
    if seconds < 3600:
        return f"{seconds // 60} мин {seconds % 60} с"
    return f"{seconds // 3600} ч {seconds // 60 % 60} мин"


def _num(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def summary_lines(mode: str, stats: fullscan.Stats) -> list[str]:
    """Что проверено: строка на каждый выполненный этап (и на этапы с ошибкой)."""
    from analyzer.fileops import human_size
    lines = []
    done = set(stats.stages)
    if fullscan.STAGE_AUTORUNS in done:
        lines.append(f"Автозапуск: записей — {_num(stats.autoruns)}")
    if fullscan.STAGE_MEMORY in done:
        lines.append(f"Память процессов: проверено — {_num(stats.processes)}")
    if fullscan.STAGE_USB in done:
        lines.append(f"Флешки (вирус-ярлык, autorun.inf): {stats.usb}" if stats.usb
                     else "Флешки: среди выбранных дисков съёмных нет")
    if fullscan.STAGE_DRIVERS in done:
        lines.append(f"Уязвимые драйверы (база LOLDrivers): проверено — {_num(stats.drivers)}"
                     if stats.drivers else "Уязвимые драйверы: базы LOLDrivers ещё нет")
    if fullscan.STAGE_EXTENSIONS in done:
        lines.append(f"Расширения браузеров: {_num(stats.extensions)}")
    if fullscan.STAGE_BCD in done:
        lines.append("Записи загрузки (BCD): проверены")
    if fullscan.STAGE_POLICIES in done:
        lines.append("Политики и блокировки реестра: проверены")
    if fullscan.STAGE_FILES in done:
        where = "Папки" if mode == "quick" else "Диски"
        text = (f"Файлы: проверено — {_num(stats.checked)}, пропущено — {_num(stats.skipped)} "
                f"({human_size(stats.skipped_bytes)})")
        if stats.game_dirs:
            text += f", папок игр — {len(stats.game_dirs)} (в них только программы)"
        lines.append(text)
        if stats.roots:
            lines.append(f"{where}: " + ", ".join(stats.roots))
    lines += [f"Не выполнено — {e}" for e in stats.stage_errors]
    return lines


def verdict(stats: fullscan.Stats) -> tuple[str, str]:
    """(цвет, текст вывода)."""
    if stats.threats:
        return LEVEL_COLOR["threat"], (f"Найдено угроз: {stats.threats}"
                                       + (f", подозрительного: {stats.suspicious}"
                                          if stats.suspicious else ""))
    if stats.suspicious:
        return LEVEL_COLOR["suspicious"], f"Угроз нет, подозрительного: {stats.suspicious}"
    return OK_COLOR, "Угроз не найдено"


class ScanResultWindow(QDialog):
    def __init__(self, mode: str, stats: fullscan.Stats, findings: list[dict], stopped: bool,
                 main=None):
        super().__init__(None)  # без родителя: не держится поверх главного окна
        self.mode, self.main, self.findings = mode, main, findings
        self.setWindowTitle(TITLES.get(mode, "Итоги проверки"))
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.resize(1100, 620)
        layout = QVBoxLayout(self)

        color, text = verdict(stats)
        if stopped:
            text += " (проверка остановлена — проверено не всё)"
        self.banner = QLabel(text)
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(f"padding: 10px; border-radius: 6px; font-size: 15px; "
                                  f"font-weight: 600; border: 1px solid {color}; color: {color};")
        layout.addWidget(self.banner)

        end = stats.finished or time.time()
        name = NAMES.get(mode, "Проверка")
        head = (f"{name} остановлена {time.strftime('%d.%m.%Y %H:%M', time.localtime(end))}"
                if stopped else
                f"{name} завершена {time.strftime('%d.%m.%Y %H:%M', time.localtime(end))}")
        info = QLabel(f"<b>{head}</b>, длилась {duration(end - stats.started)}.<br>"
                      + "<br>".join(_escape(line) for line in summary_lines(mode, stats)))
        info.setWordWrap(True)
        info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(info)

        self.table = make_table([("Уровень", 120), ("Этап", 170), ("Что найдено", 520),
                                 ("Файл", 260)])
        self.table.setSelectionMode(self.table.SelectionMode.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(lambda index: self._details(index.row()))
        self._fill()
        if findings:
            layout.addWidget(QLabel("Найденное (оно уже в журнале защиты; двойной щелчок — "
                                    "подробности, правая кнопка — действия):"))
            layout.addWidget(self.table, 1)
        else:
            self.table.hide()
            layout.addStretch(1)

        row = QHBoxLayout()
        self.quarantine_btn = QPushButton("В карантин")
        self.quarantine_btn.setToolTip("Выделенные находки с файлом")
        self.quarantine_btn.clicked.connect(lambda checked=False: self._quarantine())
        self.quarantine_btn.setVisible(any(f.get("path") for f in findings))
        journal = QPushButton("Журнал защиты")
        journal.clicked.connect(lambda checked=False: self._open_journal())
        close = QPushButton("Закрыть")
        close.clicked.connect(self.close)
        row.addWidget(self.quarantine_btn)
        row.addWidget(journal)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)

    def _fill(self) -> None:
        order = {"threat": 0, "suspicious": 1}
        self.findings.sort(key=lambda f: order.get(f["level"], 2))
        self.table.setRowCount(len(self.findings))
        for i, f in enumerate(self.findings):
            path = f.get("path", "")
            cells = [LEVEL_TEXT.get(f["level"], f["level"]), f.get("stage", ""), f["text"],
                     os.path.basename(path) if path else "—"]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setForeground(QBrush(QColor(LEVEL_COLOR.get(f["level"], ""))))
                    item.setData(PATH_ROLE, path)
                if col == 3 and path:
                    item.setToolTip(path)
                self.table.setItem(i, col, item)

    def _selected(self) -> list[dict]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.findings[r] for r in rows if r < len(self.findings)]

    def _paths(self) -> list[str]:
        paths = []
        for f in self._selected():
            path = f.get("path", "")
            if path and os.path.exists(path) and path not in paths:
                paths.append(path)
        return paths

    def _menu(self, pos) -> None:
        if not self._selected():
            return
        menu = QMenu(self)
        menu.addAction("Описание", lambda: self._details(self.table.currentRow()))
        paths = self._paths()
        if paths and self.main is not None:
            menu.addAction(f"В карантин ({len(paths)})" if len(paths) > 1 else "В карантин",
                           self._quarantine)
            menu.addAction("Открыть в сканере", lambda: self.main.open_analyzer(paths[0]))
            from analyzer import fileops
            menu.addAction("Показать в проводнике", lambda: fileops.show_in_explorer(paths[0]))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _details(self, row: int) -> None:
        if not 0 <= row < len(self.findings):
            return
        from ui.details import show_details
        f = self.findings[row]
        show_details(self, "Описание", [
            ("Уровень", LEVEL_TEXT.get(f["level"], f["level"])),
            ("Этап", f.get("stage", "")), ("Что найдено", f["text"]),
            ("Файл", f.get("path", "")), ("Время", f.get("time", ""))])

    def _quarantine(self) -> None:
        paths = self._paths()
        if not paths or self.main is None:
            return
        self.main._quarantine_threats(paths)
        for i, f in enumerate(self.findings):  # что ушло в карантин — отметить в таблице
            if f.get("path") in paths and not os.path.exists(f["path"]):
                self.table.item(i, 0).setText("В карантине")

    def _open_journal(self) -> None:
        if self.main is not None:
            self.main.show_log("Журнал защиты")


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def show(mode: str, stats: fullscan.Stats, findings: list[dict], stopped: bool,
         main=None) -> ScanResultWindow:
    """Открыть итоги; прежнее окно того же вида закрывается."""
    old = _open.pop(mode, None)
    if old is not None:
        try:
            old.close()
        except RuntimeError:  # окно уже удалено Qt
            pass
    window = ScanResultWindow(mode, stats, findings, stopped, main)
    _open[mode] = window
    window.destroyed.connect(lambda *_: _open.pop(mode, None) if _open.get(mode) is window
                             else None)
    window.show()
    window.raise_()
    window.activateWindow()
    return window
