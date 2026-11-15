"""Окно «Описание»: все сведения о строке списка и кнопки действий с ней.

Используется там, где в таблице оставлены только главные столбцы, а подробности (путь, хэши,
причина, ID...) открываются двойным щелчком или пунктом «Описание» правой кнопки:
журнал защиты, уязвимые драйверы, расширения браузеров, внедрённый код, ложные
срабатывания. Действие (label, callback): кнопка внизу; callback(dialog) может закрыть окно
(dialog.accept()) — например, если строки больше нет."""
from collections.abc import Callable

import html

from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QPushButton, QTextBrowser, QVBoxLayout,
)

KEY_WIDTH = 190  # столбец названий свойств, пикселей


def _rows_html(rows: list[tuple[str, str]]) -> str:
    """Свойства таблицей: название — жирным слева, значение — справа, абзацы сохраняются."""
    cells = "".join(
        f"<tr><td width='{KEY_WIDTH}' style='padding: 3px 10px 3px 0; font-weight: 600;'>"
        f"{html.escape(key)}</td><td style='padding: 3px 0;'>"
        f"{html.escape(value).replace(chr(10), '<br>')}</td></tr>" for key, value in rows)
    return f"<table cellspacing='0' width='100%'>{cells}</table>"


def main_window():
    """Главное окно программы (у окон инструментов нет родителя: они не держатся поверх)."""
    return next((w for w in QApplication.topLevelWidgets() if hasattr(w, "open_analyzer")
                 and hasattr(w, "show_main")), None)


def show_details(parent, title: str, rows: list[tuple[str, str]],
                 actions: list[tuple[str, Callable[[QDialog], object]]] | None = None,
                 width: int = 760) -> QDialog:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    box = QVBoxLayout(dialog)
    view = QTextBrowser()
    # перенос только по словам: таблица Qt (QTreeWidget) рвала длинные значения посреди
    # слова — «Adaptix_Beacon, Adf|ind» (комментарий 15.11.2026); путь без пробелов не
    # рвётся, а прокручивается
    view.setWordWrapMode(QTextOption.WrapMode.WordWrap)
    view.setOpenLinks(False)
    shown = [(k, str(v)) for k, v in rows if v not in (None, "")]
    view.setHtml(_rows_html(shown))
    # ширина — по самому длинному значению (путь виден целиком), но не шире экрана
    metrics = view.fontMetrics()
    # длинные описания переносятся по словам, их не учитываем — только пути и короткие строки
    longest = max((metrics.horizontalAdvance(line) for _, v in shown
                   for line in v.splitlines() if len(line) <= 260), default=0)
    width = max(width, KEY_WIDTH + longest + 90)
    screen = dialog.screen() or QApplication.primaryScreen()
    if screen is not None:
        width = min(width, screen.availableGeometry().width() - 80)
    lines = sum(1 + len(v) // 110 + v.count(chr(10)) for _, v in shown)
    dialog.resize(width, min(600, 130 + 24 * max(lines, 4)))
    box.addWidget(view, 1)

    row = QHBoxLayout()
    for label, callback in actions or []:
        button = QPushButton(label)
        button.clicked.connect(lambda checked=False, c=callback: c(dialog))
        row.addWidget(button)
    row.addStretch()
    copy = QPushButton("Копировать")
    copy.setToolTip("Все сведения — в буфер обмена")
    copy.clicked.connect(lambda: QApplication.clipboard().setText(
        "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, ""))))
    close = QPushButton("Закрыть")
    close.clicked.connect(dialog.reject)
    row.addWidget(copy)
    row.addWidget(close)
    box.addLayout(row)
    dialog.show()
    return dialog
