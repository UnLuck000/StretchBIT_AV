"""Окно изменений новой версии (changelog с GitHub).

Показывается, когда найдена новая версия: если окно программы открыто — сразу, если программа
в трее — когда пользователь её откроет (после уведомления). Скачивание и установка начинаются
только после нажатия «Обновить» — до этого программа ничего не качает.
"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout,
)


class ChangelogWindow(QDialog):
    """Список изменений (release.notes) поверх окон StretchBIT, с кнопкой «Обновить»."""

    update_requested = Signal()  # пользователь нажал «Обновить»

    def __init__(self, version: str, notes: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Обновление StretchBIT {version}")
        self.setModal(False)
        self.resize(600, 480)

        layout = QVBoxLayout(self)
        title = QLabel(f"Доступна новая версия StretchBIT {version}")
        title.setStyleSheet("font-size: 13pt; font-weight: 600;")
        layout.addWidget(title)

        hint = QLabel("Что нового в этой версии:")
        layout.addWidget(hint)

        body = QTextBrowser()
        body.setOpenExternalLinks(True)
        body.setMarkdown(notes or "Описание изменений не приложено.")
        layout.addWidget(body, 1)

        buttons = QHBoxLayout()
        self.btn_later = QPushButton("Позже")
        self.btn_later.clicked.connect(self.reject)
        self.btn_update = QPushButton("Обновить")
        self.btn_update.setDefault(True)
        self.btn_update.clicked.connect(self._on_update)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_later)
        buttons.addWidget(self.btn_update)
        layout.addLayout(buttons)

    def _on_update(self):
        self.accept()
        self.update_requested.emit()
