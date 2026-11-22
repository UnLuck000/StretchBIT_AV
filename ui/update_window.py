"""Окно обновления программы: предлагает скачать установщик новой версии в «Загрузки».

Обычное окно поверх окон StretchBIT (не модальный QMessageBox со звуком). Скачивание идёт в
фоне с прогрессом; установщик проверяется по SHA-256 и подписи (updatecheck.download) и
кладётся в папку «Загрузки», откуда его можно запустить или показать в проводнике.
"""
import os
import threading

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout,
)

import appinfo


class _Bridge(QObject):
    progress = Signal(int)          # проценты 0..100
    done = Signal(object, str)      # путь установщика | None, ошибка


class UpdateWindow(QDialog):
    """Предложение обновиться: «Скачать и установить» качает установщик в «Загрузки»."""

    def __init__(self, release, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Доступно обновление StretchBIT")
        self.setWindowFlag(Qt.WindowType.Window)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.release = release
        self.path = None
        self._bridge = _Bridge()
        self._bridge.progress.connect(self._on_progress)
        self._bridge.done.connect(self._on_done)

        layout = QVBoxLayout(self)
        title = QLabel(f"Доступна версия {release.version} (сейчас {appinfo.VERSION}).")
        title.setStyleSheet("font-size: 14pt; font-weight: 600;")
        title.setWordWrap(True)
        layout.addWidget(title)
        notes = QLabel(release.notes or "Описание изменений не приложено.")
        notes.setWordWrap(True)
        notes.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(notes)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setVisible(False)
        layout.addWidget(self.bar)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        row = QHBoxLayout()
        self.btn_download = QPushButton("Скачать и установить")
        self.btn_download.clicked.connect(self.download)
        self.btn_page = QPushButton("Открыть страницу выпуска")
        self.btn_page.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(self.release.page)))
        self.btn_later = QPushButton("Позже")
        self.btn_later.clicked.connect(self.reject)
        for widget in (self.btn_download, self.btn_page, self.btn_later):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)

        # после скачивания — запустить или показать в папке
        row_done = QHBoxLayout()
        self.btn_run = QPushButton("Запустить установщик")
        self.btn_run.clicked.connect(self.run_installer)
        self.btn_show = QPushButton("Показать в папке")
        self.btn_show.clicked.connect(self.show_folder)
        for widget in (self.btn_run, self.btn_show):
            widget.setVisible(False)
            row_done.addWidget(widget)
        row_done.addStretch()
        layout.addLayout(row_done)
        self.setMinimumWidth(520)

    def download(self):
        self.btn_download.setEnabled(False)
        self.btn_later.setEnabled(False)
        self.bar.setVisible(True)
        self.bar.setValue(0)
        self.status.setText("Скачиваю установщик…")

        def job():
            import updatecheck
            try:
                path = updatecheck.download(self.release, progress=self._bridge.progress.emit)
            except Exception as e:  # noqa: BLE001 — ошибку показываем в окне
                self._bridge.done.emit(None, str(e))
                return
            self._bridge.done.emit(path, "")

        threading.Thread(target=job, daemon=True, name="release-download").start()

    def _on_progress(self, percent: int):
        self.bar.setValue(max(0, min(100, int(percent))))

    def _on_done(self, path, error: str):
        self.bar.setVisible(False)
        self.btn_download.setEnabled(True)
        self.btn_later.setEnabled(True)
        if error:
            self.status.setText(f"Не скачано: {error}")
            return
        self.path = path
        self.status.setText(f"Установщик скачан и проверен: {path.name}")
        self.btn_run.setVisible(True)
        self.btn_show.setVisible(True)

    def run_installer(self):
        if self.path is None:
            return
        import updatecheck
        from recovery import activity
        activity.record("program", f"Запущен установщик обновления: {self.path.name}")
        updatecheck.run_installer(self.path)

    def show_folder(self):
        if self.path is None:
            return
        os.startfile(str(self.path.parent))
