"""Окно обновления программы (ui/update_window.py): предложение и скачивание."""
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


class _Release:
    version = "1.2.1"
    page = "https://github.com/x/y/releases/tag/1.2.1"
    notes = "Исправления и улучшения."


def test_update_window_offers_download(qapp):
    from ui.update_window import UpdateWindow
    win = UpdateWindow(_Release())
    assert win.windowModality() == Qt.WindowModality.NonModal
    assert win.btn_download.text() == "Скачать и установить"
    assert win.btn_run.isHidden() and win.btn_show.isHidden()
    win.close()
