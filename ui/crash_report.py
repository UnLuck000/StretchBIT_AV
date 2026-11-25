"""Отдельное окно живого процесса после завершения аварийного GUI."""
import sys
from pathlib import Path


def main() -> int:
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    from diag import consent, support
    if not consent.accepted():
        return 0
    app = QApplication.instance() or QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)
    box = QMessageBox()
    box.setWindowTitle("StretchBIT: аварийное завершение")
    box.setIcon(QMessageBox.Icon.Warning)
    box.setText("StretchBIT завершился нештатно. Хотите подготовить crash-report разработчику?")
    box.setInformativeText(
        "В отчёте только технические сводки ошибок, версия программы/Windows и известные "
        "SHA-256. Без имён/путей файлов, команд, адресов, профилей и содержимого документов.\n\n"
        "Сервер отправки пока не подключён. Можно сохранить отчёт локально; "
        "это окно показал сторож, а не повторный запуск программы.")
    send = box.addButton("Отправить crash-report", QMessageBox.ButtonRole.ActionRole)
    send.setEnabled(False)
    save = box.addButton("Сохранить отчёт…", QMessageBox.ButtonRole.AcceptRole)
    box.addButton("Не сейчас", QMessageBox.ButtonRole.RejectRole)
    box.exec()
    if box.clickedButton() is save:
        path, _ = QFileDialog.getSaveFileName(None, "Сохранить crash-report", "StretchBIT-crash.zip",
                                              "ZIP (*.zip)")
        if path:
            try:
                support.collect(Path(path), "crash")
                QMessageBox.information(None, "Crash-report", "Отчёт сохранён локально. "
                                        "Ничего не отправлено.")
            except OSError:
                QMessageBox.warning(None, "Crash-report", "Не удалось сохранить отчёт.")
    return 0
