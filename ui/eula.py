"""Ознакомление с MIT и диагностикой до запуска окна защиты, в том числе в ZIP."""
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QLabel, QMessageBox, QTextBrowser, QVBoxLayout,
)

from diag import consent


class EulaDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Лицензия MIT и диагностика StretchBIT")
        self.resize(740, 600)
        layout = QVBoxLayout(self)
        self.body = QTextBrowser()
        self.body.setPlainText(consent.text())
        layout.addWidget(self.body, 1)
        hint = QLabel("Сетевой отправки отчётов пока нет. Перед её включением потребуется "
                      "новая редакция условий и повторное согласие.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.checkbox = QCheckBox("Я ознакомился с лицензией MIT и политикой конфиденциальности")
        layout.addWidget(self.checkbox)
        buttons = QDialogButtonBox()
        self.accept_button = buttons.addButton("Продолжить", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton("Закрыть программу", QDialogButtonBox.ButtonRole.RejectRole)
        self.accept_button.setEnabled(False)
        self.checkbox.toggled.connect(self.accept_button.setEnabled)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def ensure_accepted(parent=None) -> bool:
    if consent.accepted():
        return True
    try:
        dialog = EulaDialog(parent)
    except OSError:
        QMessageBox.critical(parent, "Соглашение недоступно",
                             "Не удалось прочитать лицензионные документы. Запуск отменён; "
                             "восстановите файлы программы.")
        return False
    if dialog.exec() != QDialog.DialogCode.Accepted or not dialog.checkbox.isChecked():
        return False
    consent.accept()
    return True
