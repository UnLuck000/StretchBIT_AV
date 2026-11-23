import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

from ui.pages import AboutPage, DashboardPage, DebugPage, SettingsPage, ToolsPage
from ui.registry import FEATURES
from ui.exclusions_page import ExclusionsPage

from recovery.journal_page import JournalPage


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_pages_load(app):
    DashboardPage()
    SettingsPage()
    AboutPage()
    DebugPage(window=None)
    JournalPage()
    ExclusionsPage()


def test_no_auto_install_setting_and_changelog_window(app):
    """Настройки автообновления больше нет (обновление только по согласию); есть окно изменений."""
    from ui import settings as cfg
    from ui.changelog_window import ChangelogWindow
    page = SettingsPage()
    assert "update/auto_install" not in cfg.DEFAULTS
    assert not hasattr(page, "chk_auto_update")  # чекбокс «Автообновление в фоне» убран
    win = ChangelogWindow("1.2.3", "## Изменено\n- пункт")
    assert win is not None
    assert win.btn_update.text() == "Обновить"
    assert win.btn_later.text() == "Позже"


def test_changelog_update_button_emits_consent(app):
    """«Обновить» — единственный способ начать скачивание: по кнопке приходит сигнал согласия."""
    from ui.changelog_window import ChangelogWindow
    win = ChangelogWindow("1.2.3", "## x\n- y")
    fired = []
    win.update_requested.connect(lambda: fired.append(1))
    win.btn_update.click()
    assert fired == [1]


def test_every_literal_settings_key_is_in_defaults():
    """cfg.get/set_ с литеральной строкой обязан быть в DEFAULTS: иначе KeyError при запуске."""
    import re
    from pathlib import Path

    from ui import settings as cfg
    root = Path(__file__).resolve().parent.parent
    skip = {"tests", "tools", "user_reports", "release", "dist", "build", "__pycache__"}
    pattern = re.compile(r'cfg\.(?:get|set_)\(\s*["\']([a-z0-9_][a-z0-9_/]*)["\']')
    keys = set()
    for py in root.rglob("*.py"):
        if skip & set(py.parts):
            continue
        for m in pattern.finditer(py.read_text(encoding="utf-8", errors="replace")):
            keys.add(m.group(1))
    missing = sorted(k for k in keys if k not in cfg.DEFAULTS)
    assert not missing, f"нет в DEFAULTS: {missing}"


def test_every_feature_has_a_button(app):
    pages = (ToolsPage(window=None), DebugPage(window=None))
    for button_id in FEATURES:
        found = any(p.ui.findChild(QPushButton, button_id) is not None for p in pages)
        assert found, f"нет кнопки {button_id}"
