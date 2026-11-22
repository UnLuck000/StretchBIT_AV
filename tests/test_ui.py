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


def test_auto_update_setting_under_password(app):
    """«Автообновление в фоне» — в группе «Запуск», которая видна только после пароля."""
    from ui import settings as cfg
    page = SettingsPage()
    assert page.chk_auto_update is not None
    assert cfg.DEFAULTS["update/auto_install"] is True   # автообновление включено по умолчанию
    assert not page.chk_auto_update.isVisible()  # родитель groupStartup скрыт до пароля


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
