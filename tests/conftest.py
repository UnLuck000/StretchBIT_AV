"""Общие настройки тестов."""
import os
import sys
import tempfile

import pytest

# Конфигурация пользователя (настройки, журнал, белый список, профили VPN — userdata.py) —
# во временной папке: тесты не трогают настоящую %APPDATA%\StretchBitConfiguration.
# Задаётся до импорта модулей программы: пути вычисляются при импорте.
os.environ["STRETCHBIT_CONFIG_DIR"] = tempfile.mkdtemp(prefix="sbit-config-")
# защищённые копии списков доверия и ключ кэша (trustseal.py) — тоже во временной папке,
# не в настоящей %ProgramData%\StretchBIT
os.environ["STRETCHBIT_SEAL_DIR"] = tempfile.mkdtemp(prefix="sbit-seal-")

# технический журнал logs/app.log: «import gui» в тесте включает его (diag_log.setup), и
# дальше туда писали бы все тесты — в настоящий журнал проекта. Во временную папку.
from pathlib import Path  # noqa: E402

from diag import log as _diag_log  # noqa: E402

_diag_log.LOG_DIR = Path(tempfile.mkdtemp(prefix="sbit-logs-"))
_diag_log.LOG_FILE = _diag_log.LOG_DIR / "app.log"

# Запущенная служба установленной версии (StretchBITService-test) приостанавливает нити
# процесса pytest, если тесты читают файлы с «секретными» именами (приманки, Login Data):
# процесс зависает на первом же долгом time.sleep и прогон кажется сломанным. Не баг
# тестов — так работает защита от стилеров. Служба останавливается с правами администратора.
try:
    import psutil
    for _p in psutil.process_iter(["name"]):
        if (_p.info.get("name") or "").lower() == "stretchbit.exe":
            print("\nВНИМАНИЕ: запущена StretchBIT.exe — служба программы может "
                  "приостановить тесты (приманки, стилер-охрана) и прогон зависнет. "
                  "Остановите её с правами администратора: "
                  "sc stop StretchBITService-test\n", file=sys.stderr, flush=True)
            break
except Exception:  # noqa: BLE001, S110 — psutil недоступен: предупреждение не критично
    pass


@pytest.fixture(autouse=True)
def _free_widgets():
    """После теста виджеты удаляются, пока QApplication жив: без этого PySide6 изредка
    падает (access violation) при завершении процесса, если окна дожили до финализации
    интерпретатора. Без QApplication (чистые тесты) — ничего не делает."""
    from PySide6.QtCore import QEvent
    from PySide6.QtWidgets import QApplication
    yield
    app = QApplication.instance()
    if app is None:
        return
    for widget in QApplication.topLevelWidgets():
        widget.deleteLater()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


@pytest.fixture(autouse=True)
def _separate_release_overrides(tmp_path_factory, monkeypatch):
    """Тесты идут как тестовая версия, а она пишет исключения в signatures/
    release_overrides.json (он в Git и в релизе) — тесты его не трогают."""
    from scanner import overrides
    folder = tmp_path_factory.mktemp("release_overrides")
    monkeypatch.setattr(overrides, "RELEASE_FILE", folder / "release_overrides.json")
    monkeypatch.setattr(overrides, "_cache", None)
    # отчёт о работе (reports/activity/events.jsonl) — тоже не настоящий
    from recovery import activity
    activity_dir = tmp_path_factory.mktemp("activity")
    monkeypatch.setattr(activity, "ACTIVITY_DIR", activity_dir)
    monkeypatch.setattr(activity, "EVENTS_FILE", activity_dir / "events.jsonl")
    from scanner import whitelist
    whitelist.forget_trusted()  # доверенные хэши помнятся 2 с: тесты друг другу не мешают
