"""Выключение Windows с VPN, повтор обновления баз без сети, WinDivert из исходников,
ручной запуск с правами (14.11.2026)."""
import sys
from pathlib import Path

import pytest

from tests.test_service import FakeMonitor


@pytest.fixture
def svc(tmp_path, monkeypatch):
    import quarantine
    from recovery import threatlog
    from scanner import whitelist
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "journal" / "threats.json")
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", tmp_path / "whitelist.json")
    from service.core import ServiceCore
    FakeMonitor.instances = []
    core = ServiceCore(tmp_path / "svc", monitor_factory=FakeMonitor)
    yield core
    core.stop()


def test_vpn_stops_first(svc, monkeypatch):
    """Выключение Windows: сначала VPN (kill switch, DNS), потом защита и ETW — иначе
    Windows завершала службу раньше, и блокировка брандмауэра переживала перезагрузку."""
    order = []
    monkeypatch.setattr(svc.vpn, "stop", lambda: order.append("vpn"))
    monkeypatch.setattr(svc.guards, "stop_all", lambda: order.append("guards"))
    svc.stop()
    assert order[:2] == ["vpn", "guards"] and order.count("vpn") == 1


def test_service_accepts_preshutdown():
    from service import scm
    assert scm.SERVICE_ACCEPT_PRESHUTDOWN == 0x100
    assert scm.PRESHUTDOWN_TIMEOUT_MS >= 30000
    import inspect
    source = inspect.getsource(scm.run_as_service)
    assert "SERVICE_ACCEPT_PRESHUTDOWN" in source
    assert "SERVICE_CONFIG_PRESHUTDOWN_INFO" in inspect.getsource(scm.install)


def test_network_recovered_before_protection(svc, monkeypatch):
    """При запуске службы сеть возвращается раньше загрузки защиты файлов."""
    order = []
    svc.auto_update = True
    svc.config["enabled"] = True
    monkeypatch.setattr(svc, "_recover_vpn", lambda: order.append("recover"))
    monkeypatch.setattr(svc, "_start_monitor", lambda: order.append("monitor"))
    monkeypatch.setattr(svc, "_start_db_updates", lambda: order.append("db"))
    started = []

    class Instant:
        def __init__(self, target, **_kw):
            self.target = target

        def start(self):
            started.append(1)
            self.target()
    monkeypatch.setattr("service.core.threading.Thread", Instant)
    svc.start(pipe=False)
    assert order == ["recover", "monitor", "db"]


def test_bases_retry_soon_after_failure(svc, monkeypatch):
    """Служба стартует раньше Wi-Fi: неудача — повтор через 2 минуты (не больше 5 раз)."""
    import threading
    results = iter([False, False, True, None])
    waits = []
    svc._db_stop = threading.Event()

    def check():
        try:
            return next(results)
        except StopIteration:
            svc._db_stop.set()
            return None
    monkeypatch.setattr(svc, "update_bases_if_due", check)
    monkeypatch.setattr(svc._db_stop, "wait", lambda t: waits.append(t))
    svc._db_loop()
    svc._db_stop = None                                   # потока нет: остановке нечего ждать
    assert waits[:4] == [svc.DB_RETRY, svc.DB_RETRY, svc.DB_CHECK_INTERVAL,
                         svc.DB_CHECK_INTERVAL]


def test_windivert_from_project_when_run_from_sources(tmp_path, monkeypatch):
    from networkmonitor import tls
    project = tls.PROJECT_DIR / "native" / "windivert" / "WinDivert.dll"
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert tls.windivert_safe(project) == (True, "")
    monkeypatch.setattr(sys, "frozen", True, raising=False)   # собранная — только защищённые
    assert not tls._from_project(project)
    other = tmp_path / "WinDivert.dll"
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not tls._from_project(other)


def test_manual_start_does_not_switch_gui_to_uac_administrator():
    """Главное окно не меняет пользователя; системные инструменты повышаются отдельно."""
    source = (Path(__file__).resolve().parent.parent / "gui.py").read_text(encoding="utf-8")
    assert "elevate_on_start" not in source
    assert 'if "--tool" in sys.argv or "--undo" in sys.argv:' in source
    core = (Path(__file__).resolve().parent.parent / "service" / "core.py").read_text(
        encoding="utf-8")
    assert '"--alarm"' in core


def test_service_recover_vpn_uses_selfguard(svc, monkeypatch):
    """Возврат сети после сбоя VPN — через selfguard.recover_network (все 4 шага)."""
    import selfguard
    monkeypatch.setattr(selfguard, "recover_network",
                        lambda: ["kill switch: возвращено", "прокси: возвращено"])
    seen = []
    monkeypatch.setattr(svc.log, "warning", lambda msg, *a: seen.append(msg % a))
    svc._recover_vpn()
    assert seen == ["VPN: после сбоя службы: kill switch: возвращено",
                    "VPN: после сбоя службы: прокси: возвращено"]


def test_background_auto_update_wiring():
    """Обновление только по согласию: уведомление, окно изменений с «Обновить», возврат в трей."""
    gui = (Path(__file__).resolve().parent.parent / "gui.py").read_text(encoding="utf-8")
    assert "update/pending" in gui            # метка «было в трее» перед запуском установщика
    db = (Path(__file__).resolve().parent.parent / "mainwindow" / "databases.py").read_text(
        encoding="utf-8")
    assert "update/auto_install" not in db    # настройки автообновления больше нет
    assert "_show_changelog" in db            # окно со списком изменений (changelog с GitHub)
    assert "update_requested" in db           # скачивание начинается только по кнопке «Обновить»
    assert "run_installer" in db              # мастер Inno Setup (согласие спрашивает он)
    assert "Доступна новая версия" in db      # уведомление о новой версии
