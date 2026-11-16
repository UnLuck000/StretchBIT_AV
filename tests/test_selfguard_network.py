"""Сторож возвращает сеть после аварийного завершения с VPN (selfguard.recover_network)."""
import time

import selfguard


def test_recover_network_steps_and_budget():
    calls = []

    def ok():
        calls.append("kill switch")
        return True

    def broken():
        raise OSError("нет прав")

    def slow():
        time.sleep(2)
        return True

    report = selfguard.recover_network(0.5, [("kill switch", ok), ("DNS", broken),
                                             ("прокси", slow), ("ядра", lambda: True)])
    assert calls == ["kill switch"]
    assert report[0] == "kill switch: возвращено"
    assert report[1].startswith("DNS: ошибка")
    assert report[2].startswith("прокси: не уложился")
    assert report[3] == "ядра: не хватило времени"       # бюджет истрачен медленным шагом


def test_nothing_to_restore_is_silent():
    assert selfguard.recover_network(5, [("kill switch", lambda: False)]) == []


def test_watchdog_restores_network_without_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(selfguard, "SESSION", tmp_path / "session.json")
    monkeypatch.setattr(selfguard, "CRASH_LOG", tmp_path / "crash.log")
    (tmp_path / "session.json").write_text('{"pid": 4321}', encoding="utf-8")
    monkeypatch.setattr(selfguard, "_wait", lambda pid: None)
    monkeypatch.setattr(selfguard.time, "sleep", lambda s: None)
    monkeypatch.setattr(selfguard, "recover_network", lambda: ["kill switch: возвращено"])
    started = []
    monkeypatch.setattr(selfguard.subprocess, "Popen", lambda *a, **k: started.append(a))
    selfguard.watch(4321, restart=False)
    assert started == []                                   # из исходников — без перезапуска
    assert "kill switch: возвращено" in (tmp_path / "crash.log").read_text(encoding="utf-8")
