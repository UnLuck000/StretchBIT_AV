"""Изменение папок на ходу без настоящего наблюдения, служб и остановки процессов."""
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QListWidget, QPushButton, QMessageBox

import monitor
from mainwindow.protection import ProtectionMixin, _protection_status
from ui import access


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_folder_controls_stay_enabled_while_running(app):
    window = SimpleNamespace(
        protect_btn=QPushButton(), watch_list=QListWidget(),
        watch_add_btn=QPushButton(), watch_remove_btn=QPushButton(),
        protection_page=SimpleNamespace(set_running=lambda running: None),
        protect_status=QLabel(), refresh_dashboard=lambda: None, _apply_off_locks=lambda: None)
    for widget in (window.watch_list, window.watch_add_btn, window.watch_remove_btn):
        widget.setEnabled(False)
    ProtectionMixin._set_protection_ui(window, True)
    assert all(w.isEnabled() for w in (
        window.watch_list, window.watch_add_btn, window.watch_remove_btn))


def _window():
    changes, saved, blocked = [], [], []
    watch = QListWidget()
    watch.addItem("first")
    window = SimpleNamespace(watch_list=watch,
                             monitor=SimpleNamespace(update_folders=changes.append),
                             _add_watch_item=watch.addItem,
                             _off_blocked=blocked.append)
    window._save_watch_folders = lambda: saved.append(
        [watch.item(i).text() for i in range(watch.count())])
    return window, changes, saved, blocked


def test_live_folder_edit_is_applied_before_saving(app, monkeypatch):
    monkeypatch.setattr(access, "protection_locked", lambda: False)
    window, changes, saved, _ = _window()
    assert ProtectionMixin._change_watch_folders(window, ["second"])
    assert changes == [["second"]] and saved == [["second"]]
    assert window.watch_list.item(0).text() == "second"


def test_live_folder_removal_respects_lock(app, monkeypatch):
    monkeypatch.setattr(access, "protection_locked", lambda: True)
    window, changes, saved, blocked = _window()
    assert not ProtectionMixin._change_watch_folders(window, [])
    assert blocked and not changes and not saved
    assert window.watch_list.item(0).text() == "first"
    # Добавление папки не ослабляет защиту.
    assert ProtectionMixin._change_watch_folders(window, ["first", "second"])


def test_service_refusal_preserves_ui_folder_list(app, monkeypatch):
    monkeypatch.setattr(access, "protection_locked", lambda: False)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: None)
    window, _, saved, _ = _window()
    window.monitor.update_folders = lambda folders: (_ for _ in ()).throw(PermissionError("denied"))
    assert not ProtectionMixin._change_watch_folders(window, ["second"])
    assert not saved and window.watch_list.item(0).text() == "first"


class Observer:
    def __init__(self, events, name):
        self.events, self.name, self.ident = events, name, None

    def start(self):
        self.events.append(self.name + ":start")
        self.ident = 1

    def stop(self):
        self.events.append(self.name + ":stop")

    def join(self, timeout):
        self.events.append(self.name + ":join")


def test_monitor_starts_new_watches_before_stopping_old(tmp_path, monkeypatch):
    events = []
    mon = monitor.RealtimeMonitor([tmp_path / "old"], tmp_path, tmp_path, [], lambda *a: None,
                                  system=[])
    old, new = Observer(events, "old"), Observer(events, "new")
    monkeypatch.setattr(monitor, "Observer", lambda: new)
    monkeypatch.setattr(mon, "_schedule", lambda obs, handler: (1, 0))
    mon.update_folders([tmp_path / "new"])
    assert mon._replace_observer(old, None) is new
    assert mon.folders == [tmp_path / "new"]
    assert events == ["new:start", "old:stop", "old:join"]


def test_failed_watch_change_keeps_previous_observer(tmp_path, monkeypatch):
    events, notices = [], []
    mon = monitor.RealtimeMonitor([tmp_path / "old"], tmp_path, tmp_path, [],
                                  lambda *a: notices.append(a), system=[])
    old, new = Observer(events, "old"), Observer(events, "new")
    monkeypatch.setattr(monitor, "Observer", lambda: new)
    monkeypatch.setattr(mon, "_schedule", lambda obs, handler: (0, 0))
    mon.update_folders([])
    assert mon._replace_observer(old, None) is old
    assert mon.folders == [tmp_path / "old"] and "old:stop" not in events
    assert notices[0][0] == "error"


def test_status_hides_counter_from_older_service():
    assert _protection_status("Защита включена. Папок пользователя: 3, системных: 21") == ""
    assert _protection_status("Защита включена.") == ""
    assert _protection_status("Загружаю базы...") == "Загружаю базы..."


def test_remote_monitor_updates_folders_without_stopping():
    from service.client import RemoteMonitor
    calls = []
    def call(op, **args):
        calls.append((op, args))
        return {"run": 7}
    remote = RemoteMonitor(SimpleNamespace(call=call), ["old"], run=7)
    remote.update_folders([Path("new")])
    assert remote.folders == ["new"] and remote.run == 7
    assert calls == [("protection.set", {"on": True, "folders": ["new"]})]
