"""Отдельное повышение инструментов: без настоящего UAC, памяти процессов и системных действий."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from service import elevate, remote
from mainwindow.tools import ToolsMixin
from ui import access


@pytest.mark.parametrize("service", [None, object()])
def test_privileged_tools_request_rights_independently_of_service(monkeypatch, service):
    monkeypatch.setattr(remote, "REMOTE", service)
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    for tool in ("processes", "recovery", "autoruns", "drivers"):
        assert elevate.wanted(tool)
    assert not elevate.wanted("vpn")
    monkeypatch.setattr("trustseal.is_admin", lambda: True)
    assert not elevate.wanted("processes")


def test_tool_arguments_keep_memory_and_recovery_restrictions():
    assert elevate.tool_arguments("processes") == ["--tool", "processes"]
    assert elevate.tool_arguments("processes", allowed=["memory"]) == [
        "--tool", "processes", "--allow-memory"]
    assert elevate.tool_arguments("recovery", 2, allowed=["checks"], action="check") == [
        "--tool", "recovery", "--tab", "2", "--allow-checks", "--action", "check"]
    for kwargs in ({"name": "vpn"}, {"name": "processes", "action": "create"},
                   {"name": "recovery", "action": "arbitrary"},
                   {"name": "recovery", "allowed": ["arbitrary"]}):
        with pytest.raises(ValueError):
            elevate.tool_arguments(**kwargs)


def test_uac_cancellation_does_not_report_success(monkeypatch):
    monkeypatch.setattr(elevate, "start", lambda args: None)
    assert not elevate.open_tool("processes", allowed=["memory"])


def test_process_manager_opens_locally_without_uac(monkeypatch):
    calls = []
    signal = SimpleNamespace(connect=lambda callback: None)
    local = SimpleNamespace(analyze_requested=signal, restart_requested=signal,
                            set_memory_allowed=lambda on: None, show=lambda: None,
                            raise_=lambda: None, activateWindow=lambda: None)
    monkeypatch.setattr("mainwindow.tools.ProcessWindow", lambda: local)
    monkeypatch.setattr(access, "allowed", lambda key: True)
    window = SimpleNamespace(tool_blocked=lambda key: False, proc_window=None,
                             _open_elevated=lambda name: calls.append(name) or True,
                             apply_on_top=lambda on: None)
    ToolsMixin.open_process_manager(window)
    assert calls == [] and window.proc_window is local


def test_recovery_action_requests_uac_even_if_local_window_exists():
    calls = []
    local = object()
    window = SimpleNamespace(TAB_TOOLS={0: "btnRestorePoint"}, recovery_window=local,
                             tool_blocked=lambda key: False,
                             _open_elevated=lambda *args: calls.append(args) or True)
    ToolsMixin.open_recovery(window, 0, "create")
    assert calls == [("recovery", 0, "create")]
    assert window.recovery_window is local


@pytest.mark.parametrize("success", [False, True])
def test_restart_replaces_only_tool_and_only_after_uac_success(success):
    closed = []
    local = SimpleNamespace(close=lambda: closed.append(True))
    window = SimpleNamespace(proc_window=local, _open_elevated=lambda *args: success)
    ToolsMixin._restart_tool_as_admin(window, "processes", "proc_window")
    assert closed == ([True] if success else [])
    assert window.proc_window is (None if success else local)


def test_elevation_passes_original_ui_permissions(monkeypatch):
    monkeypatch.setattr(elevate, "wanted", lambda name: True)
    monkeypatch.setattr(access, "allowed", lambda button: button == "btnSfcDism")
    calls = []
    monkeypatch.setattr(elevate, "open_tool",
                        lambda *args, **kwargs: calls.append((args, kwargs)) or True)
    window = SimpleNamespace(statusBar=lambda: SimpleNamespace(showMessage=lambda *args: None))
    assert ToolsMixin._open_elevated(window, "processes")
    assert calls[-1][1]["allowed"] == []
    assert ToolsMixin._open_elevated(window, "recovery", 1)
    assert calls[-1][1]["allowed"] == ["sfc"]
    assert not ToolsMixin._open_elevated(window, "recovery", 3)  # исходный HKCU
    assert len(calls) == 2


def test_direct_unprivileged_tool_start_is_not_marked_elevated(monkeypatch):
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    assert elevate.run_tool(["app", "--tool", "processes"]) == 5


@pytest.mark.parametrize("allow_memory", [False, True])
def test_elevated_process_window_receives_memory_restriction(monkeypatch, allow_memory):
    from PySide6.QtWidgets import QApplication
    from processmanager import window as process_window
    from ui import theme
    app = QApplication.instance() or QApplication([])
    calls = []
    window = SimpleNamespace(set_memory_allowed=lambda on: calls.append(on),
                             windowTitle=lambda: "Процессы", setWindowTitle=lambda text: None,
                             show=lambda: None)
    monkeypatch.setattr("trustseal.is_admin", lambda: True)
    monkeypatch.setattr(elevate, "_connect_service", lambda: None)
    monkeypatch.setattr(theme, "apply_theme", lambda *args: None)
    monkeypatch.setattr(QApplication, "exec", lambda self: 0)
    monkeypatch.setattr(process_window, "ProcessWindow", lambda: window)
    args = ["app", "--tool", "processes"] + (["--allow-memory"] if allow_memory else [])
    assert elevate.run_tool(args) == 0
    assert calls == [allow_memory]
    assert app is QApplication.instance()


def test_restart_signals_no_longer_restart_main_gui():
    text = (Path(__file__).resolve().parent.parent / "mainwindow" / "tools.py").read_text(
        encoding="utf-8")
    assert "restart_requested.connect(self.restart_as_admin)" not in text
    assert '_restart_tool_as_admin("processes", "proc_window")' in text
    assert '_restart_tool_as_admin("recovery", "recovery_window")' in text
