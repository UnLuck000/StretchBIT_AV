"""Машинная установка и личный сеанс: без UAC, настоящего реестра, служб и подключений VPN."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import userdata
import usercontext
from ui import settings as cfg
from vpn import backends

ROOT = Path(__file__).resolve().parent.parent


def test_configuration_uses_token_known_folder_not_admin_environment(tmp_path, monkeypatch):
    from diag import edition
    monkeypatch.setattr(edition, "is_test", lambda: True)
    monkeypatch.setattr(userdata.sys, "frozen", True, raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "admin"))
    monkeypatch.setenv(userdata.ENV, str(tmp_path / "injected"))
    monkeypatch.setattr(usercontext, "roaming_dir", lambda: tmp_path / "user")
    folder = userdata._config_dir()
    assert folder.parent == tmp_path / "user"


def test_known_folder_failure_is_not_silently_replaced_with_admin_path(monkeypatch):
    def fail(*args):
        raise OSError("known-folder")
    monkeypatch.setattr(usercontext, "known_folder", fail)
    with pytest.raises(OSError):
        usercontext.roaming_dir()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Known Folders")
def test_real_known_folders_ignore_appdata_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "not-the-user"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "not-the-user-local"))
    assert usercontext.roaming_dir().is_absolute()
    assert usercontext.local_dir().is_absolute()
    assert usercontext.roaming_dir() != tmp_path / "not-the-user"
    assert usercontext.local_dir() != tmp_path / "not-the-user-local"


def test_installer_registers_session_start_for_all_users_not_admin_task():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    entry = next(line for line in text.splitlines() if "ValueData:" in line and
                 "--session-start" in line)
    assert "Root: HKLM;" in entry and "ValueName: \"{#AppKey}\"" in entry
    assert "uninsdeletevalue" in entry
    assert 'Parameters: "--set-autostart' not in text
    assert 'ValueName: "GuiEnabled"; ValueData: "1"; Tasks: autostart' in text
    assert 'ValueName: "GuiEnabled"; ValueData: "0"; Tasks: not autostart' in text


class Key:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def registry(monkeypatch, values):
    def query(key, name):
        try:
            return values[(key.path, name)], 1
        except KeyError:
            raise FileNotFoundError(name) from None
    fake = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_READ=1, KEY_WOW64_64KEY=2,
                           OpenKey=lambda root, path, *args: Key(path),
                           QueryValueEx=query)
    monkeypatch.setattr(cfg, "winreg", fake)
    monkeypatch.setattr(cfg.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cfg, "_startup_app_key", lambda: "StretchBIT-test")


def test_new_user_inherits_machine_default_without_writing_admin_settings(monkeypatch):
    registry(monkeypatch, {(r"Software\StretchBIT-test\Startup", "GuiEnabled"): 1})
    monkeypatch.setattr(cfg, "store", lambda: SimpleNamespace(contains=lambda key: False))
    assert cfg.autostart_gui_enabled()


@pytest.mark.parametrize("personal", [False, True])
def test_personal_choice_overrides_administrator_install_default(monkeypatch, personal):
    registry(monkeypatch, {(r"Software\StretchBIT-test\Startup", "GuiEnabled"): int(not personal)})
    monkeypatch.setattr(cfg, "store", lambda: SimpleNamespace(contains=lambda key: True))
    monkeypatch.setattr(cfg, "get", lambda key: personal)
    assert cfg.autostart_gui_enabled() is personal


def test_machine_session_start_is_checked_against_this_executable(monkeypatch):
    values = {(cfg.RUN_KEY, "StretchBIT-test"): cfg.machine_startup_command()}
    registry(monkeypatch, values)
    assert cfg.machine_startup_current()
    values[(cfg.RUN_KEY, "StretchBIT-test")] = '"C:\\other.exe" --session-start'
    assert not cfg.machine_startup_current()


def test_installed_user_does_not_need_to_create_a_privileged_task(monkeypatch):
    monkeypatch.setattr(cfg, "machine_startup_current", lambda: True)
    monkeypatch.setattr(cfg, "_remove_run_value", lambda: None)
    monkeypatch.setattr(cfg, "autostart_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(cfg, "_schtasks", lambda *args: calls.append(args))
    cfg.set_autostart(True)
    assert calls == []


def test_custom_uninstall_removes_only_matching_machine_launcher(monkeypatch):
    values = {(cfg.RUN_KEY, "StretchBIT-test"): cfg.machine_startup_command()}
    registry(monkeypatch, values)
    deleted = []
    cfg.winreg.KEY_SET_VALUE = 4
    cfg.winreg.DeleteValue = lambda key, name: deleted.append((key.path, name))
    monkeypatch.setattr(cfg, "_schtasks", lambda *args: SimpleNamespace(returncode=0, stdout=""))
    cfg.remove_install_autostart()
    assert deleted == [(cfg.RUN_KEY, "StretchBIT-test")]
    deleted.clear()
    values[(cfg.RUN_KEY, "StretchBIT-test")] = '"C:\\other.exe" --session-start'
    cfg.remove_install_autostart()
    assert deleted == []


@pytest.mark.parametrize(("kind", "mode"), [("vless", "tun"), ("wireguard", ""),
                                          ("openvpn", ""), ("vless", "tun-xray")])
def test_non_admin_vpn_never_falls_back_to_privileged_local_backend(monkeypatch, kind, mode):
    monkeypatch.setattr(backends, "REMOTE", None)
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    backend = backends.backend_for(kind, lambda text: None, mode)
    assert isinstance(backend, backends.ServiceRequiredBackend)
    assert not backend.available
    backend.connect(None)
    assert backend.state == backends.ERROR


def test_tun_uses_service_while_proxy_stays_in_user_context(monkeypatch):
    calls = []
    remote_backend = object()
    monkeypatch.setattr(backends, "REMOTE", SimpleNamespace(
        backend=lambda *args: calls.append(args) or remote_backend))
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    local = object()
    monkeypatch.setattr(backends, "XrayBackend", lambda log: local)
    assert backends.backend_for("vless", print, "tun") is remote_backend
    assert backends.backend_for("vless", print, "proxy") is local
    assert len(calls) == 1


def test_vpn_service_runtime_is_in_machine_data_not_installer_account(tmp_path, monkeypatch):
    from service.vpnhost import VpnHost
    monkeypatch.setattr(backends, "SingBoxBackend", lambda log: SimpleNamespace())
    host = VpnHost(lambda *args: None, tmp_path / "service")
    backend = host._make("vless", "tun")
    assert backend.tunnel_dir == tmp_path / "service" / "vpn-runtime"


def test_opening_tools_does_not_automatically_request_uac():
    source = (ROOT / "mainwindow" / "tools.py").read_text(encoding="utf-8")
    for start, end in (("def open_process_manager(", "def open_resource_report("),
                       ("def open_autoruns(", "def open_process_manager("),
                       ("def open_tool(", "def run_feature(")):
        section = source[source.index(start):source.index(end)]
        assert "self._open_elevated(" not in section
    gui = (ROOT / "gui.py").read_text(encoding="utf-8")
    restart = gui[gui.index("def restart_as_admin("):gui.index("# ---------- анализатор файлов")]
    assert "relaunch_as_admin(" not in restart and "quit_app(" not in restart


def test_service_refreshes_other_user_profiles_from_machine_not_request(monkeypatch, tmp_path):
    import threading
    from service import core as svc_core
    from service.pipeserver import Client
    proposed = [(tmp_path / "user" / "Documents", True, True)]
    calls = []
    core = SimpleNamespace(_lock=threading.RLock(), boot="test-boot",
                           _monitor=SimpleNamespace(update_system_folders=lambda value: calls.append(value)))
    monkeypatch.setattr(svc_core, "service_system_folders", lambda: proposed)
    reply = svc_core.ServiceCore.op_hello(core, Client(pid=1, image="", sid="S-1-5-21-user"),
                                         {"folders": [str(tmp_path / "admin")]})
    assert calls == [proposed] and reply["sid"] == "S-1-5-21-user"


@pytest.mark.parametrize("success", [False, True])
def test_profile_refresh_replaces_watches_transactionally(tmp_path, monkeypatch, success):
    import monitor
    events = []
    old_system = [(tmp_path / "admin", True, True)]
    new_system = [(tmp_path / "admin", True, True), (tmp_path / "user", True, True)]
    mon = monitor.RealtimeMonitor([], tmp_path, tmp_path, [], lambda *args: None,
                                   system=old_system)
    old = SimpleNamespace(stop=lambda: events.append("old-stop"), join=lambda **kw: None)
    new = SimpleNamespace(start=lambda: events.append("new-start"),
                          stop=lambda: events.append("new-stop"), ident=None)
    monkeypatch.setattr(monitor, "Observer", lambda: new)
    monkeypatch.setattr(mon, "_schedule", lambda *args: (0, 2) if success else (0, 0))
    mon.update_system_folders(new_system)
    assert mon._replace_observer(old, None) is (new if success else old)
    assert mon.system == (new_system if success else old_system)
    assert events == (["new-start", "old-stop"] if success else ["new-stop"])


def test_profile_refresh_runs_without_gui_and_keeps_old_roots_on_provider_failure(tmp_path):
    import monitor
    calls = []
    proposed = [(tmp_path / "new-user", True, True)]
    def provider():
        calls.append(True)
        return proposed
    mon = monitor.RealtimeMonitor([], tmp_path, tmp_path, [], lambda *args: None,
                                   system=[], system_provider=provider)
    deadline = mon._next_system_refresh
    mon._refresh_system_folders(deadline - 1)
    assert calls == []
    mon._refresh_system_folders(deadline)
    assert calls == [True] and mon._system_request == proposed
    mon._refresh_system_folders(deadline + 1)
    assert calls == [True]
    def fail():
        raise OSError("registry")
    mon._system_provider = fail
    mon._refresh_system_folders(deadline + 60)
    assert mon._system_request == proposed and mon.system == []


def test_recovery_requests_uac_only_for_privileged_action(monkeypatch):
    from recovery import window as recovery_window
    monkeypatch.setattr(recovery_window, "is_admin", lambda: False)
    calls, checks = [], []
    window = SimpleNamespace(_proc=None, admin_action_requested=SimpleNamespace(
        emit=lambda *args: calls.append(args)), _async=lambda *args: checks.append(args[0]))
    recovery_window.RecoveryWindow.run_system_check(window)
    assert checks == ["checks"] and calls == []
    recovery_window.RecoveryWindow.create_restore_point(window)
    recovery_window.RecoveryWindow.enable_protection(window)
    recovery_window.RecoveryWindow.start_command(window, "sfc_verify")
    assert calls == [("create", 0), ("enable-protection", 0), ("command:sfc_verify", 1)]
    assert checks == ["checks"]
