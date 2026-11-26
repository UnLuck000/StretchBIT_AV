"""Launcher: разрешения установки, границы сеанса и whitelist без настоящих SYSTEM-процессов."""
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager

import pytest

import bootstrap
import launcher
from service import protocol
from service.core import ServiceCore
from service.pipeserver import Client
from ui import settings as cfg

SID = "S-1-5-21-111-222-333-1001"
ROOT = Path(__file__).resolve().parent.parent


def caller(**kwargs):
    return Client(pid=100, image="app.exe", sid=SID, session=2, **kwargs)


def test_coordinator_requires_machine_permission():
    calls = []
    coordinator = launcher.Coordinator(lambda *args: calls.append(args) or 200)
    with pytest.raises(PermissionError):
        coordinator.open(caller(), {"tool": "processes"}, False)
    assert calls == []
    result = coordinator.open(caller(), {"tool": "processes", "allowed": ["memory"]}, True)
    assert result == {"pid": 200, "system": True}
    assert calls[0][1] == ["--tool", "processes", "--allow-memory"]


@pytest.mark.parametrize("payload", [
    {"tool": "cmd.exe"}, {"tool": "processes", "exe": "evil"},
    {"tool": "processes", "session": 99}, {"tool": "processes", "owner_sid": SID},
    {"tool": "processes", "tab": True}, {"tool": "processes", "tab": -1},
    {"tool": "processes", "allowed": "memory"}, {"tool": "processes", "allowed": ["evil"]},
    {"tool": "recovery", "action": "powershell -enc ..."},
    {"tool": "recovery", "tab": 3}, {"tool": "processes", "config": "other-user"},
])
def test_no_arbitrary_commands_paths_accounts_or_sessions(payload):
    with pytest.raises(ValueError):
        launcher.arguments(payload)


@pytest.mark.parametrize(("pid", "session", "sid"), [(0, 2, SID), (1, 0, SID),
                                                   (1, 2, ""), (1, 2, "../../other")])
def test_unknown_identity_is_denied(pid, session, sid):
    coordinator = launcher.Coordinator(lambda *args: pytest.fail("must not spawn"))
    with pytest.raises(PermissionError):
        coordinator.open(Client(pid, "", sid=sid, session=session), {"tool": "processes"}, True)


def test_policy_changes_require_real_admin_client_and_persist(tmp_path):
    core = ServiceCore(tmp_path, monitor_factory=lambda *args: None)
    assert not core.handle(caller(), "launcher.status", {})["allowed"]
    with pytest.raises(PermissionError):
        core.handle(caller(), "launcher.policy", {"allowed": True})
    assert core.handle(caller(elevated=True), "launcher.policy", {"allowed": True})["allowed"]
    again = ServiceCore(tmp_path, monitor_factory=lambda *args: None)
    assert again.config["launcher_allowed"] is True
    with pytest.raises(ValueError):
        core.handle(caller(elevated=True), "launcher.policy", {"allowed": "true"})
    core.handle(caller(elevated=True), "launcher.policy", {"allowed": False})
    with pytest.raises(PermissionError):
        core.handle(caller(), "launcher.open", {"tool": "processes"})
    assert protocol.OPS["launcher.policy"] == protocol.ADMIN


def test_gui_never_requests_hidden_uac_when_machine_permission_is_missing(monkeypatch):
    calls = []
    monkeypatch.setattr(cfg, "get", lambda key: True)
    monkeypatch.setattr(launcher, "CLIENT", SimpleNamespace(
        call=lambda *args, **kwargs: calls.append(args[0]) or {"allowed": False}))
    assert not launcher.try_open("processes")
    assert calls == ["launcher.status"]


def test_personal_opt_out_leaves_privileged_launcher_unused(monkeypatch):
    monkeypatch.setattr(cfg, "get", lambda key: False)
    monkeypatch.setattr(launcher, "CLIENT", SimpleNamespace(
        call=lambda *args, **kwargs: pytest.fail("must not request system rights")))
    assert not launcher.try_open("processes")


def test_gui_uses_same_coordinator_after_manual_start_and_autostart(monkeypatch):
    calls = []
    def call(op, **args):
        calls.append((op, args))
        return {"allowed": True} if op == "launcher.status" else {"pid": 200}
    monkeypatch.setattr(cfg, "get", lambda key: True)
    monkeypatch.setattr(launcher, "CLIENT", SimpleNamespace(call=call))
    assert launcher.try_open("recovery", 1, allowed=["sfc"], action="command:sfc_verify")
    assert calls[1][0] == "launcher.open"
    assert calls[1][1]["action"] == "command:sfc_verify"
    assert not {"sid", "session", "exe", "config"} & calls[1][1].keys()


def test_dispatcher_routes_machine_tools_before_user_gui(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher, "machine_tool", lambda argv: calls.append(list(argv)) or 5)
    args = ["app", "--machine-tool", "--owner-sid", SID, "--tool", "processes"]
    assert bootstrap.dispatch(args) == 5 and calls == [args]
    assert bootstrap.dispatch(["app"]) is None


def test_non_system_cannot_impersonate_machine_tool(monkeypatch):
    monkeypatch.setattr("service.winapi.current_sid", lambda: SID)
    assert launcher.machine_tool(["app", "--machine-tool", "--owner-sid", SID]) == 5


def test_machine_tool_keeps_machine_storage_and_binds_original_user(monkeypatch, tmp_path):
    from service import winapi, scm
    from service import elevate
    import psutil
    import userdata
    import privatefiles
    calls = []
    monkeypatch.setattr("deployment.installed_with_service", lambda: True)
    monkeypatch.setattr(winapi, "current_sid", lambda: "S-1-5-18")
    monkeypatch.setattr(scm, "query", lambda name: {"pid": 77, "state": scm.RUNNING})
    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(ppid=lambda: 77))
    monkeypatch.setattr(winapi, "session_of", lambda pid: 2)
    monkeypatch.setattr("trustseal.protected_dir", lambda: tmp_path)
    monkeypatch.setattr(privatefiles, "protect_directory",
                        lambda path, **kwargs: calls.append(("acl", path, kwargs)))
    monkeypatch.setattr(userdata, "set_root", lambda root: calls.append(("root", root)))
    @contextmanager
    def context(session, sid):
        calls.append(("context", session, sid))
        yield
    monkeypatch.setattr(winapi, "interactive_user_context", context)
    monkeypatch.setattr(elevate, "run_tool",
                        lambda args, **kwargs: calls.append(("tool", args, kwargs)) or 0)
    args = ["app", "--machine-tool", "--owner-sid", SID, "--tool", "processes", "--allow-memory"]
    assert launcher.machine_tool(args) == 0
    root = tmp_path / "service" / "tools" / SID
    assert calls == [("acl", root, {"system_only": True}), ("root", root),
                     ("context", 2, SID),
                     ("tool", ["app", "--tool", "processes", "--allow-memory"], {"system": True})]


def test_machine_tool_rejects_extra_flags_before_touching_storage(monkeypatch):
    from service import winapi, scm
    import psutil
    monkeypatch.setattr("deployment.installed_with_service", lambda: True)
    monkeypatch.setattr(winapi, "current_sid", lambda: "S-1-5-18")
    monkeypatch.setattr(scm, "query", lambda name: {"pid": 77, "state": scm.RUNNING})
    monkeypatch.setattr(psutil, "Process", lambda: SimpleNamespace(ppid=lambda: 77))
    assert launcher.machine_tool([
        "app", "--machine-tool", "--owner-sid", SID, "--tool", "processes", "--service-install"]) == 2


def test_source_cannot_use_production_system_spawner(monkeypatch):
    monkeypatch.delattr(launcher.sys, "frozen", raising=False)
    with pytest.raises(PermissionError):
        launcher.Coordinator._spawn(caller(), ["--tool", "processes"])


def test_installer_explicitly_delegates_system_tools_and_warns_on_opt_out():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    line = next(line for line in text.splitlines() if 'Name: "privilegedlauncher"' in line)
    assert "unchecked" not in line and "SYSTEM" in line
    assert "--service-launcher-policy on" in text and "--service-launcher-policy off" in text
    assert "Вы делегируете пользователям" in text
    assert "Без launcher для полного доступа" in text
    ui = (ROOT / "ui" / "designer" / "settings_page.ui").read_text(encoding="utf-8")
    assert "chkPrivilegedLauncher" in ui and "lblLauncherWarning" in ui


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.mark.parametrize("failure", [None, "session", "environment", "process"])
def test_system_process_creation_uses_system_environment_and_closes_handles(monkeypatch, failure):
    from service import winapi
    calls = []
    @contextmanager
    def token(session):
        assert session == 2
        yield "interactive-token"
    monkeypatch.setattr(winapi, "session_token", token)
    monkeypatch.setattr(winapi, "token_sid", lambda value: SID)
    monkeypatch.setattr(winapi, "current_sid", lambda: "S-1-5-18")
    monkeypatch.setattr(winapi, "os_error", lambda *args, **kwargs: OSError("failure"))
    def opened(proc, access, out):
        out._obj.value = 10
        return True
    def duplicate(original, access, sa, level, kind, out):
        assert original.value == 10 and kind == 1 and level == 2
        out._obj.value = 20
        return True
    def session(primary, kind, value, size):
        assert primary.value == 20 and kind == 12 and value._obj.value == 2
        return failure != "session"
    def environment(out, primary, inherit):
        assert primary.value == 20 and not inherit
        if failure == "environment":
            return False
        out._obj.value = 30
        return True
    def create(primary, exe, command, sa, ta, inherit, flags, env, cwd, startup, info):
        assert primary.value == 20 and not inherit and env.value == 30
        assert flags == winapi.CREATE_UNICODE_ENVIRONMENT
        assert startup._obj.lpDesktop == "winsta0\\default"
        calls.append(("create", exe, command.value))
        if failure == "process":
            return False
        info._obj.hProcess, info._obj.hThread, info._obj.dwProcessId = 40, 50, 200
        return True
    api = SimpleNamespace(OpenProcessToken=Function(opened), DuplicateTokenEx=Function(duplicate),
                          SetTokenInformation=Function(session), CreateProcessAsUserW=Function(create))
    kernel = SimpleNamespace(GetCurrentProcess=lambda: -1,
                             CloseHandle=lambda handle: calls.append(
                                 ("close", handle.value if hasattr(handle, "value") else handle)))
    env_api = SimpleNamespace(CreateEnvironmentBlock=Function(environment),
                              DestroyEnvironmentBlock=Function(
                                  lambda env: calls.append(("destroy", env.value))))
    monkeypatch.setattr(winapi, "advapi", lambda: api)
    monkeypatch.setattr(winapi, "k32", lambda: kernel)
    monkeypatch.setattr(winapi.ctypes, "WinDLL", lambda *args, **kwargs: env_api)
    if failure:
        with pytest.raises(OSError):
            winapi.launch_system_in_session(2, r"C:\App\StretchBIT.exe", "--machine-tool", SID)
    else:
        assert winapi.launch_system_in_session(
            2, r"C:\App\StretchBIT.exe", "--machine-tool", SID) == 200
        assert ("close", 40) in calls and ("close", 50) in calls
    assert ("close", 10) in calls and ("close", 20) in calls
    assert (("destroy", 30) in calls) is (failure not in ("session", "environment"))


def test_changed_session_user_is_denied_before_system_token_is_duplicated(monkeypatch):
    from service import winapi
    @contextmanager
    def token(session):
        yield object()
    monkeypatch.setattr(winapi, "session_token", token)
    monkeypatch.setattr(winapi, "token_sid", lambda value: SID + "2")
    monkeypatch.setattr(winapi, "current_sid", lambda: "S-1-5-18")
    monkeypatch.setattr(winapi, "advapi", lambda: pytest.fail("must not duplicate a token"))
    with pytest.raises(PermissionError):
        winapi.launch_system_in_session(2, "app", "", SID)


def test_direct_user_cannot_obtain_system_launcher_token(monkeypatch):
    from service import winapi
    monkeypatch.setattr(winapi, "current_sid", lambda: SID)
    with pytest.raises(PermissionError):
        winapi.launch_system_in_session(2, "app", "", SID)


def test_settings_opt_out_warning_is_only_text_and_does_not_change_machine_policy():
    from ui.pages import SettingsPage
    saved, visible = [], []
    page = SimpleNamespace(_save=lambda *args: saved.append(args),
                           lbl_launcher_warning=SimpleNamespace(setVisible=visible.append))
    SettingsPage._on_launcher(page, False)
    assert saved == [("startup/privileged_launcher", False)] and visible == [True]


def test_tool_context_targets_users_hive_without_importing_their_configuration(monkeypatch):
    from service import winapi
    from recovery import registry
    import os
    import winreg
    import usercontext
    import userdata
    root = userdata.CONFIG_DIR
    calls = []
    @contextmanager
    def token(session):
        yield 99
    class Key:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def __int__(self):
            return 202
    monkeypatch.setattr(winapi, "session_token", token)
    monkeypatch.setattr(winapi, "token_sid", lambda token: SID)
    monkeypatch.setattr(usercontext, "known_folder", lambda folder, token: Path(r"C:\TargetUser") / folder)
    monkeypatch.setattr(winreg, "OpenKey",
                        lambda hive, path, *args: calls.append(("hive", hive, path)) or Key())
    api = SimpleNamespace(RegOverridePredefKey=Function(
        lambda hive, target: calls.append(("override", target)) or 0))
    monkeypatch.setattr(winapi, "advapi", lambda: api)
    monkeypatch.setenv("PATH", "system-safe-path")
    monkeypatch.setenv("APPDATA", "original-system-roaming")
    monkeypatch.setattr(registry, "TARGET_SID", None)
    with winapi.interactive_user_context(2, SID):
        assert os.environ["PATH"] == "system-safe-path"
        assert os.environ["APPDATA"].startswith(r"C:\TargetUser")
        assert registry.current_sid() == SID
        assert userdata.CONFIG_DIR == root
    assert os.environ["APPDATA"] == "original-system-roaming"
    assert registry.TARGET_SID is None
    assert calls == [("hive", winreg.HKEY_USERS, SID), ("override", 202), ("override", None)]
