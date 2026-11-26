"""Архивная поставка: только временные каталоги, без UAC, Program Files и настоящих задач."""
import base64
import ctypes
import hashlib
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import archive_runtime
import archive_setup
import build_release
import deployment
import programfiles


def package(folder, edition="release"):
    (folder / "app").mkdir(parents=True)
    contents = {"StretchBIT.exe": b"not-an-executable", "app/library.dll": b"fake-library",
                "app/install-mode.json": b'{"installed_with_service": false}',
                "app/edition.txt": edition.encode("ascii")}
    for name, data in contents.items():
        (folder / name).write_bytes(data)
    manifest = {"format": 1, "edition": edition, "version": "test",
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}}
    (folder / deployment.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    source = tmp_path / "Downloads" / "StretchBIT"
    data = package(source)
    pf = tmp_path / "Program Files"
    pf.mkdir()
    state = tmp_path / "ProgramData"
    state.mkdir()
    monkeypatch.setattr(deployment, "program_files", lambda: pf)
    monkeypatch.setattr(deployment, "package_root", lambda: source)
    monkeypatch.setattr("trustseal.protected_dir", lambda: state)
    monkeypatch.setattr("trustseal.ensure_root", lambda: state)
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    monkeypatch.setattr("winacl._problem", lambda *args: "")
    monkeypatch.setattr("winacl.admin_only", lambda *args: (True, ""))
    monkeypatch.setattr("privatefiles.protect_directory", lambda *args, **kwargs: None)
    monkeypatch.setattr(programfiles, "mkdir", lambda path: path.mkdir())
    monkeypatch.setattr(programfiles, "publish_acl", lambda path: None)
    @contextmanager
    def output(path):
        with path.open("xb") as stream:
            yield stream
    monkeypatch.setattr(programfiles, "output", output)
    monkeypatch.setattr(archive_runtime, "conflicting_service", lambda: False)
    registered = []
    monkeypatch.setattr(archive_runtime, "register_task",
                        lambda root, state: registered.append((root, state)))
    return SimpleNamespace(source=source, data=data, pf=pf, state=state, registered=registered)


def test_mode_defaults_false_and_true_is_not_a_truthy_string(tmp_path):
    assert not deployment.installed_with_service(tmp_path)
    (tmp_path / "app").mkdir()
    mode = tmp_path / "app" / deployment.MODE_FILE
    for value in (False, "true", 1, None):
        mode.write_text(json.dumps({"installed_with_service": value}), encoding="utf-8")
        assert not deployment.installed_with_service(tmp_path)
    mode.write_text('{"installed_with_service": true}', encoding="utf-8")
    assert deployment.installed_with_service(tmp_path)


@pytest.mark.parametrize("path", ["../secret", "/absolute", r"app\..\secret", "C:/Windows/file",
                                  "app/a:stream", "app//file", "app/./file", "app/nul.txt",
                                  "app/file.", "app/file ", "app/a?b"])
def test_manifest_cannot_target_outside_program_or_windows_devices(path):
    with pytest.raises(ValueError):
        deployment.relative_file(path)


def test_relocation_verifies_copy_keeps_source_and_unknown_files(sandbox):
    extra = sandbox.source / "important-user-document.txt"
    extra.write_text("keep", encoding="utf-8")
    target = archive_setup.provision(sandbox.source)
    assert target.parent == sandbox.pf
    assert deployment.ready(target)
    assert not deployment.installed_with_service(target)
    assert (target / "StretchBIT.exe").read_bytes() == b"not-an-executable"
    assert (sandbox.source / "StretchBIT.exe").exists()  # ещё исполняющийся оригинал не удалялся
    assert extra.read_text(encoding="utf-8") == "keep"
    assert not (target / extra.name).exists()
    assert sandbox.registered[0][0] == target
    config = json.loads((sandbox.registered[0][1] / "config.json").read_text(encoding="utf-8"))
    assert config["launcher_allowed"] is True
    assert not (sandbox.source / "settings.ini").exists()


def test_modified_package_never_registers_system_task(sandbox):
    (sandbox.source / "app" / "library.dll").write_bytes(b"modified")
    with pytest.raises(ValueError, match="изменён"):
        archive_setup.provision(sandbox.source)
    assert not sandbox.registered
    assert not deployment.archive_target(sandbox.data, sandbox.source).exists()
    assert (sandbox.source / "StretchBIT.exe").exists()


def test_unknown_destination_is_never_overwritten(sandbox):
    target = deployment.archive_target(sandbox.data, sandbox.source)
    target.mkdir()
    keep = target / "unknown.txt"
    keep.write_bytes(b"keep")
    with pytest.raises((OSError, ValueError)):
        archive_setup.provision(sandbox.source)
    assert keep.read_bytes() == b"keep" and not sandbox.registered


def test_existing_service_conflict_does_not_move_or_stop_anything(sandbox, monkeypatch):
    monkeypatch.setattr(archive_runtime, "conflicting_service", lambda: True)
    with pytest.raises(RuntimeError, match="две защиты"):
        archive_setup.provision(sandbox.source)
    assert not sandbox.registered and list(sandbox.pf.iterdir()) == []


def test_failed_task_registration_leaves_no_ready_flag_and_can_retry(sandbox, monkeypatch):
    def fail(*args):
        raise OSError("scheduler")
    monkeypatch.setattr(archive_runtime, "register_task", fail)
    with pytest.raises(OSError):
        archive_setup.provision(sandbox.source)
    target = deployment.archive_target(sandbox.data, sandbox.source)
    assert target.exists() and not deployment.ready(target)
    monkeypatch.setattr(archive_runtime, "register_task", lambda *args: None)
    assert archive_setup.provision(sandbox.source) == target and deployment.ready(target)


def test_cleanup_removes_only_unchanged_manifest_files(sandbox):
    target = archive_setup.provision(sandbox.source)
    changed = sandbox.source / "app" / "library.dll"
    changed.write_bytes(b"changed-by-user")
    unknown = sandbox.source / "notes.txt"
    unknown.write_bytes(b"keep")
    shortcut = sandbox.source / "StretchBIT - Program Files.lnk"
    shortcut.write_bytes(b"fake-shortcut")
    archive_setup.cleanup_source(sandbox.source, target)
    assert not (sandbox.source / "StretchBIT.exe").exists()
    assert changed.read_bytes() == b"changed-by-user"
    assert unknown.read_bytes() == b"keep" and shortcut.exists()
    assert (target / "StretchBIT.exe").exists()


def test_cleanup_is_never_run_as_administrator(sandbox, monkeypatch):
    target = archive_setup.provision(sandbox.source)
    monkeypatch.setattr("trustseal.is_admin", lambda: True)
    archive_setup.cleanup_source(sandbox.source, target)
    assert (sandbox.source / "StretchBIT.exe").exists()


def test_hardlinks_are_rejected_before_any_system_task(sandbox):
    link = sandbox.source / "another-library.dll"
    link.hardlink_to(sandbox.source / "app" / "library.dll")
    with pytest.raises(OSError):
        archive_setup.provision(sandbox.source)
    assert not sandbox.registered


def test_task_is_system_not_highest_available_user(sandbox):
    target = deployment.archive_target(sandbox.data, sandbox.source)
    xml = archive_runtime.task_xml(target)
    assert archive_runtime.task_matches(xml, target)
    assert not archive_runtime.task_matches(xml.replace("S-1-5-18", "user"), target)
    assert not archive_runtime.task_matches(xml.replace("--archive-host", "--service"), target)
    assert "O:BAG:BAD:P" in xml and "<BootTrigger>" in xml
    assert "<LogonType>ServiceAccount</LogonType>" in xml
    assert "IgnoreNew" in xml


def test_archive_host_requires_system_and_prepared_copy(monkeypatch):
    monkeypatch.setattr("service.winapi.current_sid", lambda: "S-1-5-21-1")
    assert archive_runtime.main(["app", "--archive-host"]) == 5


def test_archive_pipe_cannot_be_impersonated_by_user_process(monkeypatch):
    from service import client, winapi
    closed = []
    kernel = SimpleNamespace(CreateFileW=lambda *args: 123, SetNamedPipeHandleState=lambda *args: True)
    monkeypatch.setattr(winapi, "k32", lambda: kernel)
    monkeypatch.setattr(winapi, "server_pid", lambda handle: 200)
    monkeypatch.setattr(winapi, "handle_owner_sid", lambda handle: "S-1-5-21-1")
    monkeypatch.setattr(winapi, "close", closed.append)
    connection = client.ServiceClient(r"\\.\pipe\sbit-archive-test", verify_server=lambda pid: True)
    with pytest.raises(client.ServiceUnavailable, match="SYSTEM"):
        connection._open()
    assert closed == [123]


def test_ready_metadata_alone_does_not_allow_system_client_connection(sandbox, monkeypatch):
    from service import client, winapi
    monkeypatch.setattr(client.sys, "frozen", True, raising=False)
    monkeypatch.setattr(winapi, "available", lambda: True)
    assert client.connect() is None


def test_cancelled_uac_does_not_move_files_or_launch_admin_gui(sandbox, monkeypatch):
    monkeypatch.setattr(archive_setup.sys, "frozen", True, raising=False)
    monkeypatch.setattr(archive_setup, "_message", lambda *args: 6)
    monkeypatch.setattr(archive_setup, "_start_provisioner", lambda *args: None)
    assert archive_setup.ensure(["app"]) is None
    assert list(sandbox.pf.iterdir()) == [] and (sandbox.source / "StretchBIT.exe").exists()


def test_archive_metadata_is_not_created_in_installer_source(tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "docs").mkdir(parents=True)
    for name in ("EULA.txt", "PRIVACY.txt"):
        (root / "docs" / name).write_text("legal", encoding="utf-8")
    (root / "LICENSE").write_text("MIT", encoding="utf-8")
    folder = root / "dist" / "StretchBIT"
    package(folder)
    monkeypatch.setattr(build_release, "ROOT", root)
    build_release.prepare_archive(folder)
    assert not deployment.installed_with_service(folder)
    assert deployment.read_manifest(folder)["files"]["StretchBIT.exe"]


def test_rar_is_real_external_rar_not_renamed_zip(tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "docs").mkdir(parents=True)
    for name in ("EULA.txt", "PRIVACY.txt"):
        (root / "docs" / name).write_text("legal", encoding="utf-8")
    (root / "LICENSE").write_text("MIT", encoding="utf-8")
    folder = root / "dist" / "StretchBIT"
    package(folder)
    monkeypatch.setattr(build_release, "ROOT", root)
    monkeypatch.setattr(build_release, "find_rar", lambda: tmp_path / "Rar.exe")
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        Path(args[-2]).write_bytes(b"RAR-test")
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr(build_release.subprocess, "run", run)
    result = build_release.make_rar(folder)
    assert result.suffix == ".rar" and result.read_bytes() == b"RAR-test"
    assert "-ma5" in calls[0][0] and "-r" in calls[0][0]
    assert calls[0][1]["cwd"] == folder.parent


def test_missing_rar_has_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(build_release, "find_rar", lambda: None)
    with pytest.raises(SystemExit, match="Rar.exe"):
        build_release.make_rar(tmp_path)


def stage_package(sandbox):
    script = Path(archive_setup.__file__).with_name("archive_stage.ps1").read_bytes()
    (sandbox.source / "app" / "archive_stage.ps1").write_bytes(script)
    sandbox.data["files"]["app/archive_stage.ps1"] = hashlib.sha256(script).hexdigest()
    (sandbox.source / deployment.MANIFEST).write_text(json.dumps(sandbox.data), encoding="utf-8")


def test_staging_integrity_is_checked_before_any_uac(sandbox, monkeypatch):
    stage_package(sandbox)
    (sandbox.source / "app" / "archive_stage.ps1").write_bytes(b"untrusted")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: pytest.fail("UAC before integrity check"))
    with pytest.raises(ValueError, match="Сценарий"):
        archive_setup._start_provisioner(sandbox.source, sandbox.data)


def test_manifest_is_pinned_before_staging(sandbox):
    stage_package(sandbox)
    (sandbox.source / deployment.MANIFEST).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Список"):
        archive_setup._start_provisioner(sandbox.source, sandbox.data)


def test_staging_uses_system_powershell_encoded_text_and_safe_cwd(sandbox, monkeypatch):
    from service import elevate
    stage_package(sandbox)
    captured = []
    def directory(buffer, size):
        buffer.value = r"C:\Windows\System32"
        return len(buffer.value)
    def launch(pointer):
        info = ctypes.cast(pointer, ctypes.POINTER(elevate.SHELLEXECUTEINFOW)).contents
        captured.append((info.lpFile, info.lpDirectory, info.lpParameters, info.lpVerb))
        info.hProcess = 123
        return True
    class Function:
        def __init__(self, callback):
            self.callback = callback
        def __call__(self, *args):
            return self.callback(*args)
    kernel = SimpleNamespace(GetSystemDirectoryW=Function(directory))
    shell = SimpleNamespace(ShellExecuteExW=Function(launch))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **kwargs: kernel if name == "kernel32" else shell)
    monkeypatch.setattr(elevate, "start", lambda *args: pytest.fail("Source EXE elevation is forbidden"))
    assert archive_setup._start_provisioner(sandbox.source, sandbox.data) == 123
    executable, cwd, parameters, verb = captured[0]
    assert executable == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert cwd == r"C:\Windows\System32" and verb == "runas"
    text = base64.b64decode(parameters.split()[-1]).decode("utf-16-le")
    assert "__SOURCE_BASE64__" not in text and "__MANIFEST_SHA256__" not in text
    assert hashlib.sha256((sandbox.source / deployment.MANIFEST).read_bytes()).hexdigest() in text
    assert len(executable) + len(parameters) + 4 < 32767
    assert "--archive-finalize" in text


def test_finalization_never_relocates_or_accepts_user_writable_code(sandbox, monkeypatch):
    monkeypatch.setattr(archive_setup, "provision", lambda *args: pytest.fail("Unexpected relocation"))
    with pytest.raises(PermissionError):
        archive_setup.finalize(sandbox.source)
    target = sandbox.pf / "protected"
    package(target)
    monkeypatch.setattr("winacl.admin_only", lambda *args: (False, "writable"))
    with pytest.raises(PermissionError):
        archive_setup.finalize(target)
    assert not sandbox.registered


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell / WinAPI")
def test_stager_native_reader_without_elevation(tmp_path):
    """Исполняется только префикс чтения: без копирования, UAC, задач и сообщений."""
    import syscmd
    script = Path(archive_setup.__file__).with_name("archive_stage.ps1").read_text(encoding="utf-8")
    prefix = script.split("  $input=OpenSource 'archive-files.json'", 1)[0]
    data = b"read-only native staging probe"
    (tmp_path / "probe.bin").write_bytes(data)
    prefix = prefix.replace("__SOURCE_BASE64__", base64.b64encode(
        str(tmp_path).encode("utf-8")).decode("ascii"))
    probe = prefix + """
      $s=OpenSource 'probe.bin'
      try { Write-Output (Digest $s) } finally {$s.Dispose()}
    } catch { Write-Error $_; exit 1 }
    """
    encoded = base64.b64encode(probe.encode("utf-16-le")).decode("ascii")
    result = subprocess.run([syscmd.POWERSHELL, "-NoProfile", "-NonInteractive",
                             "-EncodedCommand", encoded], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.decode().strip() == hashlib.sha256(data).hexdigest()


def test_stager_is_packaged_and_old_source_helper_is_disabled():
    root = Path(archive_setup.__file__).parent
    assert '(str(ROOT / "archive_stage.ps1"), ".")' in (root / "StretchBIT.spec").read_text(encoding="utf-8")
    import bootstrap
    assert bootstrap.dispatch(["app", "--archive-setup"]) == 5


def test_unprepared_archive_cannot_bypass_staging_with_tool_uac(sandbox, monkeypatch):
    from service import elevate
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: pytest.fail("Source EXE elevation"))
    with pytest.raises(PermissionError, match="защищённую копию"):
        elevate.start(["--tool", "processes"])
