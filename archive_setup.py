"""Первый запуск ZIP/RAR: проверенная копия, UAC, защищённый код и задача SYSTEM."""
import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import deployment
import privatefiles
import programfiles


def _closed_dir(path: Path) -> None:
    if path.exists():
        privatefiles._check_path(path)
        import winacl
        if winacl._problem(path, winacl.FOLDER_MASK, "служебной папки"):
            raise PermissionError("Существующая служебная папка не защищена")
    else:
        _closed_dir(path.parent)
        programfiles.mkdir(path)


def provision(source: Path) -> Path:
    """Только от повышенного helper; чужую установленную копию/неизвестные файлы не заменять."""
    import archive_runtime
    import winacl
    data = deployment.read_manifest(source)
    if deployment.installed_with_service(source):
        raise ValueError("Установленная через Installer копия не переносится как архив")
    if archive_runtime.conflicting_service():
        raise RuntimeError("Уже работает служба установленной копии. Нельзя включать две защиты параллельно")
    target = deployment.archive_target(data, source)
    if target.exists():
        privatefiles._check_path(target)
        if not winacl.admin_only(target / "StretchBIT.exe")[0] or deployment.installed_with_service(target) or \
                deployment.manifest_id(deployment.read_manifest(target)) != deployment.manifest_id(data):
            raise FileExistsError("В целевой папке уже есть другая копия. Её файлы не перезаписаны")
    else:
        privatefiles._check_path(target.parent)
        stage = target.with_name(target.name + ".setup-" + uuid.uuid4().hex)
        programfiles.mkdir(stage)
        files, folders = [], [stage]
        try:
            for name, digest in data["files"].items():
                relative = deployment.relative_file(name)
                path = stage / relative
                missing = []
                parent = path.parent
                while parent != stage and not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for directory in reversed(missing):
                    programfiles.mkdir(directory)
                    folders.append(directory)
                files.append(path)
                programfiles.copy_verified(source / relative, path, source, digest)
            manifest = stage / deployment.MANIFEST
            files.append(manifest)
            programfiles.write_new(manifest, json.dumps(
                data, ensure_ascii=False, sort_keys=True).encode("utf-8"))
            programfiles.publish_acl(stage)
            stage.rename(target)  # без замены существующей папки
        except BaseException:
            # Удаляются лишь созданные этим вызовом файлы, не всё дерево пользователя.
            for path in reversed(files):
                if path.exists():
                    privatefiles._check_path(path)
                    path.unlink()
            for directory in reversed(folders):
                try:
                    directory.rmdir()
                except OSError:
                    pass
            raise
    return finalize(target)


def finalize(target: Path) -> Path:
    """Настройка только уже защищённой копии, без повторного переноса."""
    import archive_runtime
    import trustseal
    import winacl
    privatefiles._check_path(target)
    if not target.is_relative_to(deployment.program_files()) or \
            not winacl.admin_only(target / "StretchBIT.exe")[0] or \
            deployment.installed_with_service(target):
        raise PermissionError("Завершать настройку можно только из защищённой архивной копии")
    if archive_runtime.conflicting_service():
        raise RuntimeError("Уже работает служба установленной копии. Нельзя включать две защиты параллельно")
    data = deployment.read_manifest(target)
    for name, expected in data["files"].items():
        path = target / deployment.relative_file(name)
        if not winacl.admin_only(path)[0]:
            raise PermissionError("Файлы архивной копии не защищены")
        with programfiles.locked_input(path, target) as (stream, _):
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError("Файлы архивной копии изменены")
    for name in ("cache", "logs", "reports", "quarantine_data"):
        directory = target / "app" / name
        if not directory.exists():
            programfiles.mkdir(directory)
        privatefiles.protect_directory(directory, recursive=True, system_only=True)
    trustseal.ensure_root()
    state = archive_runtime.data_dir(target)
    _closed_dir(state)
    owner_file = state / "archive-owner.json"
    expected_owner = {"root": str(target), "manifest": deployment.manifest_id(data)}
    if owner_file.exists():
        if json.loads(owner_file.read_text(encoding="utf-8")) != expected_owner:
            raise ValueError("Служебная папка относится к другой архивной копии")
    else:
        programfiles.write_new(owner_file, json.dumps(expected_owner).encode("utf-8"))
    config = state / "config.json"
    if not config.exists():
        programfiles.write_new(config, b'{"launcher_allowed": true, "enabled": false}')
    ready = target / deployment.READY_FILE
    created_ready = not ready.exists()
    if created_ready:
        programfiles.write_new(ready, json.dumps(
            {"format": 1, "manifest": deployment.manifest_id(data),
             "task": deployment.task_name(target)}).encode("utf-8"))
        programfiles.publish_acl(ready)
        # Ready не даёт прав; пользователь может прочитать адрес своей настроенной копии.
        # Сам код и запись по-прежнему принадлежат BA, не текущему user.
    try:
        archive_runtime.register_task(target, state)
    except OSError:
        if created_ready:
            ready.unlink(missing_ok=True)
        raise
    return target


def _message(text: str, flags: int = 0x30) -> int:
    import ctypes
    return ctypes.windll.user32.MessageBoxW(None, text, "StretchBIT: архивная копия", flags)


def elevated_main() -> int:
    from trustseal import is_admin
    if not getattr(sys, "frozen", False) or not is_admin():
        return 5
    try:
        finalize(deployment.package_root())
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        _message(f"Настройка архивной копии не завершена:\n{error}\n\nИсходные файлы сохранены.", 0x10)
        return 1


def _start_provisioner(source: Path, data: dict):
    """В UAC передаётся проверенный текст, не EXE/DLL или PS1 из исходной папки."""
    from service import elevate
    with programfiles.locked_input(source / deployment.MANIFEST, source) as (stream, _):
        raw = stream.read(deployment.MAX_MANIFEST + 1)
    if len(raw) > deployment.MAX_MANIFEST or json.loads(raw) != data:
        raise ValueError("Список файлов архива изменён")
    with programfiles.locked_input(source / "app" / "archive_stage.ps1", source) as (stream, _):
        script = stream.read(256 * 1024)
    if hashlib.sha256(script).hexdigest() != data["files"].get("app/archive_stage.ps1"):
        raise ValueError("Сценарий настройки архива изменён")
    text = script.decode("utf-8").replace(
        "__SOURCE_BASE64__", base64.b64encode(str(source).encode("utf-8")).decode("ascii")).replace(
        "__MANIFEST_SHA256__", hashlib.sha256(raw).hexdigest())
    encoded = base64.b64encode(text.encode("utf-16-le")).decode("ascii")
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    size = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    system = Path(buffer.value)
    executable = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    parameters = subprocess.list2cmdline(["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
    if len(str(executable)) + len(parameters) + 4 >= 32767:
        raise ValueError("Слишком длинная команда первичной настройки")
    info = elevate.SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = elevate.SEE_MASK_NOCLOSEPROCESS
    info.lpVerb, info.lpFile, info.lpParameters = "runas", str(executable), parameters
    info.lpDirectory, info.nShow = str(system), 0
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(elevate.SHELLEXECUTEINFOW)]
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == elevate.ERROR_CANCELLED:
            return None
        raise ctypes.WinError(error)
    return info.hProcess


def make_shortcut(source: Path, target: Path) -> None:
    """Создаётся исходным user, не UAC-администратором; неизвестные ярлыки не затираются."""
    import syscmd
    privatefiles._check_path(source)
    temporary = source / f".sbit-{uuid.uuid4().hex}.lnk"
    destination = source / "StretchBIT - Program Files.lnk"
    if destination.exists():
        destination = source / f"StretchBIT - {uuid.uuid4().hex[:8]}.lnk"
    script = ("$w=New-Object -ComObject WScript.Shell;"
              "$s=$w.CreateShortcut($env:SBIT_LINK);$s.TargetPath=$env:SBIT_TARGET;"
              "$s.WorkingDirectory=[IO.Path]::GetDirectoryName($env:SBIT_TARGET);$s.Save()")
    try:
        result = subprocess.run([*syscmd.PS_ARGS, script], capture_output=True,
                                env={**os.environ, "SBIT_LINK": str(temporary),
                                     "SBIT_TARGET": str(target / "StretchBIT.exe")},
                                creationflags=0x08000000)
        if result.returncode or not temporary.is_file():
            raise OSError("Не удалось создать ярлык; исходная программа не удалена")
        temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)


def ensure(argv: list[str]) -> int | None:
    """Исходный пользователь остаётся жив и сам запускает GUI после завершения UAC-helper."""
    if not getattr(sys, "frozen", False) or deployment.installed_with_service():
        return None
    source = deployment.package_root()
    import winacl
    if deployment.ready(source) and source.is_relative_to(deployment.program_files()) and \
            winacl.admin_only(sys.executable)[0]:
        return None
    from trustseal import is_admin
    if is_admin():
        _message("Откройте архивную программу обычным запуском, не от имени администратора. "
                 "Она сама запросит UAC только для настройки, сохранив GUI у исходного пользователя.")
        return 1
    try:
        data = deployment.read_manifest(source)
        target = deployment.archive_target(data, source)
        configured = deployment.ready(target) and winacl.admin_only(target / "StretchBIT.exe")[0] and \
            deployment.manifest_id(deployment.read_manifest(target)) == deployment.manifest_id(data)
        if not configured:
            if _message(f"Архивную копию нужно разместить в защищённой папке:\n{target}\n\n"
                        "Будет создана задача launcher от SYSTEM. Она даёт пользователям "
                        "широкий доступ к известным системным инструментам без повторного UAC. "
                        "GUI, настройки и VPN-профили останутся у пользователя.\n\n"
                        "В исходной папке останется ярлык; посторонние файлы не удаляются.\n"
                        "Для настройки потребуется подтверждение администратора. Продолжить?",
                        0x34) != 6:
                return None
            from service import elevate, winapi
            handle = _start_provisioner(source, data)
            if handle is None:
                return None
            try:
                winapi.k32().WaitForSingleObject(handle, 0xFFFFFFFF)
                code = elevate.exit_code(handle)  # закрывает завершённый дескриптор
                handle = None
            finally:
                if handle:
                    winapi.close(handle)
            if code != 0 or not deployment.ready(target):
                return 1
        make_shortcut(source, target)
        subprocess.Popen([str(target / "StretchBIT.exe"), "--archive-resume", str(source),
                          str(os.getpid()), "--", *argv[1:]], close_fds=True)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        _message(f"Архивная копия не настроена:\n{error}\n\nИсходные файлы не удалены.", 0x10)
        return 1


def cleanup_source(source: Path, target: Path) -> None:
    """Только от user, только совпадающие файлы пакета, после выхода прежнего EXE."""
    from trustseal import is_admin
    if is_admin() or source == target or source.is_relative_to(deployment.program_files()) or \
            source.is_relative_to(target) or target.is_relative_to(source):
        return
    privatefiles._check_path(source)
    original = deployment.read_manifest(source)
    current = deployment.read_manifest(target)
    if deployment.manifest_id(original) != deployment.manifest_id(current):
        raise ValueError("Список исходных файлов изменён; очистка отменена")
    from service import winapi
    for name, expected in original["files"].items():
        path = source / deployment.relative_file(name)
        try:
            with programfiles.locked_input(path, source, deleting=True) as (stream, handle):
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest == expected:
                    if handle is None:
                        path.unlink()
                    else:
                        winapi.delete_by_handle(handle)
        except OSError:
            continue  # занятые/изменённые файлы сохраняются
    # Метаданные пакета и неизвестные/пользовательские файлы оставляем вместе с ярлыком.
    directories = {path.parent for name in original["files"]
                   for path in [source / deployment.relative_file(name)]}
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        if directory != source:
            try:
                privatefiles._check_path(directory)
                directory.rmdir()
            except OSError:
                pass


def resume(argv: list[str]) -> int | None:
    from trustseal import is_admin
    if is_admin():
        return 5
    try:
        index = argv.index("--archive-resume")
        source = Path(argv[index + 1]).absolute()
        pid = int(argv[index + 2])
        if argv[index + 3] != "--" or not deployment.ready():
            return 2
        remaining = argv[index + 4:]
        from service import winapi, client
        # Ждём старый EXE, но не завершаем ни его, ни какие-либо сторонние процессы.
        if winapi.process_image(pid).casefold() == str(source / "StretchBIT.exe").casefold():
            handle = winapi.k32().OpenProcess(0x100000, False, pid)
            if handle:
                try:
                    winapi.k32().WaitForSingleObject(handle, 15_000)
                finally:
                    winapi.close(handle)
        import time
        deadline = time.monotonic() + 15
        ready = False
        while time.monotonic() < deadline:
            connection = client.connect()
            if connection is not None:
                connection.close()
                ready = True
                break
            time.sleep(0.2)
        if ready:
            cleanup_source(source, deployment.package_root())
        _message(f"Программа размещена в:\n{deployment.package_root()}\n\n"
                 "Это защищает код launcher от подмены перед запуском с правами SYSTEM. "
                 "Личная конфигурация и VPN-профили остаются в AppData пользователя."
                 + ("" if ready else "\n\nЗадача пока не отвечает. Исходные файлы сохранены."))
        argv[:] = [argv[0], *remaining]
        return None
    except (OSError, ValueError, IndexError) as error:
        _message(f"Перенос завершён не полностью: {error}. Исходные файлы сохранены.", 0x10)
        return 1
