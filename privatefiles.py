"""Закрытые локальные файлы: явная DACL и атомарная запись без открытого временного файла."""
import ctypes
import os
import stat
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


def _check_path(path: Path) -> None:
    # Не применять права и не писать через junction/symlink, в том числе в предках.
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OSError("Защищённое хранилище не допускает ссылки и точки повторной обработки")


def _sddl(directory: bool, administrators: bool, system_only: bool = False) -> str:
    from service.winapi import current_sid
    sid = current_sid()
    if not sid:
        raise OSError("Не удалось определить владельца защищённого хранилища")
    flags = "OICI" if directory else ""
    identities = ["SY", "BA"] if system_only else list(
        dict.fromkeys([sid, "SY"] + (["BA"] if administrators else [])))
    return "D:P" + "".join(f"(A;{flags};FA;;;{who})" for who in identities)


def _set_acl(path: Path, administrators: bool = False, system_only: bool = False) -> None:
    if sys.platform != "win32":
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    adv.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    adv.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _sddl(path.is_dir(), administrators, system_only), 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # Полностью заменить DACL, а не добавить разрешения к прежним широким ACE.
        if not adv.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def protect_directory(folder: Path, *, recursive: bool = False,
                      administrators: bool = False, system_only: bool = False) -> None:
    folder = Path(os.path.abspath(folder))
    _check_path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    _set_acl(folder, administrators, system_only)
    if recursive:
        for entry in folder.iterdir():
            _check_path(entry)
            if entry.is_dir():
                protect_directory(entry, recursive=True, administrators=administrators,
                                  system_only=system_only)
            else:
                _set_acl(entry, administrators, system_only)


def write_bytes(path: Path, data: bytes, *, administrators: bool = False) -> None:
    """До записи содержимого закрыть папку и новый файл; ошибка ACL отменяет запись."""
    path = Path(os.path.abspath(path))
    protect_directory(path.parent, recursive=True, administrators=administrators)
    _check_path(path)
    fd, name = tempfile.mkstemp(prefix=".sbit-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            _set_acl(temporary, administrators)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_text(path: Path, text: str, *, administrators: bool = False) -> None:
    write_bytes(path, text.encode("utf-8"), administrators=administrators)
