"""Безопасное создание новой программной копии: владелец BA задаётся при создании."""
import ctypes
import hashlib
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from ctypes import wintypes

import privatefiles


@contextmanager
def _security(readable: bool = False):
    from service import winapi
    # BA как владелец: split-token пользователя-администратора не должен владеть кодом.
    sddl = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if readable:
        sddl += "(A;OICI;0x1200a9;;;BU)"
    sa, descriptor = winapi.security_attributes(sddl)
    try:
        yield sa, descriptor
    finally:
        winapi.k32().LocalFree(descriptor)


def mkdir(path: Path) -> None:
    """Только новый каталог; существующий не переписывать и не переназначать его права."""
    privatefiles._check_path(path)
    if sys.platform != "win32":
        path.mkdir(mode=0o700)
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    with _security() as (sa, _descriptor):
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(sa)):
            raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def output(path: Path):
    """CREATE_NEW, без разделения дескриптора и без окна с владельцем обычного user."""
    privatefiles._check_path(path)
    if sys.platform != "win32":
        with path.open("xb") as stream:
            yield stream
        return
    from service import winapi
    with _security() as (sa, _descriptor):
        handle = winapi.k32().CreateFileW(str(path), winapi.GENERIC_WRITE, 0,
                                         ctypes.byref(sa), winapi.CREATE_NEW, 0x80, None)
    if not handle or handle == winapi.INVALID_HANDLE:
        raise winapi.os_error(text="новый файл программы не создан")
    try:
        fd = winapi.fd_from_handle(handle, True)
    except BaseException:
        winapi.close(handle)
        raise
    with os.fdopen(fd, "wb") as stream:
        yield stream
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def locked_input(path: Path, root: Path, *, deleting: bool = False):
    """Файл на месте, без reparse/hardlinks, заблокированный от подмены до конца операции."""
    privatefiles._check_path(path)
    if sys.platform != "win32":
        if path.stat().st_nlink != 1:
            raise OSError("Жёсткие ссылки в поставке запрещены")
        with path.open("rb") as stream:
            yield stream, None
        return
    from service import winapi
    access = winapi.GENERIC_READ | (winapi.DELETE if deleting else 0)
    handle = winapi.k32().CreateFileW(str(path), access, winapi.FILE_SHARE_READ, None,
                                     winapi.OPEN_EXISTING, 0x00200080, None)
    if not handle or handle == winapi.INVALID_HANDLE:
        raise winapi.os_error(text="файл поставки не открыт")
    try:
        winapi.check_disk_file(handle)
        info = winapi.BY_HANDLE_FILE_INFORMATION()
        if not winapi.k32().GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise winapi.os_error()
        final = Path(winapi.final_path(handle))
        if info.dwFileAttributes & 0x400 or info.nNumberOfLinks != 1 or not final.is_absolute() or \
                not Path(os.path.normcase(str(final))).is_relative_to(
                    Path(os.path.normcase(os.path.abspath(root)))):
            raise OSError("Файл поставки ведёт за пределы пакета или является ссылкой")
        # CRT-дескриптор получает копию handle, оригинал остаётся для delete_by_handle.
        duplicate = wintypes.HANDLE()
        k = winapi.k32()
        if not k.DuplicateHandle(k.GetCurrentProcess(), handle, k.GetCurrentProcess(),
                                 ctypes.byref(duplicate), 0, False, winapi.DUPLICATE_SAME_ACCESS):
            raise winapi.os_error()
        try:
            fd = winapi.fd_from_handle(duplicate.value, False)
        except BaseException:
            winapi.close(duplicate.value)
            raise
        with os.fdopen(fd, "rb") as stream:
            yield stream, handle
    finally:
        winapi.close(handle)


def copy_verified(source: Path, target: Path, root: Path, expected: str) -> None:
    digest = hashlib.sha256()
    with locked_input(source, root) as (stream, _handle), output(target) as out:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            out.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError(f"Файл архива изменён: {source.name}")


def write_new(path: Path, data: bytes) -> None:
    with output(path) as stream:
        stream.write(data)


def publish_acl(root: Path) -> None:
    """После проверки содержимого разрешить обычным пользователям только чтение/запуск."""
    if sys.platform != "win32":
        return
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    with _security(True) as (_sa, descriptor):
        for path in [root, *root.rglob("*")]:
            privatefiles._check_path(path)
            if not adv.SetFileSecurityW(str(path), 0x80000005, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
