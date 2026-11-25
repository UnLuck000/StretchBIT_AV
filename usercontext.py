"""Личные каталоги текущего токена Windows, не администратора установки и не ENV."""
import ctypes
import sys
import uuid
from ctypes import wintypes
from pathlib import Path

ROAMING = "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D"
LOCAL = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091"


def known_folder(folder_id: str) -> Path:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32")
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                          wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole.CoTaskMemFree.restype = None
    guid = ctypes.create_string_buffer(uuid.UUID(folder_id).bytes_le)
    result = ctypes.c_void_p()
    # Не создавать папку и не требовать её наличия (например, Roaming у LocalSystem).
    code = shell.SHGetKnownFolderPath(guid, 0x4000, None, ctypes.byref(result))
    if code < 0:
        raise OSError(f"Не удалось получить каталог текущего пользователя: HRESULT 0x{code & 0xffffffff:08x}")
    try:
        if not result.value:
            raise OSError("Windows не вернула каталог пользователя")
        value = ctypes.wstring_at(result)
        if not value:
            raise OSError("Windows вернула пустой каталог пользователя")
        return Path(value)
    finally:
        ole.CoTaskMemFree(result)


def roaming_dir() -> Path:
    if sys.platform == "win32":
        return known_folder(ROAMING)
    return Path.home() / ".config"


def local_dir() -> Path:
    if sys.platform == "win32":
        return known_folder(LOCAL)
    return Path.home() / ".local" / "share"
