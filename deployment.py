"""Способ поставки — метаданные, а не разрешение на повышение прав."""
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

MODE_FILE = "install-mode.json"
MANIFEST = "archive-files.json"
READY_FILE = "archive-ready.json"
MAX_MANIFEST = 16 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def package_root() -> Path:
    return Path(os.path.abspath(sys.executable)).parent


def installed_with_service(root: Path | None = None) -> bool:
    if root is None and not getattr(sys, "frozen", False):
        return False
    root = root or package_root()
    path = root / "app" / MODE_FILE
    try:
        if path.stat().st_size > 4096:
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        return isinstance(data, dict) and data.get("installed_with_service") is True
    except (OSError, ValueError):
        return False


def relative_file(name: str) -> Path:
    if not isinstance(name, str) or any(char in name for char in '\\:\0<>"|?*'):
        raise ValueError("Неверное имя файла поставки")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("Путь поставки должен быть относительным")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if any(part.endswith((".", " ")) or part.split(".", 1)[0].casefold() in reserved for part in path.parts):
        raise ValueError("Специальные имена Windows запрещены")
    return Path(*path.parts)


def read_manifest(root: Path) -> dict:
    path = root / MANIFEST
    if path.stat().st_size > MAX_MANIFEST:
        raise ValueError("Слишком большой список файлов архива")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != 1 or \
            data.get("edition") not in ("release", "test") or not isinstance(data.get("files"), dict):
        raise ValueError("Неверные метаданные архивной сборки")
    if not 1 <= len(data["files"]) <= 100_000:
        raise ValueError("Неверное число файлов архива")
    seen = set()
    for name, digest in data["files"].items():
        relative_file(name)
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError("Неверный SHA-256 файла поставки")
        key = name.casefold()
        if key in seen or key in (MANIFEST.casefold(), READY_FILE.casefold()):
            raise ValueError("Повторное или служебное имя файла поставки")
        seen.add(key)
    if "StretchBIT.exe" not in data["files"] or f"app/{MODE_FILE}" not in data["files"]:
        raise ValueError("В архиве нет программы или метки поставки")
    return data


def manifest_id(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def program_files() -> Path:
    from usercontext import known_folder
    return known_folder("6D809377-6AF0-444B-8957-A3773F02200E")


def archive_target(data: dict, source: Path | None = None) -> Path:
    suffix = "-test" if data["edition"] == "test" else ""
    pf = program_files()
    target = pf / f"StretchBIT-archive{suffix}"
    source = source or package_root()
    if source.is_relative_to(pf) and ready(source):
        return source
    if os.path.normcase(os.path.abspath(source)) == os.path.normcase(os.path.abspath(target)):
        return target.with_name(target.name + "-protected")
    return target


def root_id(root: Path | None = None) -> str:
    root = root or package_root()
    return hashlib.sha256(os.path.normcase(os.path.abspath(root)).encode("utf-8")).hexdigest()[:16]


def task_name(root: Path | None = None) -> str:
    return "StretchBIT-Archive-" + root_id(root)


def pipe_name(root: Path | None = None) -> str:
    return r"\\.\pipe\sbit-archive-" + root_id(root)


def ready(root: Path | None = None) -> bool:
    """Ready лишь выбирает режим: реальный запуск дополнительно проверяет ACL и SYSTEM."""
    root = root or package_root()
    try:
        path = root / READY_FILE
        if path.stat().st_size > 4096:
            return False
        value = json.loads(path.read_text(encoding="utf-8"))
        return value == {"format": 1, "manifest": manifest_id(read_manifest(root)),
                         "task": task_name(root)}
    except (OSError, ValueError):
        return False
