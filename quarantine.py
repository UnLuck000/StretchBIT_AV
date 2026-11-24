import json
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from scanner.hashing import sha256_of, load_signatures
from scanner.whitelist import add_to_whitelist
from scanner.signature import describe, inspect_signature
from diag.log import get as _log

log = _log("quarantine")

QUARANTINE_DIR = Path("quarantine_data").resolve()
SIGNATURES_FILE = Path("signatures/hashes.txt")

class NeedAdmin(PermissionError):
    """Папка карантина закрыта от записи (установленная программа, с 1.0.0), а программа
    запущена без прав администратора."""


NEED_ADMIN_TEXT = ("нужны права администратора: папка карантина закрыта от записи, а программа "
                   "запущена без них. Перезапустите её от имени администратора")


def _check_writable() -> None:
    QUARANTINE_DIR.mkdir(exist_ok=True)
    probe = QUARANTINE_DIR / f".probe-{uuid.uuid4().hex[:8]}"
    try:
        probe.write_bytes(b"")
        probe.unlink()
    except PermissionError:
        raise NeedAdmin(NEED_ADMIN_TEXT) from None


STATUS_QUARANTINED = "quarantined"
STATUS_RESTORED = "restored"
STATUS_DELETED = "deleted"


# Файл в карантине не должен оставаться рабочей программой: его нельзя запустить из папки
# карантина, и на него не срабатывают другие антивирусы. Содержимое — XOR с ключом по кругу
# (это не шифрование от человека, а обезвреживание). В метаданных — "encoding": "xor1";
# записи прежних версий без этого поля лежат как есть и восстанавливаются по-старому.
XOR_KEY = bytes.fromhex("5342495451a7c33e9d18f06b2c74e5b1")
ENCODING = "xor1"
_CHUNK = 1 << 20


def _xor_copy(src: Path, dst: Path) -> None:
    """Копия src в dst через XOR (операция обратима: тем же вызовом обратно)."""
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        _xor_stream(fin, fout)


def _file_key(f) -> tuple | None:
    """(том, индекс) файла по Windows HANDLE. На Windows сбой — ошибка, не пропуск."""
    if os.name != "nt":
        return None
    import ctypes
    import msvcrt
    from ctypes import wintypes
    class _Info(ctypes.Structure):  # BY_HANDLE_FILE_INFORMATION
        _fields_ = [("attr", wintypes.DWORD), ("created", wintypes.FILETIME),
                    ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    info = _Info()
    if not k.GetFileInformationByHandle(wintypes.HANDLE(msvcrt.get_osfhandle(f.fileno())),
                                         ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (info.volume, info.index_high, info.index_low)


def _same_file(path: Path, key: tuple | None) -> bool:
    """Путь всё ещё ведёт к тому же файлу, что читали (защита от подмены между шагами)."""
    if key is None:
        return False  # отсутствие идентичности не подтверждает совпадение
    try:
        with open(path, "rb") as f:
            return _file_key(f) == key
    except OSError:
        return False


def _xor_stream(fin, fout, digest=None, plain_in: bool = True) -> int:
    """XOR из открытого файла в открытый файл; размер. digest — SHA-256 исходного
    содержимого: plain_in — вход как есть (карантин), иначе выход (восстановление)."""
    table = [bytes(b ^ k for b in range(256)) for k in XOR_KEY]
    width = len(XOR_KEY)
    block = _CHUNK - _CHUNK % width  # кусок кратен ключу: его фаза не сбивается
    size = 0
    while True:
        chunk = fin.read(block)
        if not chunk:
            break
        out = bytearray(chunk)
        for i in range(width):
            out[i::width] = chunk[i::width].translate(table[i])
        if digest is not None:
            digest.update(chunk if plain_in else out)
        fout.write(out)
        size += len(chunk)
    return size


def _stored_sha256(meta: dict) -> str:
    """SHA-256 исходного содержимого файла, лежащего в карантине."""
    import hashlib
    stored = _stored_path(meta["id"])
    if meta.get("encoding") != ENCODING:
        return sha256_of(stored)
    digest = hashlib.sha256()
    table = [bytes(b ^ k for b in range(256)) for k in XOR_KEY]
    width = len(XOR_KEY)
    block = _CHUNK - _CHUNK % width
    with open(stored, "rb") as f:
        while True:
            chunk = f.read(block)
            if not chunk:
                break
            out = bytearray(chunk)
            for i in range(width):
                out[i::width] = chunk[i::width].translate(table[i])
            digest.update(out)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _meta_path(item_id: str) -> Path:
    if not item_id or not item_id.isascii() or not item_id.isalnum():
        raise ValueError("неверный идентификатор карантина")
    return QUARANTINE_DIR / f"{item_id}.json"


def _stored_path(item_id: str) -> Path:
    _meta_path(item_id)  # одинаковая проверка имени для данных и метаданных
    return QUARANTINE_DIR / f"{item_id}.quar"


def _read_meta(item_id: str) -> dict:
    meta = json.loads(_meta_path(item_id).read_text(encoding="utf-8"))
    # записи, созданные до появления статусов, считаем находящимися в карантине
    meta.setdefault("status", STATUS_QUARANTINED)
    return meta


def _write_meta(meta: dict) -> None:
    """Записывает метаданные через временный файл, чтобы JSON не повредился при сбое."""
    path = _meta_path(meta["id"])
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def add_hash_to_signatures(sha256: str) -> bool:
    """Дописывает хэш в hashes.txt. Возвращает False, если он там уже есть."""
    sha256 = sha256.strip().lower()
    SIGNATURES_FILE.parent.mkdir(parents=True, exist_ok=True)

    needs_newline = False
    if SIGNATURES_FILE.exists():
        if sha256 in load_signatures(SIGNATURES_FILE):
            return False
        content = SIGNATURES_FILE.read_bytes()
        needs_newline = bool(content) and not content.endswith(b"\n")

    with SIGNATURES_FILE.open("a", encoding="utf-8") as f:
        if needs_newline:  # последняя строка без переноса: не склеиваем хэши
            f.write("\n")
        f.write(sha256 + "\n")
    return True


# Интерфейс со службой (service/remote.py): карантин ведёт служба, вызовы идут по каналу.
# В самой службе и без неё — None, всё как раньше.
_remote = None


def set_remote(backend) -> None:
    global _remote
    _remote = backend


def quarantine_file(path: Path, reason: str, *, expected_sha256: str = "",
                    before_delete=None, verify=None) -> str:
    """Перемещает файл в карантин и возвращает его идентификатор. NeedAdmin — нет прав на
    папку карантина; PermissionError — файл занят."""
    if _remote is not None:
        if expected_sha256 or before_delete is not None or verify is not None:
            raise OSError("автокарантин выполняется только в движке защиты")
        return _remote.quarantine_file(path, reason)
    _check_writable()
    path = Path(path).resolve()
    try:
        signature_text = describe(inspect_signature(path))
    except Exception:  # подпись не должна мешать сохранению резервной копии
        signature_text = ""
    if os.name != "nt":
        # Без удаления по дескриптору не обещаем безопасное автодействие.
        raise OSError("безопасный карантин поддерживается только в Windows")
    import msvcrt
    from service import winapi
    # Без FILE_SHARE_WRITE/DELETE: нельзя менять или переименовать открытый объект.
    h = winapi.open_file(str(path), winapi.GENERIC_READ | winapi.DELETE,
                         winapi.FILE_SHARE_READ, winapi.OPEN_EXISTING)
    try:
        winapi.check_disk_file(h)
        original = winapi.final_path(h)
        if not original:
            raise OSError("не удалось определить путь открытого файла")
        windows = os.path.normcase(os.path.abspath(
            os.environ.get("SystemRoot", r"C:\Windows"))).rstrip("\\/") + os.sep
        if expected_sha256 and os.path.normcase(original).startswith(windows):
            raise OSError("автокарантин системного файла запрещён")
        fd = winapi.fd_from_handle(h, write=False)
    except BaseException:
        winapi.close(h)
        raise
    with os.fdopen(fd, "rb") as fin:
        return quarantine_stream(
            fin, original, reason, expected_sha256=expected_sha256, signature=signature_text,
            before_delete=before_delete, verify=verify,
            delete=lambda: winapi.delete_by_handle(msvcrt.get_osfhandle(fin.fileno())))


def quarantine_stream(fin, original_path: str, reason: str, delete=None, *,
                      sid: str = "", expected_sha256: str = "", before_delete=None,
                      signature: str = "", verify=None) -> str:
    """Карантин из уже открытого файла (служба: дескриптор открыл интерфейс со своими
    правами, путь от пользователя служба не открывает). delete() — удалить исходный файл
    через тот же дескриптор; ошибка удаления отменяет карантин."""
    import hashlib
    _check_writable()
    item_id = uuid.uuid4().hex
    stored = _stored_path(item_id)
    digest = hashlib.sha256()
    try:
        with open(stored, "wb") as fout:
            size = _xor_stream(fin, fout, digest)
        if expected_sha256 and digest.hexdigest() != expected_sha256:
            raise OSError("содержимое файла изменилось после проверки")
        if verify is not None and not verify(fin):
            raise OSError("повторная проверка открытого файла не подтвердила угрозу")
        meta = {
            "id": item_id,
            "status": STATUS_QUARANTINED,
            "original_path": str(original_path),
            "sha256": digest.hexdigest(),
            "size": size,
            "reason": reason,
            "signature": signature,
            "quarantined_at": _now(),
            "encoding": ENCODING,
            "sid": sid,
        }
        _write_meta(meta)
        if before_delete is not None:
            before_delete()
        if delete is not None:
            delete()
    except BaseException:
        stored.unlink(missing_ok=True)
        _meta_path(item_id).unlink(missing_ok=True)
        raise
    return item_id


def restore_stream(item_id: str, fout, dest: str = "", whitelist: bool = True) -> str:
    """Восстановление в уже открытый файл (служба: файл создал интерфейс со своими правами).
    Содержимое сверяется с хэшем до записи статуса. Возвращает путь назначения."""
    import hashlib
    meta = _read_meta(item_id)
    if meta["status"] != STATUS_QUARANTINED:
        raise ValueError("Этот элемент уже восстановлен или удалён")
    if _stored_sha256(meta) != meta["sha256"]:
        raise ValueError("Хэш изменился: файл в карантине повреждён")
    stored = _stored_path(item_id)
    digest = hashlib.sha256()
    with open(stored, "rb") as fin:
        if meta.get("encoding") == ENCODING:
            _xor_stream(fin, fout, digest, plain_in=False)
        else:
            for chunk in iter(lambda: fin.read(_CHUNK), b""):
                digest.update(chunk)
                fout.write(chunk)
    fout.flush()
    if digest.hexdigest() != meta["sha256"]:
        raise ValueError("Хэш изменился при восстановлении")
    stored.unlink(missing_ok=True)
    dest = dest or meta["original_path"]
    meta["status"] = STATUS_RESTORED
    meta["restored_at"] = _now()
    meta["restored_to"] = dest
    _write_meta(meta)
    if whitelist:
        add_to_whitelist(meta["sha256"], dest)
    return dest


def list_quarantine(include_history: bool = False) -> list[dict]:
    """По умолчанию возвращает только файлы, которые сейчас в карантине.
    С include_history=True добавляет восстановленные и удалённые записи.
    Одна повреждённая запись не роняет весь список: пропускается и журналируется."""
    if _remote is not None:
        return _remote.list_quarantine(include_history)
    if not QUARANTINE_DIR.exists():
        return []
    items = []
    for meta_file in QUARANTINE_DIR.glob("*.json"):
        try:
            meta = _read_meta(meta_file.stem)
            if include_history or meta["status"] == STATUS_QUARANTINED:
                items.append(meta)
        except Exception as e:  # noqa: BLE001 — битая запись не должна ломать весь журнал
            log.warning("Карантин: пропущена повреждённая запись %s: %s", meta_file.name, e)
    return sorted(items, key=lambda m: m.get("quarantined_at", ""))


def restore_file(item_id: str, overwrite: bool = False, whitelist: bool = True) -> Path:
    """Возвращает файл на исходное место. JSON остаётся со статусом «restored».
    По умолчанию хэш файла заносится в белый список."""
    if _remote is not None:
        return _remote.restore_file(item_id, overwrite, whitelist)
    meta = _read_meta(item_id)
    if meta["status"] != STATUS_QUARANTINED:
        raise ValueError("Этот элемент уже восстановлен или удалён")

    stored = _stored_path(item_id)
    if _stored_sha256(meta) != meta["sha256"]:
        raise ValueError("Хэш изменился: файл в карантине повреждён")

    dest = Path(meta["original_path"])
    if dest.exists() and not overwrite:
        raise FileExistsError(f"По пути {dest} уже есть файл")

    dest.parent.mkdir(parents=True, exist_ok=True)
    if meta.get("encoding") == ENCODING:
        tmp = dest.with_name(dest.name + ".sbit-restore")
        try:
            _xor_copy(stored, tmp)
            os.replace(tmp, dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        stored.unlink(missing_ok=True)
    else:
        shutil.move(str(stored), dest)

    meta["status"] = STATUS_RESTORED
    meta["restored_at"] = _now()
    _write_meta(meta)

    if whitelist:
        add_to_whitelist(meta["sha256"], str(dest))
    return dest


def delete_file(item_id: str) -> bool:
    """Удаляет файл, оставляет JSON со статусом «deleted» и заносит хэш в базу сигнатур.
    Возвращает True, если хэш был добавлен в hashes.txt (False, если уже был там)."""
    if _remote is not None:
        return _remote.delete_file(item_id)
    meta = _read_meta(item_id)
    if meta["status"] != STATUS_QUARANTINED:
        raise ValueError("Этот элемент уже восстановлен или удалён")

    added = add_hash_to_signatures(meta["sha256"])  # операция безопасна для повтора
    _stored_path(item_id).unlink(missing_ok=True)

    meta["status"] = STATUS_DELETED
    meta["deleted_at"] = _now()
    _write_meta(meta)
    return added
