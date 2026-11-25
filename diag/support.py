"""Безопасные технические сводки и заглушка отправки.

Нет HTTP-клиента, URL, очереди и фоновой отправки. Сырые журналы никогда не
передаются этому интерфейсу: только фиксированная схема без свободного текста.
"""
import json
import logging
import platform
import re
import time
import zipfile
from pathlib import Path

import appinfo
import datadirs

SENDING_AVAILABLE = False  # включение требует реализации транспорта и новой EULA
MAX_BYTES = 2 * 2**20
MAX_RECORDS = 5000
FILES = {"essential": "important.jsonl", "extra": "technical.jsonl", "vpn": "vpn-events.jsonl"}
COMPONENTS = {"app", "crash", "service", "proc", "scanner", "vpn", "network", "updater", "qt"}
LEVELS = {10: "DEBUG", 20: "INFO", 30: "WARNING", 40: "ERROR", 50: "CRITICAL"}
ERRORS = {"OSError", "ValueError", "TypeError", "RuntimeError", "PermissionError",
          "FileNotFoundError", "TimeoutError", "MemoryError", "KeyError", "IndexError"}
EXTRA_DETAILS = (
    "Версия и издание StretchBIT, версия/разрядность Windows. Дополнительные технические "
    "события программы: время, раздел, уровень, тип и числовой код ошибки (если известны), "
    "известные SHA-256 файлов. Включаются также обычные события, не только ошибки.\n\n"
    "Не передаются сырые строки app.log, тексты команд, содержимое файлов, имена и пути, "
    "имя пользователя/компьютера, IP/MAC, URL, ключи, снимки и комментарии. "
    "VPN-диагностика не включается без отдельного согласия.\n\n"
    "Сейчас отправка не подключена; никаких сетевых запросов или очереди нет.")
VPN_DETAILS = (
    "Версия и издание StretchBIT, версия/разрядность Windows. Отдельная диагностика VPN: "
    "время события, уровень и числовой код/тип ошибки (если известны), "
    "известные SHA-256 файлов. Только техническая сводка из отдельного журнала.\n\n"
    "Без сырых строк VPN-ядер, серверов, IP, доменов, истории посещений, профилей, "
    "подписок, UUID, паролей, токенов, маршрутов и конфигураций.\n\n"
    "Сейчас отправка не подключена.")


def summary(record: logging.LogRecord) -> dict:
    from diag import anon
    component = record.name.removeprefix("sbit.").split(".", 1)[0]
    data = {"time": int(record.created), "component": component if component in COMPONENTS else "other",
            "level": LEVELS.get(record.levelno, "INFO")}
    # Не копируем message, args, traceback, threadName и прочие произвольные строки.
    if record.exc_info and record.exc_info[0]:
        name = record.exc_info[0].__name__
        data["error"] = name if name in ERRORS else "Error"
        code = getattr(record.exc_info[1], "winerror", None)
        if isinstance(code, int) and 0 <= code < 2**32:
            data["code"] = code
    try:
        hashes = anon.known_file_hashes(record.getMessage())
        if hashes:
            data["sha256"] = hashes[:32]
    except Exception:  # noqa: BLE001, S110 — нельзя логировать из обработчика журнала рекурсивно
        pass
    return data


class SummaryFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps(summary(record), ensure_ascii=True, separators=(",", ":"))


def valid_record(raw) -> dict | None:
    """Повторный allowlist при экспорте, даже если локальный JSONL был изменён."""
    if not isinstance(raw, dict):
        return None
    stamp = raw.get("time")
    if not isinstance(stamp, int) or not 0 <= stamp < 2**40:
        return None
    result = {"time": stamp, "component": raw.get("component"), "level": raw.get("level")}
    if result["component"] not in COMPONENTS | {"other"} or result["level"] not in LEVELS.values():
        return None
    if raw.get("error") in ERRORS | {"Error"}:
        result["error"] = raw["error"]
    code = raw.get("code")
    if isinstance(code, int) and 0 <= code < 2**32:
        result["code"] = code
    hashes = raw.get("sha256")
    if isinstance(hashes, list):
        clean = [s.lower() for s in hashes[:32]
                 if isinstance(s, str) and re.fullmatch(r"[a-fA-F0-9]{64}", s)]
        if clean:
            result["sha256"] = clean
    return result


def records(folder: Path, kind: str) -> list[dict]:
    out = []
    path = folder / FILES[kind]
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - MAX_BYTES))
            # Обрезанная первая строка отбросится JSON-парсером.
            for line in stream.read(MAX_BYTES).decode("utf-8", "replace").splitlines()[-MAX_RECORDS:]:
                try:
                    value = valid_record(json.loads(line))
                except (ValueError, TypeError):
                    continue
                if value is not None:
                    if kind == "essential" and value["level"] not in ("ERROR", "CRITICAL"):
                        continue
                    if kind != "vpn" and value["component"] == "vpn":
                        continue
                    out.append(value)
    except OSError:
        pass
    return out


def crash_frames(folders) -> list[dict]:
    """Из faulthandler берём только строку и хэш своего исходного модуля, не путь/код."""
    import hashlib
    root = Path(__file__).resolve().parent.parent
    frames = []
    for folder in folders:
        try:
            with (folder / "crash.log").open("rb") as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 65536))
                text = stream.read(65536).decode("utf-8", "replace")
        except OSError:
            continue
        for name, line in re.findall(r'File "([^"\r\n]+)", line (\d+)', text)[-64:]:
            item = {"line": min(int(line[:9]), 2**31 - 1), "sha256": ""}
            if not name.startswith(("\\\\", "//")):
                try:
                    path = Path(name).resolve()
                    if path.is_relative_to(root) and path.suffix == ".py" and path.stat().st_size <= 2**20:
                        item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    pass
            frames.append(item)
    return frames[-64:]


def collect(target: Path, kind: str = "essential") -> dict:
    """Локальный ZIP из фиксированной схемы. Это не отправка и не очередь."""
    from ui import settings as cfg
    from diag import edition
    if kind not in (*FILES, "crash"):
        raise ValueError("неизвестный вид диагностики")
    if kind in ("extra", "vpn") and not cfg.get("support/extra"):
        raise PermissionError("нет согласия на дополнительные сведения")
    if kind == "vpn" and not cfg.get("support/vpn"):
        raise PermissionError("нет отдельного согласия на сведения VPN")
    selected = "essential" if kind == "crash" else kind
    folders = {datadirs.LOGS.resolve(), (datadirs.APP_CACHE.parent / "logs").resolve()}
    events = [r for folder in folders for r in records(folder, selected)]
    version = platform.version()
    safe_version = version if re.fullmatch(r"\d+(?:\.\d+){1,4}", version) else ""
    parts = safe_version.split(".")
    manifest = {"app": "StretchBIT", "version": appinfo.VERSION, "kind": kind,
                "edition": "test" if edition.is_test() else "release",
                "created": int(time.time()), "schema": 1,
                "windows_build": safe_version,
                "arch": "64" if platform.machine().lower() in ("amd64", "x86_64", "arm64", "aarch64")
                else "32", "events": len(events)}
    manifest["windows"] = {"caption": "Windows", "build": parts[2] if len(parts) >= 3 else "",
                           "arch": manifest["arch"]}
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    import tempfile
    import os
    fd, name = tempfile.mkstemp(prefix="sbit-report-", suffix=".part", dir=target.parent)
    os.close(fd)
    tmp = Path(name)
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=True))
            # Повторяющиеся события не должны выглядеть zip-бомбой для импортёра отчётов.
            z.writestr("events.jsonl", "".join(json.dumps(r, ensure_ascii=True) + "\n" for r in events),
                       compress_type=zipfile.ZIP_STORED)
            # Нативный сбой может не успеть записать событие ERROR.
            if kind == "crash":
                z.writestr("crash.json", json.dumps({"event": "unexpected_exit",
                                                   "frames": crash_frames(folders)}))
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return manifest


def request_send(kind: str = "essential") -> str:
    """Заглушка: не создаёт архив, не открывает сеть и ничего не ставит в очередь."""
    return "Отправка пока недоступна: сервер приёма не подключён. Ничего не отправлено."
