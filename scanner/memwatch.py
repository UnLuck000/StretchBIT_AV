"""Наблюдение за памятью процессов: ловит внедрение кода в уже работающие процессы.

Контроль запуска (launchguard) проверяет ФАЙЛ нового процесса, а не его память. Вредонос
может записать свой код в чужой процесс (explorer.exe, svchost.exe) и удалить себя — файл
жертвы чистый и подписан, чужой код только в памяти. Два способа (15.11.2026):

1. Поток в чужом процессе — ETW Microsoft-Windows-Kernel-Process, ключ потоков (0x20),
   событие 3 ThreadStart. В заголовке события — PID того, КТО создал поток (проверено вживую:
   CreateRemoteThread из python.exe в дочерний процесс → заголовок 4640, ProcessID 16044),
   в данных — ProcessID и ThreadID жертвы, со смещения 40 — StartAddr. Создатель ≠ жертва →
   сразу проверка памяти жертвы правилами YARA для памяти. Не считаются: ядро (PID 0, 4),
   первый поток нового процесса (его создаёт родитель — процесс моложе FRESH), csrss.exe
   (потоки Ctrl+C в консольных программах). Нужны права администратора (служба); без них —
   только способ 2.
2. Новая исполняемая память — раз в INTERVAL отпечаток исполняемых регионов всех процессов
   (адрес, размер, права, тип — без чтения содержимого; VirtualQueryEx). Отпечаток
   изменился → проверка памяти. У каждого процесса свой интервал: сначала INTERVAL, после
   чистой проверки изменившейся памяти удваивается до MAX_INTERVAL (программы с JIT меняют
   память постоянно); браузеры, .NET и т. п. по имени — сразу MAX_INTERVAL. Процесс обходится
   не чаще своего интервала: обход стоит в ядре ~2 мкс на регион памяти (вызов VirtualQueryEx),
   у браузеров регионов десятки тысяч. Ловит и внедрение без нового потока
   (APC, подмена контекста потока). Процесс, впервые увиденный после первого обхода, с
   приватной исполняемой памятью и без JIT — проверяется сразу (подмена образа процесса:
   создан приостановленным, код записан до первого обхода). Первый обход только запоминает:
   то, что работало до включения, проверяют быстрая и полная проверки.

Совпадение правил: программа без действительной подписи — угроза, с подписью — «проверить»
(как memscan в диспетчере процессов). Сама ничего не завершает: on_event(kind, info),
kind — found | status | error.
"""
import ctypes
import hashlib
import os
import queue
import struct
import sys
import threading
import time

SESSION_NAME = "sbit-threads"
KEYWORD_THREAD = 0x20
EVENT_THREAD_START = 3
START_ADDR_OFFSET = 40      # ProcessID, ThreadID, 4 указателя стека → StartAddr
INTERVAL = 60.0             # с: обход отпечатков
MAX_INTERVAL = 15 * 60.0    # с: предел для программ, которые меняют память постоянно
FRESH = 5.0                 # с: первый поток процесса моложе этого создаёт родитель
REMOTE_REPEAT = 10.0        # с: повторный поток в ту же жертву — не раньше
SKIP_CREATORS = {"csrss.exe"}
EXEC_MASK = 0x10 | 0x20 | 0x40 | 0x80   # PAGE_EXECUTE*
MEM_COMMIT, MEM_PRIVATE = 0x1000, 0x20000


def parse_thread_start(header_pid: int, data: bytes) -> tuple[int, int, int, int] | None:
    """(создатель, жертва, поток, адрес начала) или None — поток своего процесса."""
    if len(data) < 8:
        return None
    target, tid = struct.unpack_from("<II", data, 0)
    start = struct.unpack_from("<Q", data, START_ADDR_OFFSET)[0] \
        if len(data) >= START_ADDR_OFFSET + 8 else 0
    if header_pid == target or header_pid in (0, 4) or target in (0, 4):
        return None
    return header_pid, target, tid, start


def is_jit_name(name: str) -> bool:
    from processmanager.memdeep import JIT_HINTS
    low = name.lower()
    return any(hint in low for hint in JIT_HINTS)


try:  # нативный модуль (native/src/module.cpp): обход всех процессов в десятки раз быстрее
    from scanner._native import exec_map as _native_exec_map
except (ImportError, AttributeError):  # модуль не собран или старой сборки
    _native_exec_map = None


def exec_map(pid: int) -> tuple | None:
    """(отпечаток исполняемых регионов, байт приватной исполняемой памяти); None — нет
    доступа или процесс завершился. Отпечаток сравнивается только с прежним того же процесса."""
    if _native_exec_map is not None:
        return _native_exec_map(pid)
    return exec_map_python(pid)


def exec_map_python(pid: int) -> tuple[str, int] | None:
    """Запасной вариант без нативного модуля (около 4,5 мкс на регион памяти)."""
    from processmanager import memdeep
    k32 = memdeep.kernel32
    handle = k32.OpenProcess(memdeep.PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        mbi = memdeep.MEMORY_BASIC_INFORMATION()
        query, ref, size_of = k32.VirtualQueryEx, ctypes.byref(mbi), ctypes.sizeof(mbi)
        address, limit = 0, 0x7FFFFFFFFFFF
        parts: list[tuple] = []
        private = 0
        while address < limit:   # самый частый код обхода: без лишних обращений к атрибутам
            if not query(handle, address, ref, size_of):
                break
            size = mbi.RegionSize
            if mbi.State == MEM_COMMIT and mbi.Protect & EXEC_MASK:
                kind = mbi.Type
                parts.append((address, size, mbi.Protect, kind))
                if kind == MEM_PRIVATE:
                    private += size
            if size == 0:
                break
            address += size
        digest = hashlib.sha1(repr(parts).encode(), usedforsecurity=False)
        return digest.hexdigest(), private
    finally:
        k32.CloseHandle(handle)


class _Seen:
    __slots__ = ("created", "fp", "interval", "mapped", "scanned")

    def __init__(self, created: float, fp, interval: float, now: float):
        self.created, self.fp, self.interval = created, fp, interval
        self.mapped, self.scanned = now, 0.0


class MemWatch:
    def __init__(self, on_event, interval: float = INTERVAL, use_etw: bool = True,
                 rules=None, lister=None, mapper=None, scanner=None):
        self.on_event = on_event
        self.interval = interval
        self.use_etw = use_etw
        self._rules = rules
        self._list = lister or self._list_processes        # тесты подменяют
        self._map = mapper or exec_map
        self._scan = scanner or self._scan_memory
        self._stop = threading.Event()
        self._queue: queue.Queue = queue.Queue(maxsize=256)
        self._seen: dict[int, _Seen] = {}
        self._remote_last: dict[int, float] = {}
        self._trace = None
        self._threads: list[threading.Thread] = []
        self.etw = False
        self.scans = 0           # проверок памяти за работу (для журнала и тестов)
        self.passes = 0          # обходов отпечатков

    # ---------- запуск ----------
    def start(self) -> None:
        self._stop.clear()
        if self.use_etw and sys.platform == "win32":
            from processmanager.etw import KERNEL_PROCESS, EtwTrace
            trace = EtwTrace(SESSION_NAME, KERNEL_PROCESS, KEYWORD_THREAD, self._on_etw,
                             event_ids={EVENT_THREAD_START}, flush=0.5)
            if trace.start() == 0:
                self._trace, self.etw = trace, True
        for target, name in ((self._worker, "memwatch-scan"), (self._poller, "memwatch-poll")):
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            self._threads.append(thread)
        self.on_event("status", self.describe())

    def describe(self) -> str:
        how = ("потоки, созданные в чужих процессах, — сразу; новая исполняемая память — раз "
               "в минуту") if self.etw else ("новая исполняемая память — раз в минуту (потоки "
                                            "в чужих процессах видны только с правами "
                                            "администратора)")
        return f"Память запущенных программ проверяется при внедрении кода: {how}."

    def stop(self) -> None:
        self._stop.set()
        if self._trace is not None:
            self._trace.stop()
            self._trace = None
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads = []

    def running(self) -> bool:
        return bool(self._threads) and not self._stop.is_set()

    # ---------- способ 1: поток в чужом процессе ----------
    def _on_etw(self, event_id: int, header_pid: int, data: bytes) -> None:
        if event_id != EVENT_THREAD_START or header_pid == os.getpid():
            return
        parsed = parse_thread_start(header_pid, data)
        if parsed is None:
            return
        try:
            self._queue.put_nowait(("remote", *parsed))
        except queue.Full:
            pass  # всплеск событий: обход отпечатков всё равно увидит изменения

    def _worker(self) -> None:
        while not self._stop.is_set():
            item = self._queue.get()
            if item is None:
                return
            try:
                self._handle_remote(*item[1:])
            except Exception:  # noqa: BLE001 — один сбой не останавливает наблюдение
                from diag.log import swallowed
                swallowed("memwatch: поток в чужом процессе")

    def _handle_remote(self, creator: int, target: int, tid: int, start: int) -> None:
        now = time.monotonic()
        if now - self._remote_last.get(target, -1e9) < REMOTE_REPEAT:
            return
        info = self._process_info(target)
        if info is None:  # уже завершился
            return
        source = self._process_info(creator) or self._from_story(creator)
        if source["name"].lower() in SKIP_CREATORS:
            return
        if info["ppid"] == creator and time.time() - info["created"] < FRESH:
            return  # первый поток нового процесса: его создаёт родитель
        self._remote_last[target] = now
        reason = (f"поток создан процессом {source['name']} (PID {creator}), "
                  f"адрес начала 0x{start:x}")
        self._check(info, reason, creator=source)

    # ---------- способ 2: новая исполняемая память ----------
    def _poller(self) -> None:
        first = True
        while not self._stop.is_set():
            try:
                self._pass(first)
                first = False
            except Exception:  # noqa: BLE001 — обход повторится через interval
                from diag.log import swallowed
                swallowed("memwatch: обход отпечатков")
            if self._stop.wait(self.interval):
                return

    def _pass(self, first: bool) -> None:
        now = time.monotonic()
        alive = set()
        for proc in self._list():
            if self._stop.is_set():
                return
            pid = proc["pid"]
            alive.add(pid)
            seen = self._seen.get(pid)
            if seen is not None and seen.created == proc["created"] and (
                    now - seen.mapped < seen.interval - self.interval / 2):
                continue  # память этого процесса меняется часто: обходится реже (interval)
            mapped = self._map(pid)
            if mapped is None:
                continue
            fp, private = mapped
            jit = is_jit_name(proc["name"])
            if seen is None or seen.created != proc["created"]:
                seen = self._seen[pid] = _Seen(proc["created"], fp,
                                               MAX_INTERVAL if jit else self.interval, now)
                if not first and private and not jit:
                    seen.scanned = now
                    self._check(proc, "новый процесс с исполняемым кодом в приватной памяти")
                continue
            seen.mapped = now
            if fp == seen.fp:
                continue
            seen.fp, seen.scanned = fp, now
            if not self._check(proc, "в процессе появилась новая исполняемая память"):
                seen.interval = min(seen.interval * 2, MAX_INTERVAL)
        for pid in set(self._seen) - alive:
            del self._seen[pid]
            self._remote_last.pop(pid, None)
        self.passes += 1

    # ---------- проверка ----------
    def _check(self, proc: dict, reason: str, creator: dict | None = None) -> bool:
        """True — найдено совпадение правил."""
        self.scans += 1
        result = self._scan(proc["pid"])
        if result is None or result.status not in ("match", "signed"):
            return False
        level = "threat" if result.status == "match" else "suspicious"
        info = {"pid": proc["pid"], "name": proc["name"], "exe": proc.get("exe", ""),
                "level": level, "matches": list(result.matches), "reason": reason,
                "text": f"память: {', '.join(result.matches)} — {reason}"}
        if creator is not None:
            info.update(creator_pid=creator["pid"], creator_name=creator["name"],
                        creator_exe=creator.get("exe", ""))
        self.on_event("found", info)
        return True

    def _rules_for_memory(self):
        """Правила для памяти: общая копия memscan.get_rules — после обновления баз служба
        сбрасывает её (memscan.reset_cache), и следующая проверка берёт новые."""
        if self._rules is not None:
            return self._rules
        from processmanager.memscan import get_rules
        return get_rules("memory")

    def _scan_memory(self, pid: int):
        from processmanager.memscan import scan_process
        from scanner.signature import VALID, inspect_signature
        rules = self._rules_for_memory()
        if rules is None:
            return None
        result = scan_process(rules, pid)
        if result.status == "match":
            exe = self._exe(pid)
            if exe:
                try:
                    from pathlib import Path
                    if inspect_signature(Path(exe)).status == VALID:
                        result.status = "signed"  # подписанная программа: проверить
                except OSError:
                    pass
        return result

    # ---------- процессы ----------
    @staticmethod
    def _exe(pid: int) -> str:
        from processmanager import ntsnap
        try:
            return ntsnap._exe_by_kernel(pid) or ""
        except Exception:  # noqa: BLE001 — процесс завершился
            return ""

    def _list_processes(self) -> list[dict]:
        from processmanager import ntsnap
        from processmanager.memscan import kernel_process
        me = os.getpid()
        found = []
        for raw in ntsnap.list_processes():
            if raw.pid == me or raw.pid in (0, 4):
                continue
            exe = self._exe(raw.pid)
            if kernel_process(raw.pid, raw.ppid, exe):
                continue
            found.append({"pid": raw.pid, "ppid": raw.ppid, "name": raw.name, "exe": exe,
                          "created": raw.created})
        return found

    @staticmethod
    def _from_story(pid: int) -> dict:
        """Создатель потока уже завершился («внедрился и удалился»): имя и файл — из сводки
        processmanager/story.py (её пишет контроль запуска при каждом запуске)."""
        from processmanager.story import STORY
        rec = STORY.record(pid)
        if rec is None:
            return {"pid": pid, "name": "завершившийся процесс", "exe": "", "ppid": 0,
                    "created": 0.0}
        return {"pid": pid, "name": rec.name or "завершившийся процесс", "exe": rec.exe,
                "ppid": rec.ppid, "created": rec.started}

    def _process_info(self, pid: int) -> dict | None:
        from processmanager import ntsnap
        for raw in ntsnap.list_processes():
            if raw.pid == pid:
                return {"pid": pid, "ppid": raw.ppid, "name": raw.name, "exe": self._exe(pid),
                        "created": raw.created}
        return None
