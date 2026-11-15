"""Наблюдение за памятью процессов (scanner/memwatch.py): разбор события потока ETW, обход
отпечатков исполняемой памяти и отбор потоков в чужих процессах. Без ETW и без YARA."""
import struct
import time

from scanner import memwatch


def _thread_event(target: int, tid: int, start: int) -> bytes:
    # ProcessID, ThreadID, StackBase, StackLimit, UserStackBase, UserStackLimit, StartAddr,
    # Win32StartAddr, TebBase, SubProcessTag — 68 байт, как в живом событии Windows 11
    return struct.pack("<II4QQQQI", target, tid, 1, 2, 3, 4, start, start, 5, 0)


def test_parse_thread_start():
    data = _thread_event(16044, 15456, 0x7FFF6F2D0E50)
    assert len(data) == 68
    assert memwatch.parse_thread_start(4640, data) == (4640, 16044, 15456, 0x7FFF6F2D0E50)
    assert memwatch.parse_thread_start(16044, data) is None          # свой поток
    assert memwatch.parse_thread_start(4, data) is None              # ядро
    assert memwatch.parse_thread_start(4640, b"\0" * 4) is None


class Hit:
    status, matches = "match", ["Injected_Code"]


class Clean:
    status, matches = "clean", []


def _watch(procs, maps, hits=()):
    scanned, found = [], []

    def scan(pid):
        scanned.append(pid)
        return Hit() if pid in hits else Clean()
    watch = memwatch.MemWatch(lambda kind, info: found.append((kind, info)), interval=60,
                              use_etw=False, lister=lambda: list(procs),
                              mapper=lambda pid: maps.get(pid), scanner=scan)
    return watch, scanned, found


def _later(watch, seconds=60.0):
    """Прошло seconds: обходы идут раз в минуту, а не подряд."""
    for seen in watch._seen.values():
        seen.mapped -= seconds
        seen.scanned -= seconds


def _proc(pid, name="app.exe", created=1.0, ppid=1):
    return {"pid": pid, "ppid": ppid, "name": name, "exe": rf"C:\x\{name}", "created": created}


def test_first_pass_only_remembers_then_changes_are_scanned():
    procs = [_proc(10), _proc(11, "chrome.exe")]
    maps = {10: ("a", 0), 11: ("b", 4096)}
    watch, scanned, found = _watch(procs, maps, hits={10})
    watch._pass(first=True)
    assert scanned == [] and len(watch._seen) == 2
    _later(watch)
    watch._pass(first=False)
    assert scanned == []                                   # ничего не изменилось
    maps[10] = ("a2", 4096)                                # новая исполняемая память
    _later(watch)
    watch._pass(first=False)
    assert scanned == [10]
    assert found[-1][0] == "found" and found[-1][1]["level"] == "threat"
    assert "новая исполняемая память" in found[-1][1]["reason"]


def test_clean_changes_back_off_and_jit_is_rare():
    procs = [_proc(10, "dotnetapp.exe"), _proc(11, "chrome.exe")]
    maps = {10: ("v0", 0), 11: ("c0", 0)}
    watch, scanned, _ = _watch(procs, maps)
    watch._pass(first=True)
    assert watch._seen[11].interval == memwatch.MAX_INTERVAL   # браузер — сразу редко
    maps[10], maps[11] = ("v1", 0), ("c1", 0)
    _later(watch)
    watch._pass(first=False)
    assert scanned == [10]                                     # браузер ещё не обходится
    assert watch._seen[10].interval == 120                     # чисто — интервал удвоен
    maps[10] = ("v2", 0)
    _later(watch)
    watch._pass(first=False)                                   # через минуту — рано
    assert scanned == [10]
    _later(watch)                                              # прошло два интервала обхода
    watch._pass(first=False)
    assert scanned == [10, 10]


def test_new_process_with_private_code_is_scanned():
    procs = [_proc(10)]
    maps = {10: ("a", 0)}
    watch, scanned, _ = _watch(procs, maps)
    watch._pass(first=True)
    procs += [_proc(20, "hollow.exe", created=5.0), _proc(21, "plain.exe", created=5.0),
              _proc(22, "firefox.exe", created=5.0)]
    maps.update({20: ("h", 8192), 21: ("p", 0), 22: ("f", 65536)})
    watch._pass(first=False)
    assert scanned == [20]                                     # без приватного кода и JIT — нет


def test_remote_thread_filters(monkeypatch):
    watch, scanned, found = _watch([], {}, hits={30})
    now = time.time()
    infos = {30: _proc(30, "explorer.exe", created=now - 600, ppid=5),
             31: _proc(31, "child.exe", created=now, ppid=40),
             40: _proc(40, "dropper.exe", created=now - 60, ppid=5),
             50: _proc(50, "csrss.exe", created=now - 600, ppid=4)}
    monkeypatch.setattr(watch, "_process_info", lambda pid: infos.get(pid))
    monkeypatch.setattr(watch, "_from_story", lambda pid: {"pid": pid, "name": "gone.exe",
                                                            "exe": "", "ppid": 0, "created": 0})
    watch._handle_remote(40, 31, 1, 0x1000)                    # первый поток нового процесса
    watch._handle_remote(50, 30, 2, 0x1000)                    # csrss: Ctrl+C
    assert scanned == []
    watch._handle_remote(40, 30, 3, 0x7FF0)                    # внедрение в explorer
    assert scanned == [30]
    info = found[-1][1]
    assert info["creator_name"] == "dropper.exe" and "0x7ff0" in info["reason"]
    watch._handle_remote(40, 30, 4, 0x7FF0)                    # повтор сразу — не проверяется
    assert scanned == [30]
    watch._remote_last.clear()
    watch._handle_remote(99, 30, 5, 0x10)                      # создатель уже завершился
    assert found[-1][1]["creator_name"] == "gone.exe"


def test_exec_map_native_matches_python():
    import os
    native = memwatch.exec_map(os.getpid())
    python = memwatch.exec_map_python(os.getpid())
    assert native is not None and python is not None
    assert abs(native[1] - python[1]) < 16 * 1024 * 1024       # приватный исполняемый код
