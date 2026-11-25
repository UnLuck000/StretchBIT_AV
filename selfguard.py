r"""Сторож программы: перезапуск после нештатного завершения.

Программа с правами администратора недоступна процессам обычного пользователя, но её может
снять другой процесс с правами (или она упадёт сама) — и защита молча пропадёт до следующего
входа в Windows. Сторож — второй процесс той же программы (StretchBIT.exe --watchdog <PID>):
ждёт завершения главного и, если обычного выхода не было (logs/session.json остался —
diag/crash.py), запускает программу заново в трее и пишет об этом в logs/crash.log.

Не перезапускает:
  * после обычного выхода («Выход» в трее, перезапуск с правами, удаление);
  * если идёт установка или удаление (метка cache/no_restart или запущен установщик);
  * чаще 3 раз за 10 минут (программа падает сразу при запуске — не зацикливаться).

Сеть после VPN (15.11.2026). Программу с подключённым VPN сняли в диспетчере задач: ядра VPN
завершились вместе с ней (объект задания Windows), а kill switch и подменённый DNS остались —
интернет был перекрыт, пока программу не запустили вручную. Теперь сторож после нештатного
завершения сам, до перезапуска, возвращает сеть (recover_network, не дольше NETWORK_BUDGET):
ядра без родителя, системный прокси, kill switch, DNS адаптеров. Работает всегда — и из
исходников, и с выключенным перезапуском (protect/selfguard): тогда сторож только
возвращает сеть.

Перезапуск — только в собранной программе (из исходников — при STRETCHBIT_WATCHDOG=1: иначе
остановка отладки в PyCharm перезапускала бы программу) и с настройкой protect/selfguard.
"""
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
import datadirs

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
SYNCHRONIZE = 0x00100000
LIMIT, WINDOW_SEC = 3, 600
MARK_SEC = 900                      # сколько действует метка «не перезапускать»
SESSION = datadirs.LOGS / "session.json"
CRASH_LOG = datadirs.LOGS / "crash.log"
STATE = datadirs.CACHE / "selfguard.json"
NO_RESTART = datadirs.APP_CACHE / "no_restart"  # ставят установщик и удаление
INSTALLER_HINTS = ("-setup", "unins0")
NETWORK_BUDGET = 90.0               # с: на возврат сети после VPN (Celeron: PowerShell медленный)
NO_RESTART_ARG = "--no-restart"     # сторож только возвращает сеть
NO_RECOVERY_ARG = "--no-network-recovery"  # пассивная версия: только предложение crash-report

_proc: subprocess.Popen | None = None


def allowed() -> bool:
    """Можно ли перезапускать программу (сеть сторож возвращает всегда)."""
    return bool(getattr(sys, "frozen", False)) or os.environ.get("STRETCHBIT_WATCHDOG") == "1"


def _command(*args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, str(Path(__file__).resolve().parent / "gui.py"), *args]


def start(restart: bool = True, recover: bool = True) -> bool:
    """Запустить сторожа для этого процесса (или убедиться, что он жив). restart=False или
    из исходников — сторож только возвращает сеть после VPN, программу не перезапускает."""
    global _proc
    if _proc is not None and _proc.poll() is None:
        return True
    args = ["--watchdog", str(os.getpid())]
    if not (restart and allowed()):
        args.append(NO_RESTART_ARG)
    if not recover:
        args.append(NO_RECOVERY_ARG)
    try:
        _proc = subprocess.Popen(_command(*args),
                                 creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
    except OSError:
        _proc = None
        return False
    return True


def stop() -> None:
    """Обычный выход: сторож больше не нужен."""
    global _proc
    proc, _proc = _proc, None
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass


def forbid_restart() -> None:
    """Перед установкой или удалением: программу закроют принудительно — не возвращать её."""
    try:
        NO_RESTART.parent.mkdir(parents=True, exist_ok=True)
        NO_RESTART.write_text(str(time.time()), encoding="ascii")
    except OSError:
        pass


def _forbidden() -> bool:
    try:
        return time.time() - NO_RESTART.stat().st_mtime < MARK_SEC
    except OSError:
        return False


def _installer_running() -> bool:
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            name = (p.info.get("name") or "").lower()
            if any(h in name for h in INSTALLER_HINTS) and ("stretchbit" in name
                                                            or name.startswith("unins0")):
                return True
    except Exception:  # noqa: BLE001, S110 — нет psutil или доступа: считаем, что не идёт
        pass
    return False


def abnormal_exit(pid: int) -> bool:
    """Главный процесс завершился, а метка его сеанса осталась — выхода не было."""
    try:
        data = json.loads(SESSION.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return int(data.get("pid", 0)) == pid


def may_restart(now: float | None = None) -> bool:
    """Не чаще LIMIT раз за WINDOW_SEC; отметка о перезапуске записывается."""
    now = time.time() if now is None else now
    try:
        times = [t for t in json.loads(STATE.read_text(encoding="utf-8"))
                 if now - float(t) < WINDOW_SEC]
    except (OSError, ValueError, TypeError):
        times = []
    if len(times) >= LIMIT:
        return False
    times.append(now)
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(times), encoding="utf-8")
    except OSError:
        pass
    return True


def _note(text: str) -> None:
    try:
        CRASH_LOG.parent.mkdir(exist_ok=True)
        with open(CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(f"--- сторож {time.strftime('%Y-%m-%d %H:%M:%S')}: {text}\n")
    except OSError:
        pass


def _wait(pid: int) -> bool:
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    handle = k32.OpenProcess(SYNCHRONIZE, False, pid)
    if not handle:
        # Отказ в доступе не означает смерть процесса: не показываем ложный crash-report.
        import psutil
        return not psutil.pid_exists(pid)
    try:
        return k32.WaitForSingleObject(ctypes.c_void_p(handle), 0xFFFFFFFF) == 0
    finally:
        k32.CloseHandle(ctypes.c_void_p(handle))


def decide(pid: int) -> str:
    """Что делать после завершения главного процесса: "" — ничего, иначе причина отказа
    или "restart"."""
    if not abnormal_exit(pid):
        return ""
    if _forbidden():
        return "идёт установка или удаление — без перезапуска"
    if _installer_running():
        return "запущен установщик — без перезапуска"
    if not may_restart():
        return f"больше {LIMIT} перезапусков за {WINDOW_SEC // 60} минут — без перезапуска"
    return "restart"


def recover_network(budget: float = NETWORK_BUDGET, steps=None) -> list[str]:
    """Вернуть сеть после аварийного завершения с VPN: что вернули (и что не успели).
    Каждый шаг — в своём потоке, весь возврат — не дольше budget секунд."""
    if steps is None:
        from vpn import dnsguard, killswitch, procguard, xray
        steps = [("ядра VPN без программы", procguard.kill_orphans),
                 ("kill switch", killswitch.recover),
                 ("DNS адаптеров", dnsguard.recover),
                 ("системный прокси", xray.recover_proxy)]
    deadline = time.monotonic() + budget
    report = []
    for title, step in steps:
        left = deadline - time.monotonic()
        if left <= 0:
            report.append(f"{title}: не хватило времени")
            continue
        result: dict = {}

        def run(step=step, result=result):
            try:
                result["value"] = step()
            except Exception as e:  # noqa: BLE001 — остальные шаги всё равно выполняются
                result["error"] = e
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(left)
        if thread.is_alive():
            report.append(f"{title}: не уложился в {budget:.0f} с")
        elif "error" in result:
            report.append(f"{title}: ошибка {result['error']}")
        elif result.get("value"):
            report.append(f"{title}: возвращено")
    return report


def _offer_crash_report(pid: int) -> None:
    """Отдельный живой процесс: предложение не зависит от следующего запуска GUI."""
    from diag import consent
    if not consent.accepted():
        return
    try:
        subprocess.Popen(_command("--crash-report"), creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                         close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except OSError:
        _note("не удалось открыть предложение crash-report")


def watch(pid: int, restart: bool = True, recover: bool = True) -> None:
    """Тело процесса-сторожа (gui.py --watchdog <PID> [--no-restart])."""
    if _wait(pid) is False:
        return
    time.sleep(1.0)  # выход пишет метку последним действием — дать ей исчезнуть
    if not abnormal_exit(pid):
        return
    if _forbidden() or _installer_running():
        return  # установку/удаление не выдаём за сбой
    _offer_crash_report(pid)  # до длительного возврата сети и до возможного перезапуска
    try:  # сначала сеть: без этого интернет перекрыт, пока программу не запустят вручную
        done = recover_network() if recover else []
    except Exception as e:  # noqa: BLE001 — перезапуск важнее
        done = [f"ошибка {e}"]
    if done:
        _note(f"программа (PID {pid}) завершена не штатно; сеть после VPN: " + "; ".join(done))
    if not restart:
        return
    verdict = decide(pid)
    if not verdict:
        return
    if verdict != "restart":
        _note(f"программа (PID {pid}) завершена не штатно; {verdict}")
        return
    _note(f"программа (PID {pid}) завершена не штатно — перезапуск")
    try:
        subprocess.Popen(_command("--autostart", "--restarted"),
                         creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS, close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except OSError as e:
        _note(f"перезапуск не удался: {e}")
