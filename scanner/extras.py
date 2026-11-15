"""Дополнительные этапы быстрой и полной проверки (fullscan.run).

• Быстрая: весь автозапуск — реестр, папки автозагрузки, службы, планировщик, WMI (как
  сканер автозапуска: файлы записей — через scanner.pool, подписи и признаки — assess).
• Полная (с 15.11.2026): тот же автозапуск, флешки (вирус-ярлык, autorun.inf, скрытые скрипты — usbguard.scan),
  уязвимые драйверы (база LOLDrivers — scanner.drivers), расширения браузеров
  (toolbox.extensions, только опасные), записи загрузки BCD (recovery.checks.check_bcd),
  политики и блокировки реестра (recovery.policies: запрет диспетчера задач, DisallowRun,
  перехват IFEO...). hosts и прокси в полной больше нет.
• Обе: память запущенных процессов (YARA по приватной памяти, как «Сканировать память» в
  диспетчере процессов: системные неизменившиеся процессы берутся из memcache, совпадение у
  подписанной программы — «проверить», не угроза).

Каждый этап сообщает найденное через on_found(path, level, text): path — файл (можно
поместить в карантин) или пустая строка (запись системы, драйвер, расширение). Записи
из исключений (автозапуск, проверка системы, драйверы) не показываются, как и в их окнах.
"""
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

AUTORUN_LEVELS = {"threat": "threat", "suspicious": "suspicious"}  # «проверить» — не находка
CHECK_LEVELS = {"bad": "threat", "warning": "suspicious"}
DRIVER_LEVELS = {"danger": "threat", "warning": "suspicious"}
USB_LEVELS = {"threat": "threat", "suspicious": "suspicious"}


def scan_autoruns(signatures, rules, whitelist, on_found, cancel: threading.Event,
                  say=lambda text: None) -> int:
    """Все записи автозапуска; найденное — on_found. Возвращает число записей."""
    from autoruns.scanner import Context, assess, collect_all
    from scanner import exclusions, pool as scan_pool
    say("Автозапуск: читаю записи...")
    entries, _ = collect_all()
    data = exclusions.load()
    entries = [e for e in entries
               if not exclusions.matches(data, "autoruns", exclusions.entry_key(e),
                                         exclusions.fingerprint(e.exe))]
    ctx = Context(signatures, rules, whitelist)
    exes = sorted({e.exe for e in entries if e.exe and os.path.isfile(e.exe)})
    say(f"Автозапуск: проверяю файлы ({len(exes)})...")
    for path, reason, error in scan_pool.check_files(exes, signatures, rules, whitelist,
                                                     cancel=cancel):
        ctx.verdicts[path] = "" if error is not None else reason or ""
    for e in entries:
        if cancel.is_set():
            break
        try:
            assess(e, ctx)
        except Exception:  # noqa: S110 — одна непонятная запись не обрывает этап
            continue
        level = AUTORUN_LEVELS.get(e.level)
        if level:
            text = f"автозапуск ({e.location}: {e.name}) — " + "; ".join(e.flags)
            on_found(e.exe if e.exe and os.path.isfile(e.exe) else "", level, text)
    return len(entries)


def scan_usb(roots: list[str], on_found, cancel: threading.Event,
             say=lambda text: None) -> int:
    """Съёмные диски из roots: признаки вируса-ярлыка (сами файлы флешки проверяет обход
    диска). Число проверенных флешек."""
    from scanner.fullscan import drives
    from usbguard.scan import scan_drive
    wanted = {os.path.normcase(r.rstrip("\\/")) for r in roots}
    done = 0
    for drive in drives():
        if cancel.is_set():
            break
        if not drive.removable or os.path.normcase(drive.root.rstrip("\\/")) not in wanted:
            continue
        say(f"Флешка {drive.root[:2]}: ярлыки, autorun.inf, скрытые папки...")
        report = scan_drive(drive.root, drive.label)
        done += 1
        for f in report.findings:
            level = USB_LEVELS.get(f.level)
            if level:
                on_found(f.path if os.path.isfile(f.path) else "", level,
                         f"флешка {drive.root[:2]}: {f.title} ({f.path})")
    return done


def scan_drivers(on_found, cancel: threading.Event, say=lambda text: None) -> int:
    """Драйверы системы по базе LOLDrivers; число проверенных драйверов."""
    from scanner import drivers
    say("Уязвимые драйверы: читаю список...")
    db = drivers.load_db()
    if not len(db):
        say("Уязвимые драйверы: базы LOLDrivers ещё нет")
        return 0
    found = drivers.list_drivers()
    excluded = drivers.excluded_hashes()
    say(f"Уязвимые драйверы: проверяю ({len(found)})...")
    done = 0
    for d in found:
        if cancel.is_set():
            break
        drivers.check(d, db, excluded)
        done += 1
        level = DRIVER_LEVELS.get(d.level)
        if level:
            service = f", служба {d.service}" if d.service else ""
            # путь не передаётся: драйвер в карантин из журнала не убирают (система может
            # не загрузиться) — для этого окно «Уязвимые драйверы» (отключение с откатом)
            on_found("", level, f"драйвер {d.path}{service}: {d.verdict()}")
    return done


def scan_extensions(on_found, cancel: threading.Event, say=lambda text: None) -> int:
    """Расширения браузеров; находка — только «опасное» (как красные строки в окне
    «Расширения браузеров»). Число расширений."""
    from toolbox import extensions
    say("Расширения браузеров...")
    items = extensions.all_extensions()
    for ext in items:
        if cancel.is_set():
            break
        level, reasons = ext.risk
        if level == "danger":
            name = ext.name or ext.ext_id
            on_found("", "suspicious", f"расширение {ext.browser} ({ext.profile}): {name} "
                                       f"[{ext.ext_id}] — " + "; ".join(reasons))
    return len(items)


def scan_bcd(on_found, cancel: threading.Event, say=lambda text: None) -> int:
    """Записи загрузки (тестовый режим подписи, отключённая проверка целостности...)."""
    from recovery import checks
    from scanner import exclusions
    say("Записи загрузки BCD...")
    data = exclusions.load()
    findings = checks.check_bcd()
    for f in findings:
        level = CHECK_LEVELS.get(f.level)
        if level and not exclusions.matches(data, "checks", exclusions.finding_key(f)):
            on_found("", level, f"загрузка (BCD): {f.title} — {f.status}")
    return 0 if cancel.is_set() else 1


def scan_policies(on_found, cancel: threading.Event, say=lambda text: None) -> int:
    """Политики и блокировки в реестре; число найденных (до исключений)."""
    from recovery import policies
    from scanner import exclusions
    say("Политики и блокировки реестра...")
    data = exclusions.load()
    hits = policies.scan_restrictions()
    for hit in hits:
        if cancel.is_set():
            break
        if not exclusions.matches(data, "checks", exclusions.hit_key(hit)):
            # UAC и точки восстановления выключены — угроза, остальное — подозрительно
            level = "threat" if hit.restriction_name in policies.CRITICAL else "suspicious"
            on_found("", level, f"ограничение в реестре: {hit.title} "
                                f"({hit.hive}\\{hit.path})")
    return len(hits)


@dataclass
class _Proc:  # то, что нужно memcache: pid, время запуска, файл
    pid: int
    ppid: int
    name: str
    exe: str
    created: float


def scan_memory(on_found, cancel: threading.Event, say=lambda text: None,
                workers: int | None = None) -> int:
    """Память всех процессов правилами «memory»; число проверенных процессов."""
    from processmanager import memcache, ntsnap
    import ownproc
    from processmanager.memscan import by_signature, get_rules, kernel_process, scan_process
    from scanner.yara_engine import rules_version
    from ui import settings as cfg
    say("Память процессов: загружаю правила...")
    rules = get_rules("memory")
    if rules is None:
        return 0
    rules_key = f"memory|False|{rules_version(rules) or id(rules)}"
    me = os.getpid()
    procs = []
    for raw in ntsnap.list_processes():
        if raw.pid == me:
            continue
        exe = ntsnap._exe_by_kernel(raw.pid)
        if kernel_process(raw.pid, raw.ppid, exe):
            continue
        if ownproc.is_own_process(raw.pid, exe):
            continue  # своя программа (служба, окно): в памяти — правила YARA, совпали бы сами
        procs.append(_Proc(raw.pid, raw.ppid, raw.name, exe, raw.created))

    def work(p: _Proc):
        if cancel.is_set():
            return p, None
        cached, fp = memcache.lookup(p, rules_key)
        if cached is not None:
            return p, cached
        res = scan_process(rules, p.pid)
        memcache.store(p, rules_key, fp, res)
        return p, by_signature(res, p.exe)  # подписанная программа: проверить, не угроза

    done = 0
    workers = workers or int(cfg.get("scan/workers"))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(work, p) for p in procs]
        for future in as_completed(futures):
            p, res = future.result()
            if res is None:
                continue
            done += 1
            if done % 20 == 0:
                say(f"Память процессов: {done}/{len(procs)}")
            if res.status in ("match", "signed", "check"):
                level = "threat" if res.status == "match" else "suspicious"
                on_found(p.exe or "", level,
                         f"память процесса {p.name} (PID {p.pid}): {res.text()}")
    return done
