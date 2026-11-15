r"""Свои процессы программы: защиты их не проверяют и не приостанавливают.

Пока защиты работали в окне, своим был сам процесс (os.getpid()) и его дочерние. Со службой
(service/) защиты — в её процессе, а окно и его рабочие процессы проверки — отдельные
StretchBIT.exe без прав. Служба приостанавливала бы собственное окно: «Расширения» читают
Local State браузера, проверка дисков открывает Cookies — и окно замирало бы, не в силах
ответить на тревогу о самом себе.

* is_program(pid) — образ процесса тот же StretchBIT.exe, что у нас: окно, служба, рабочие
  процессы «--scan-worker», сторож. Только в собранной программе: из исходников образ —
  python.exe, и своим оказался бы любой скрипт.
* in_program_dir(exe) — файл из папки установки (ядра VPN, rizin, upx...), если папку меняют
  только администраторы (winacl): в открытую папку свой файл подложит кто угодно.

Дочерние процессы окна (PowerShell, ядра VPN) своими НЕ считаются: родителя процессу без прав
можно подделать (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), а образ в закрытой папке — нет.
Скрипты окна проверяются AMSI и журналом 4104 наравне с чужими.
"""
import os
import sys

_dir_safe: bool | None = None  # папка программы закрыта от записи (проверяется один раз)


def program_exe() -> str:
    """Путь StretchBIT.exe (os.path.normcase) в собранной программе, иначе ""."""
    return os.path.normcase(sys.executable) if getattr(sys, "frozen", False) else ""


def image(pid: int) -> str:
    """Путь образа процесса или ""."""
    try:
        from processmanager import ntsnap
        if ntsnap.AVAILABLE:
            return ntsnap.identity(pid)[0]
        import psutil
        return psutil.Process(pid).exe()
    except Exception:  # noqa: BLE001 — процесс завершился или защищён
        return ""


def is_program(pid: int, exe: str | None = None) -> bool:
    """Этот процесс или другой процесс той же программы. exe — путь образа, если известен."""
    if pid == os.getpid():
        return True
    own = program_exe()
    if not own:
        return False
    if exe is None:
        exe = image(pid)
    return bool(exe) and os.path.normcase(os.path.normpath(exe)) == own


def in_program_dir(exe: str) -> bool:
    """Файл лежит в папке установки, и менять её могут только администраторы."""
    global _dir_safe
    own = program_exe()
    if not own or not exe:
        return False
    root = os.path.dirname(own) + os.sep
    if not os.path.normcase(os.path.normpath(exe)).startswith(root):
        return False
    if _dir_safe is None:
        try:
            import winacl
            _dir_safe = winacl.admin_only(own)[0]
        except Exception:  # noqa: BLE001 — права не узнать: папку закрытой не считаем
            _dir_safe = False
    return _dir_safe


# ---------- обе версии программы (релизная и тестовая) ----------
EDITION_DIRS = ("StretchBIT", "StretchBIT-test")   # папки установки в Program Files
_safe_dirs: dict[str, bool] = {}


def install_dirs() -> list[str]:
    """Папки установки программы (обеих версий) с разделителем на конце, os.path.normcase.
    Из исходников тоже: служба установленной версии — своя (15.11.2026 полная проверка из
    исходников нашла «вирусы» в памяти службы — там загружены правила YARA)."""
    roots = {os.environ.get("ProgramW6432", ""), os.environ.get("ProgramFiles", "")}
    found = [os.path.normcase(os.path.join(r, name)) + os.sep
             for r in roots if r for name in EDITION_DIRS]
    own = program_exe()
    if own:
        found.append(os.path.dirname(own) + os.sep)
    return sorted(set(found))


def _dir_closed(folder: str) -> bool:
    if folder not in _safe_dirs:
        try:
            import winacl
            _safe_dirs[folder] = os.path.isdir(folder) and \
                winacl.admin_only(os.path.join(folder, "StretchBIT.exe"))[0]
        except Exception:  # noqa: BLE001 — права не узнать: папку закрытой не считаем
            _safe_dirs[folder] = False
    return _safe_dirs[folder]


def is_own_file(exe: str) -> bool:
    """Файл из папки установки StretchBIT (любой версии), закрытой от записи: сама программа,
    её служба, ядра VPN, rizin. Открытая папка не считается: свой файл туда подложит любой."""
    if not exe:
        return False
    path = os.path.normcase(os.path.normpath(exe))
    return any(path.startswith(folder) and _dir_closed(folder) for folder in install_dirs())


def is_own_process(pid: int, exe: str | None = None) -> bool:
    """Процесс программы (любой версии) или её файла из закрытой папки установки."""
    if is_program(pid, exe):
        return True
    if exe is None:
        exe = image(pid)
    return is_own_file(exe)
