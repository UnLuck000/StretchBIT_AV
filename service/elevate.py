r"""Инструменты, меняющие систему, — отдельным процессом с правами
через окно UAC, а не операциями канала службы.

Почему не через службу: всё, что окно без прав может попросить у службы, может попросить и
вредонос в сеансе пользователя (он внедряется в процесс окна — тот без прав). Для защиты
это терпимо (операции узкие, ослабляющие — под запретом lock_protection), а центр
восстановления, сканер автозапуска и драйверы — это удаление ключей реестра, служб и файлов
по выбору пользователя: такой канал был бы готовым повышением прав. Окно UAC на каждое
открытие инструмента подтверждает сам пользователь (обойти его без прав нельзя).

    StretchBIT.exe --tool <recovery|autoruns|drivers|processes> [--tab N] — окно инструмента
    StretchBIT.exe --undo <id записи журнала>                     — отмена с правами

При вводе credentials другой учётной записи процесс инструмента принадлежит ей.
Главное окно остаётся у исходного пользователя: его AppData/DPAPI не подменяются.
Разрешённые вкладки передаются отдельно; общие карантин/журнал защиты — у службы.
"""
import ctypes
import os
import sys
from ctypes import wintypes

TOOLS = ("recovery", "autoruns", "drivers", "processes")
CAPABILITIES = ("memory", "restore", "sfc", "checks")
RECOVERY_ACTIONS = {
    "create": "restore", "enable-protection": "restore", "check": "checks",
    "command:sfc_verify": "sfc", "command:sfc_scan": "sfc", "command:dism_check": "sfc",
    "command:dism_scan": "sfc", "command:dism_restore": "sfc",
}
ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x40
SW_SHOWNORMAL = 1
STILL_ACTIVE = 259


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def wanted(name: str) -> bool:
    """Права нужны инструменту независимо от наличия службы защиты."""
    from trustseal import is_admin
    return name in TOOLS and not is_admin()


def command(args: list[str]) -> tuple[str, str]:
    """(программа, параметры): собранная — StretchBIT.exe, из исходников — python gui.py."""
    import subprocess
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(args)
    gui = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gui.py")
    return sys.executable, subprocess.list2cmdline([gui, *args])


def start(args: list[str]):
    """Запуск с правами. Дескриптор процесса или None (окно UAC закрыли «Нет»)."""
    if sys.platform != "win32":
        return None
    exe, params = command(args)
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb, info.lpFile, info.lpParameters = "runas", exe, params
    info.lpDirectory = os.getcwd()
    info.nShow = SW_SHOWNORMAL
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            return None
        raise OSError(err, f"не удалось запустить с правами администратора ({err})")
    return info.hProcess


def exit_code(handle) -> int | None:
    """Код завершения процесса или None, пока он работает."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    code = wintypes.DWORD()
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    if not k32.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == STILL_ACTIVE:
        return None
    k32.CloseHandle(handle)
    return code.value


def tool_arguments(name: str, tab: int = 0, *, allowed=(), action: str | None = None) -> list[str]:
    """Только известный инструмент, разрешения интерфейса и фиксированные действия."""
    if name not in TOOLS or any(cap not in CAPABILITIES for cap in allowed):
        raise ValueError("Неизвестный инструмент или разрешение")
    if action is not None and (name != "recovery" or action not in RECOVERY_ACTIONS):
        raise ValueError("Неизвестное действие инструмента")
    args = ["--tool", name] + (["--tab", str(int(tab))] if tab else [])
    args += [f"--allow-{cap}" for cap in allowed]
    if action:
        args += ["--action", action]
    return args


def open_tool(name: str, tab: int = 0, *, allowed=(), action: str | None = None) -> bool:
    """True — инструмент открыт процессом с правами; False — пользователь отказался."""
    args = tool_arguments(name, tab, allowed=allowed, action=action)
    handle = start(args)
    if handle is None:
        return False
    ctypes.WinDLL("kernel32").CloseHandle(handle)
    return True


# ---------- процесс с правами ----------
def _connect_service() -> None:
    from service import client, remote
    svc = client.connect()
    if svc is not None:
        remote.install(svc)


def run_tool(argv: list[str]) -> int:
    """--tool: одно окно инструмента; программа завершается, когда его закрыли."""
    name = argv[argv.index("--tool") + 1] if argv.index("--tool") + 1 < len(argv) else ""
    if name not in TOOLS:
        return 2
    from trustseal import is_admin
    if not is_admin():
        return 5  # не изображать успешное повышение прав при прямом запуске --tool
    tab = 0
    if "--tab" in argv:
        try:
            tab = int(argv[argv.index("--tab") + 1])
        except (ValueError, IndexError):
            tab = 0
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QTimer

    from ui import settings as cfg
    from ui import theme
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply_theme(app, cfg.get("general/theme"))
    _connect_service()
    from diag.log import get
    get("service").info("Инструмент с правами: %s", name)
    if name == "recovery":
        from recovery.window import RecoveryWindow
        window = RecoveryWindow()
        window.set_allowed("--allow-restore" in argv, "--allow-sfc" in argv,
                           "--allow-checks" in argv)
        window.tabs.setTabVisible(3, False)  # HKCU-ассоциации меняются в исходном GUI, не у UAC-админа
        window.show_tab(tab)
        action = argv[argv.index("--action") + 1] if "--action" in argv and \
            argv.index("--action") + 1 < len(argv) else None
        if "--action" in argv:
            capability = RECOVERY_ACTIONS.get(action)
            if capability is None or f"--allow-{capability}" not in argv:
                window.deleteLater()
                return 2
            if action.startswith("command:"):
                key = action.partition(":")[2]  # только фиксированный ключ COMMANDS
                QTimer.singleShot(0, lambda: window.start_command(key))
            else:
                callback = {"create": window.create_restore_point,
                            "enable-protection": window.enable_protection,
                            "check": window.run_system_check}[action]
                QTimer.singleShot(0, callback)  # подтверждения остаются в самом окне
    elif name == "autoruns":
        from autoruns.window import AutorunsWindow
        window = AutorunsWindow()
    elif name == "drivers":
        from toolbox.driverswindow import DriversWindow
        window = DriversWindow()
    else:
        from processmanager.window import ProcessWindow
        window = ProcessWindow()
        window.set_memory_allowed("--allow-memory" in argv)
    window.setWindowTitle(window.windowTitle() + " — с правами администратора")
    window.show()
    return app.exec()


def needs_admin(error: BaseException) -> bool:
    """Отмена не удалась из-за прав (окно без прав администратора)."""
    text = str(error)
    return isinstance(error, PermissionError) or getattr(error, "winerror", 0) == 5 or any(
        s in text for s in ("Access is denied", "Отказано в доступе", "0x80070005",
                            "прав администратора", "Нет прав"))


def run_undo(argv: list[str]) -> int:
    """--undo id [id...]: отменить записи журнала действий с правами и показать итог."""
    ids = [a for a in argv[argv.index("--undo") + 1:] if not a.startswith("--")]
    from PySide6.QtWidgets import QApplication, QMessageBox

    from ui import settings as cfg
    from ui import theme
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply_theme(app, cfg.get("general/theme"))
    _connect_service()
    import recovery.journal_page  # noqa: F401 — регистрирует откаты всех разделов
    from recovery import journal
    messages, errors = [], []
    for record_id in ids:
        try:
            try:
                messages.append(journal.undo(record_id))
            except journal.UnsignedRecord as unsigned:
                if QMessageBox.question(None, "Запись без подписи",
                                        "Запись журнала не подписана. Отменить её?\n\n" +
                                        str(unsigned)) != QMessageBox.StandardButton.Yes:
                    continue
                messages.append(journal.undo(record_id, unsigned_ok=True))
        except (ValueError, OSError) as e:
            errors.append(str(e))
    if errors:
        QMessageBox.warning(None, "Отмена действия", f"Отменено: {len(messages)}. Не удалось: "
                            f"{len(errors)}\n\n" + "\n".join(errors[:10]))
        return 1
    QMessageBox.information(None, "Отмена действия",
                            messages[0] if len(messages) == 1 else
                            f"Отменено действий: {len(messages)}")
    return 0
