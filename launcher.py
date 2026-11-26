"""Привилегированный координатор: только известные инструменты и сеанс проверенного клиента.

Установленная служба уже работает от SYSTEM. Администратор явно разрешает делегирование
при установке; GUI не получает её токен, доступ к произвольному запуску или чужому AppData.
"""
import os
import re
import subprocess
import sys
import threading

SID_RE = re.compile(r"S-\d+(?:-\d+){2,}", re.ASCII)
CLIENT = None


def arguments(request: dict) -> list[str]:
    """Не принимать exe, командную строку, путь конфигурации, SID или номер сеанса от GUI."""
    from service.elevate import CAPABILITIES, tool_arguments
    if set(request) - {"tool", "tab", "allowed", "action"}:
        raise ValueError("Неизвестные параметры launcher")
    tool, tab = request.get("tool"), request.get("tab", 0)
    allowed = request.get("allowed", [])
    if type(tab) is not int or not 0 <= tab <= 2:
        raise ValueError("Неизвестная вкладка")
    if not isinstance(allowed, list) or len(allowed) > len(CAPABILITIES) or \
            any(not isinstance(item, str) for item in allowed):
        raise ValueError("Неверные разрешения инструмента")
    if any(item not in CAPABILITIES for item in allowed):
        raise ValueError("Неизвестное разрешение инструмента")
    allowed = [item for item in CAPABILITIES if item in allowed]
    if not isinstance(tool, str):
        raise ValueError("Не указан инструмент")
    if request.get("action") is not None and not isinstance(request["action"], str):
        raise ValueError("Неверное действие")
    if tool != "recovery" and tab != 0:
        raise ValueError("У инструмента нет вкладок восстановления")
    return tool_arguments(tool, tab, allowed=allowed, action=request.get("action"))


class Coordinator:
    def __init__(self, spawn=None):
        self.spawn = spawn or self._spawn
        self._lock = threading.Lock()

    @staticmethod
    def _spawn(client, args: list[str]) -> int:
        from service import winapi
        if not getattr(sys, "frozen", False):
            raise PermissionError("Автоматический привилегированный launcher доступен в установленной сборке")
        import winacl
        safe, reason = winacl.admin_only(sys.executable)
        if not safe:
            raise PermissionError(f"Путь системного инструмента не защищён: {reason}")
        if client.session <= 0 or winapi.session_of(client.pid) != client.session:
            raise PermissionError("Нет подтверждённого пользовательского сеанса")
        if not SID_RE.fullmatch(client.sid or ""):
            raise PermissionError("Нет подтверждённого SID пользователя")
        args = ["--machine-tool", "--owner-sid", client.sid, *args]
        return winapi.launch_system_in_session(client.session, sys.executable,
                                               subprocess.list2cmdline(args), client.sid)

    def open(self, client, request: dict, permitted: bool) -> dict:
        if not permitted:
            raise PermissionError("Администратор не разрешил привилегированный launcher")
        args = arguments(request)
        if client.pid <= 0 or client.session <= 0 or not SID_RE.fullmatch(client.sid or ""):
            raise PermissionError("Неизвестный пользовательский сеанс")
        with self._lock:
            pid = self.spawn(client, args)
        return {"pid": pid, "system": True}


def configure(client) -> None:
    global CLIENT
    CLIENT = client


def try_open(tool: str, tab: int = 0, *, allowed=(), action=None) -> bool:
    """Без скрытого UAC: отказ службы оставляет инструмент в пользовательском режиме."""
    from ui import settings as cfg
    if CLIENT is None or not cfg.get("startup/privileged_launcher"):
        return False
    try:
        status = CLIENT.call("launcher.status", timeout=3.0)
        if not status.get("allowed"):
            return False
        CLIENT.call("launcher.open", timeout=10.0, tool=tool, tab=tab,
                    allowed=list(allowed), action=action)
        return True
    except (OSError, ValueError):
        from diag.log import get
        get("launcher").warning("Привилегированный launcher недоступен; автоматического UAC нет")
        return False


def machine_tool(argv: list[str]) -> int:
    """Точка входа дочернего инструмента SYSTEM; до импорта GUI и пользовательских настроек."""
    from service import protocol, scm, winapi
    from service.elevate import run_tool
    import psutil
    if winapi.current_sid() != "S-1-5-18":
        return 5
    import deployment
    if deployment.installed_with_service():
        info = scm.query(protocol.service_name())
        if not info or info["state"] != scm.RUNNING or psutil.Process().ppid() != info["pid"]:
            return 5
    else:
        import archive_runtime
        if not deployment.ready() or not archive_runtime.host_pid_valid(psutil.Process().ppid()):
            return 5
    try:
        index = argv.index("--owner-sid")
        sid = argv[index + 1]
        if not SID_RE.fullmatch(sid):
            return 2
        args = argv[1:index] + argv[index + 2:]
        args.remove("--machine-tool")
        # Повторно проверить whitelist, не полагаясь лишь на создание процесса службой.
        request = {"tool": args[args.index("--tool") + 1], "tab": 0, "allowed": []}
        from service.elevate import CAPABILITIES
        request["allowed"] = [item for item in CAPABILITIES if f"--allow-{item}" in args]
        if "--tab" in args:
            request["tab"] = int(args[args.index("--tab") + 1])
        if "--action" in args:
            request["action"] = args[args.index("--action") + 1]
        if arguments(request) != args:
            return 2
    except (ValueError, IndexError):
        return 2
    import userdata
    import privatefiles
    import trustseal
    # Корень службы уже закрыт ею при запуске: не переназначать ACL всего журнала
    # и рабочих баз при каждом открытии окна инструмента.
    if deployment.installed_with_service():
        root = trustseal.protected_dir() / "service" / "tools" / sid
    else:
        import archive_runtime
        root = archive_runtime.data_dir() / "tools" / sid
    privatefiles.protect_directory(root, system_only=True)
    userdata.set_root(root)
    session = winapi.session_of(os.getpid())
    with winapi.interactive_user_context(session, sid):
        return run_tool([argv[0], *args], system=True)
