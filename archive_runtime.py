"""Ядро архивной копии: задача SYSTEM вместо регистрации службы SCM."""
import os
import subprocess
import sys
import threading
from pathlib import Path
import xml.etree.ElementTree as ET

import deployment


def data_dir(root: Path | None = None) -> Path:
    import trustseal
    return trustseal.protected_dir() / "archive" / deployment.root_id(root)


def server_check(pid: int) -> bool:
    """В клиенте SID дополнительно подтверждается владельцем самого pipe handle."""
    from service import winapi
    image = winapi.process_image(pid)
    return bool(image) and os.path.normcase(os.path.abspath(image)) == \
        os.path.normcase(os.path.abspath(sys.executable))


def host_pid_valid(pid: int) -> bool:
    from service import winapi
    return server_check(pid) and winapi.process_sid(pid) == "S-1-5-18"


def task_xml(root: Path) -> str:
    from xml.sax.saxutils import escape
    executable = escape(str(root / "StretchBIT.exe"))
    folder = escape(str(root))
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>StretchBIT: защищённый launcher архивной копии</Description>
    <SecurityDescriptor>O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;IU)</SecurityDescriptor></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType>
    <RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable></Settings>
  <Actions Context="System"><Exec><Command>{executable}</Command><Arguments>--archive-host</Arguments>
    <WorkingDirectory>{folder}</WorkingDirectory></Exec></Actions>
</Task>
"""


def task_matches(text: str, root: Path) -> bool:
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    try:
        task = ET.fromstring(text)
    except ET.ParseError:
        return False
    def value(path):
        return task.findtext(path, "", ns)
    return (value("t:Principals/t:Principal/t:UserId") == "S-1-5-18"
            and value("t:Principals/t:Principal/t:RunLevel") == "HighestAvailable"
            and value("t:Actions/t:Exec/t:Command").casefold() ==
            str(root / "StretchBIT.exe").casefold()
            and value("t:Actions/t:Exec/t:Arguments") == "--archive-host"
            and value("t:Actions/t:Exec/t:WorkingDirectory").casefold() == str(root).casefold()
            and task.find("t:Triggers/t:BootTrigger", ns) is not None)


def register_task(root: Path, state: Path) -> None:
    import programfiles
    from service import winapi
    xml = state / "launcher-task.xml"
    if xml.exists():
        # Состояние уже в закрытой папке; не открывать временный XML в AppData user/admin.
        xml.unlink()
    programfiles.write_new(xml, task_xml(root).encode("utf-16"))
    command = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "schtasks.exe")
    result = subprocess.run([command, "/Create", "/TN", deployment.task_name(root),
                             "/XML", str(xml), "/F"], capture_output=True,
                            creationflags=0x08000000)
    if result.returncode:
        raise winapi.os_error(text="не удалось создать задачу SYSTEM для архивной копии")
    result = subprocess.run([command, "/Run", "/TN", deployment.task_name(root)],
                            capture_output=True, creationflags=0x08000000)
    if result.returncode:
        raise OSError("Задача создана, но launcher не запущен")


def conflicting_service() -> bool:
    """Не включать параллельно независимые ETW/TUN-защиты двух копий приложения."""
    from service import scm
    return any((info := scm.query(name)) and info["state"] in (scm.RUNNING, scm.START_PENDING)
               for name in ("StretchBITService", "StretchBITService-test"))


def main(argv: list[str]) -> int:
    from service import winapi
    import winacl
    root = deployment.package_root()
    if argv[1:] != ["--archive-host"] or not getattr(sys, "frozen", False) or \
            deployment.installed_with_service(root) or winapi.current_sid() != "S-1-5-18":
        return 5
    if not deployment.ready(root) or not root.is_relative_to(deployment.program_files()) or \
            not winacl.admin_only(sys.executable)[0]:
        return 5
    if conflicting_service():
        return 3
    import userdata
    folder = data_dir(root)
    import privatefiles
    privatefiles.protect_directory(folder, recursive=True, system_only=True)
    userdata.set_root(folder)
    from diag import log
    log.LOG_FILE = folder / "archive-host.log"
    log.setup(worker=True)
    from service.core import ServiceCore
    core = ServiceCore(folder)
    try:
        core.start(pipe=False)
        core.start_pipe(deployment.pipe_name(root))
        threading.Event().wait()
    finally:
        core.stop()
    return 0
