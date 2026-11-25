"""Учётная запись GUI/автозапуска и принятие документов: без UAC и настоящих заданий."""
import subprocess
from pathlib import Path
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from diag import consent
from service import winapi
from ui import settings as cfg

ROOT = Path(__file__).resolve().parent.parent
SID = "S-1-5-21-111-222-333-1001"


def test_installer_acknowledgment_is_bound_to_displayed_documents(tmp_path, monkeypatch):
    import userdata
    calls = []
    for attr, name in (("LICENSE_FILE", "LICENSE"), ("EULA_FILE", "EULA.txt"),
                       ("PRIVACY_FILE", "PRIVACY.txt")):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        monkeypatch.setattr(consent, attr, path)
    monkeypatch.setattr(userdata, "protect_config", lambda: calls.append("protect"))
    monkeypatch.setattr(userdata, "migrate", lambda: calls.append("migrate"))
    from service import transfer
    monkeypatch.setattr(transfer, "window", lambda: calls.append("transfer"))
    monkeypatch.setattr(consent, "accept", lambda: calls.append("accept"))
    assert not consent.accept_from_installer("outdated")
    assert calls == []
    revision = consent.revision()
    assert consent.accept_from_installer(revision)
    assert calls == ["protect", "migrate", "transfer", "protect", "accept"]
    calls.clear()
    consent.PRIVACY_FILE.write_text("changed", encoding="utf-8")
    assert not consent.accept_from_installer(revision)
    assert calls == []


def test_installer_acceptance_does_not_bypass_acl_failure(monkeypatch):
    import userdata
    def fail():
        raise PermissionError("ACL")
    monkeypatch.setattr(userdata, "protect_config", fail)
    calls = []
    monkeypatch.setattr(consent, "accept", lambda: calls.append(True))
    with pytest.raises(PermissionError):
        consent.accept_from_installer(consent.revision())
    assert not calls


def test_installer_user_commands_run_as_original_user_and_silent_has_no_consent():
    script = (ROOT / "installer.iss").read_text(encoding="utf-8")
    for marker in ('Parameters: "--accept-installed-legal ', 'Parameters: "--set-autostart on"',
                   'Parameters: "--set-autostart off"', 'Description: "Запустить '):
        line = next(line for line in script.splitlines() if marker in line)
        assert "runasoriginaluser" in line
        if "--accept-installed-legal" in line:
            assert "skipifsilent" in line and "waituntilterminated" in line
    service = next(line for line in script.splitlines() if 'Parameters: "--service-install"' in line)
    assert "runasoriginaluser" not in service
    assert "LicenseFile={#LegalFile}" in script


def test_english_mit_is_first_and_russian_translation_is_below():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License\n")
    assert text.index("OUT OF OR IN CONNECTION WITH THE SOFTWARE") < text.index(
        "РУССКИЙ ПЕРЕВОД ЛИЦЕНЗИИ MIT")
    assert "применяется приведённый выше оригинальный английский текст" in text
    shown = consent.text()
    assert shown.index("MIT License") < shown.index("РУССКИЙ ПЕРЕВОД ЛИЦЕНЗИИ MIT")
    assert shown.index("РУССКИЙ ПЕРЕВОД ЛИЦЕНЗИИ MIT") < shown.index(
        "STRETCHBIT: ЛИЦЕНЗИЯ MIT И УСЛОВИЯ ДИАГНОСТИКИ")


def test_user_task_has_interactive_token_and_no_elevation(monkeypatch):
    monkeypatch.setattr(cfg, "_autostart_parts", lambda: (r"C:\Program Files\StretchBIT.exe",
                                                        "--autostart"))
    root = ET.fromstring(cfg.task_xml(SID))
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.findtext("t:Principals/t:Principal/t:UserId", namespaces=ns) == SID
    assert root.findtext("t:Triggers/t:LogonTrigger/t:UserId", namespaces=ns) == SID
    assert root.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=ns) == "LeastPrivilege"
    assert root.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns) == "InteractiveToken"


def test_task_names_are_per_sid_not_environment_username(monkeypatch):
    monkeypatch.setenv("USERNAME", "admin")
    monkeypatch.setenv("USERDOMAIN", "WrongAccount")
    monkeypatch.setattr(winapi, "current_sid", lambda: SID)
    first = cfg.user_task_name()
    assert first == "StretchBIT-" + SID
    monkeypatch.setattr(winapi, "current_sid", lambda: SID + "2")
    assert cfg.user_task_name() != first
    monkeypatch.setattr(winapi, "current_sid", lambda: "")
    with pytest.raises(OSError):
        cfg.user_task_name()


def test_task_creation_uses_current_token_sid_without_real_schtasks(monkeypatch):
    calls = []
    monkeypatch.setattr(winapi, "current_sid", lambda: SID)
    monkeypatch.setattr(cfg, "_remove_run_value", lambda: None)
    def run(*args):
        if "/Create" in args:
            xml = Path(args[args.index("/XML") + 1]).read_text(encoding="utf-16")
            calls.append((args, xml))
        return SimpleNamespace(returncode=1 if "/Query" in args else 0, stdout="", stderr="")
    monkeypatch.setattr(cfg, "_schtasks", run)
    cfg.set_autostart(True)
    assert len(calls) == 1
    args, xml = calls[0]
    assert args[args.index("/TN") + 1] == "StretchBIT-" + SID
    assert SID in xml and "LeastPrivilege" in xml and "HighestAvailable" not in xml


@pytest.mark.parametrize("change", ["none", "other-user", "elevated", "wrong-mode", "malformed"])
def test_task_current_checks_identity_privilege_and_mode(monkeypatch, change):
    monkeypatch.setattr(winapi, "current_sid", lambda: SID)
    monkeypatch.setattr(cfg, "_autostart_parts", lambda: (r"C:\SBIT\StretchBIT.exe", "--autostart"))
    xml = cfg.task_xml(SID)
    if change == "other-user":
        xml = xml.replace(SID, SID + "2")
    elif change == "elevated":
        xml = xml.replace("LeastPrivilege", "HighestAvailable")
    elif change == "wrong-mode":
        xml = xml.replace("--autostart", "--recover-network")
    elif change == "malformed":
        xml = "not xml"
    monkeypatch.setattr(cfg, "_schtasks",
                        lambda *args: subprocess.CompletedProcess(args, 0, xml, ""))
    assert cfg.autostart_current() is (change == "none")


def test_original_user_receipt_does_not_depend_on_gui_launch_checkbox():
    script = (ROOT / "installer.iss").read_text(encoding="utf-8")
    receipt = next(line for line in script.splitlines() if 'Parameters: "--accept-installed-legal '
                   in line)
    assert "postinstall" not in receipt and "Tasks:" not in receipt
    gui = (ROOT / "gui.py").read_text(encoding="utf-8")
    assert gui.index('if "--accept-installed-legal" in sys.argv:') < gui.index(
        "from diag import log as diag_log")


def test_uninstall_removes_user_tasks_only_for_its_own_install(monkeypatch):
    monkeypatch.setattr(cfg, "_autostart_parts", lambda: (r"C:\SBIT\StretchBIT.exe", "--autostart"))
    own_xml = cfg.task_xml(SID)
    other_xml = own_xml.replace(r"C:\SBIT\StretchBIT.exe", r"C:\Other\StretchBIT.exe")
    names = ["StretchBIT-" + SID, "StretchBIT-" + SID + "2", "Unrelated"]
    deleted = []
    def run(*args):
        if "/FO" in args:
            return SimpleNamespace(returncode=0, stdout="\n".join(
                f'"\\{name}","time","status"' for name in names))
        if "/Delete" in args:
            deleted.append(args[args.index("/TN") + 1])
            return SimpleNamespace(returncode=0)
        name = args[args.index("/TN") + 1]
        return SimpleNamespace(returncode=0, stdout=own_xml if name == names[0] else other_xml)
    monkeypatch.setattr(cfg, "_schtasks", run)
    cfg.remove_install_autostart()
    assert deleted == [names[0]]
