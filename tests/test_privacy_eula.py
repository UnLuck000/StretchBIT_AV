"""EULA, диагностические сводки и заглушка: без настоящих крашей/отправки/процессов."""
import hashlib
import json
import logging
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from diag import anon, consent, support
from ui import settings as cfg


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_eula_acceptance_is_bound_to_full_text(tmp_path, monkeypatch):
    path = tmp_path / "EULA.txt"
    path.write_text("first", encoding="utf-8")
    monkeypatch.setattr(consent, "EULA_FILE", path)
    cfg.set_("privacy/eula_revision", "")
    assert not consent.accepted()
    consent.accept()
    assert consent.accepted()
    path.write_text("second", encoding="utf-8")
    assert not consent.accepted()


def test_license_and_privacy_changes_require_new_acknowledgment(tmp_path, monkeypatch):
    for name, attr in (("LICENSE", "LICENSE_FILE"), ("EULA.txt", "EULA_FILE"),
                       ("PRIVACY.txt", "PRIVACY_FILE")):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        monkeypatch.setattr(consent, attr, path)
    consent.accept()
    assert consent.accepted()
    consent.PRIVACY_FILE.write_text("new policy", encoding="utf-8")
    assert not consent.accepted()
    consent.accept()
    consent.LICENSE_FILE.write_text("changed license", encoding="utf-8")
    assert not consent.accepted()


def test_mit_notice_and_permissions_are_not_overridden_by_eula():
    root = Path(__file__).resolve().parent.parent
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    eula = (root / "docs" / "EULA.txt").read_text(encoding="utf-8")
    assert "Copyright (c) 2026 VovanNBit" in license_text
    assert "sublicense, and/or sell" in license_text
    assert "included in all" in license_text
    assert "не требуется" in eula
    assert "При расхождении действует MIT" in eula
    assert "не являются дополнительными" in eula
    assert "Принятие этого соглашения включает согласие на передачу" not in eula
    spec = (root / "StretchBIT.spec").read_text(encoding="utf-8")
    assert 'ROOT / "LICENSE"' in spec and 'ROOT / "docs" / "PRIVACY.txt"' in spec


def test_public_author_is_consistent_and_documents_have_no_email():
    import re
    import appinfo
    root = Path(__file__).resolve().parent.parent
    assert appinfo.AUTHOR == "VovanNBit"
    assert f"Copyright (c) 2026 {appinfo.AUTHOR}" in (root / "LICENSE").read_text(encoding="utf-8")
    for name in ("README.md", "docs/EULA.txt", "docs/PRIVACY.txt"):
        text = (root / name).read_text(encoding="utf-8")
        assert appinfo.AUTHOR in text
        assert re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text) is None


def test_eula_requires_an_explicit_checkbox(app):
    from ui.eula import EulaDialog
    dialog = EulaDialog()
    assert not dialog.accept_button.isEnabled()
    assert "MIT License" in dialog.body.toPlainText()
    assert "ПОЛИТИКА КОНФИДЕНЦИАЛЬНОСТИ" in dialog.body.toPlainText()
    assert "обязательную" not in dialog.checkbox.text()
    dialog.checkbox.setChecked(True)
    assert dialog.accept_button.isEnabled()


def test_eula_refusal_does_not_save_consent(app, monkeypatch):
    from ui import eula
    monkeypatch.setattr(consent, "accepted", lambda: False)
    calls = []
    monkeypatch.setattr(consent, "accept", lambda: calls.append("accepted"))
    monkeypatch.setattr(eula, "EulaDialog", lambda parent: SimpleNamespace(
        exec=lambda: QDialog.DialogCode.Rejected, checkbox=SimpleNamespace(isChecked=lambda: False)))
    assert not eula.ensure_accepted() and calls == []


def test_missing_eula_blocks_start_with_a_message(app, tmp_path, monkeypatch):
    from ui import eula
    monkeypatch.setattr(consent, "EULA_FILE", tmp_path / "missing.txt")
    shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args: shown.append(args))
    assert not eula.ensure_accepted() and len(shown) == 1


def test_reset_does_not_revoke_mandatory_eula():
    cfg.set_("privacy/eula_revision", "accepted-test")
    cfg.reset()
    assert cfg.get("privacy/eula_revision") == "accepted-test"
    cfg.set_("privacy/eula_revision", "")  # не влияет на другие проверки сторожа


def test_eula_guard_precedes_registration_and_main_window():
    root = Path(__file__).resolve().parent.parent
    gui = (root / "gui.py").read_text(encoding="utf-8")
    main = gui[gui.index('if __name__ == "__main__":'):]
    assert main.index("if not ensure_accepted():") < main.index("elevate_on_start()")
    assert main.index("if not ensure_accepted():") < main.index("service_client =")
    assert main.index("if not ensure_accepted():") < main.index("window = MainWindow()")
    spec = (root / "StretchBIT.spec").read_text(encoding="utf-8")
    assert '"EULA.txt"), "docs"' in spec
    assert "LicenseFile=LICENSE" in (root / "installer.iss").read_text(encoding="utf-8")


def test_known_file_name_replaced_with_content_hash(tmp_path):
    anon.reset()
    path = tmp_path / "Личный договор.docx"
    path.write_bytes(b"harmless test document")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    anon.register_file(path, digest)
    text = anon.scrub(f'Ошибка файла "{path}"')
    assert "Личный" not in text and str(path) not in text
    assert "SHA256:" + digest in text
    assert hashlib.sha256(str(path).encode()).hexdigest() not in text
    assert anon.known_file_hashes(str(path)) == [digest]
    anon.reset()


def test_unknown_file_name_is_hidden_without_fake_hash():
    anon.reset()
    text = anon.scrub(r'C:\Users\Ivan\Desktop\СекретныйДоговор.docx')
    assert "СекретныйДоговор" not in text
    assert anon.FILE_UNKNOWN in text and "SHA256:" not in text
    assert "secret_no_extension" not in anon.scrub(r"C:\private\secret_no_extension")
    assert "Личное имя" not in anon.scrub(r'"C:\private\Личное имя без расширения"')


def test_arbitrary_hash_in_message_is_not_a_file_digest():
    anon.reset()
    assert anon.known_file_hashes("SHA256:" + "a" * 64) == []


def test_ambiguous_basenames_do_not_choose_an_arbitrary_hash():
    anon.reset()
    anon.register_file(r"C:\one\test.exe", "a" * 64)
    anon.register_file(r"D:\two\test.exe", "b" * 64)
    assert anon.scrub("test.exe") == anon.FILE_UNKNOWN
    assert anon.scrub(r"C:\one\test.exe") == "SHA256:" + "a" * 64
    anon.reset()


def test_summary_never_copies_free_text_or_credentials():
    rec = logging.LogRecord("sbit.vpn", logging.ERROR, "secret.py", 9,
                            "user=Ivan password=secret url=https://private.example/?token=secret",
                            (), None)
    data = support.summary(rec)
    assert data["component"] == "vpn" and data["level"] == "ERROR"
    text = json.dumps(data)
    for secret in ("Ivan", "secret", "private.example", "secret.py", "password", "token"):
        assert secret not in text
    data.update({"message": "secret", "path": "secret", "sha256": ["not a hash", "a" * 64]})
    safe = support.valid_record(data)
    assert "message" not in safe and "path" not in safe and safe["sha256"] == ["a" * 64]


def test_local_report_allowlists_sources_and_fields(tmp_path, monkeypatch):
    import datadirs
    folder = tmp_path / "logs"
    folder.mkdir()
    monkeypatch.setattr(datadirs, "LOGS", folder)
    monkeypatch.setattr(datadirs, "APP_CACHE", tmp_path / "program" / "cache")
    event = {"time": 1, "component": "app", "level": "ERROR", "message": "private",
             "sha256": ["b" * 64]}
    (folder / support.FILES["essential"]).write_text(
        json.dumps(event) + "\n" + json.dumps({**event, "component": "vpn"}) + "\n",
        encoding="utf-8")
    (folder / "app.log").write_text("password=private secret token", encoding="utf-8")
    (folder / "vpn-client.log").write_text("vpn private", encoding="utf-8")
    out = tmp_path / "report.zip"
    manifest = support.collect(out, "crash")
    assert manifest["events"] == 1
    with zipfile.ZipFile(out) as z:
        assert set(z.namelist()) == {"manifest.json", "events.jsonl", "crash.json"}
        for name in z.namelist():
            assert b"private" not in z.read(name)
        assert b"b" * 64 in z.read("events.jsonl")
    cfg.set_("support/extra", False)
    with pytest.raises(PermissionError):
        support.collect(tmp_path / "extra.zip", "extra")
    assert not (tmp_path / "extra.zip").exists()


def test_safe_crash_report_can_be_imported_with_repeated_events(tmp_path, monkeypatch):
    import datadirs
    from tools import import_reports
    folder = tmp_path / "logs"
    folder.mkdir()
    monkeypatch.setattr(datadirs, "LOGS", folder)
    monkeypatch.setattr(datadirs, "APP_CACHE", tmp_path / "program" / "cache")
    row = json.dumps({"time": 1, "component": "crash", "level": "CRITICAL"}) + "\n"
    (folder / support.FILES["essential"]).write_text(row * 5000, encoding="utf-8")
    report = tmp_path / "crash.zip"
    support.collect(report, "crash")
    imported = import_reports.import_zip(report, tmp_path / "imported")
    info = import_reports.summary(imported)
    assert "технических событий: 5000" in info and "crash-report:" in info


def test_stub_does_not_queue_or_call_network(tmp_path, monkeypatch):
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("заглушка не должна открывать сеть"))
    assert not support.SENDING_AVAILABLE
    assert "Ничего не отправлено" in support.request_send("essential")
    assert not list(tmp_path.iterdir())


def test_support_controls_are_admin_only_and_disabled(app):
    from ui.pages import SettingsPage
    page = SettingsPage()
    assert page.group_support.isHidden()
    page.set_debug(True)
    assert not page.group_support.isHidden()
    assert not page.chk_support_extra.isEnabled()
    assert not page.btn_support_send.isEnabled()
    assert not page.btn_support_vpn.isEnabled()
    assert page.btn_support_vpn.isHidden()
    assert cfg.secure("support/extra") and cfg.secure("support/vpn")


def test_extra_consent_explained_before_enabling(app, monkeypatch):
    from ui.pages import SettingsPage
    cfg.set_("support/extra", False)
    page = SettingsPage()
    monkeypatch.setattr(support, "SENDING_AVAILABLE", True)  # только проверка будущего обработчика
    seen = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda parent, title, text, *a: seen.append(text) or QMessageBox.StandardButton.No)
    page._support_toggle(True)
    assert support.EXTRA_DETAILS in seen and not cfg.get("support/extra")
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Yes)
    page._support_toggle(True)
    assert cfg.get("support/extra") and not page.btn_support_vpn.isHidden()
    assert not cfg.get("support/vpn")  # отдельное согласие не следует из общего
    page._support_toggle(False)
    assert not cfg.get("support/extra") and not cfg.get("support/vpn")


def test_watchdog_offers_report_before_recovery_without_restart(monkeypatch):
    import selfguard
    order = []
    monkeypatch.setattr(selfguard, "_wait", lambda pid: None)
    monkeypatch.setattr(selfguard.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(selfguard, "abnormal_exit", lambda pid: True)
    monkeypatch.setattr(selfguard, "_forbidden", lambda: False)
    monkeypatch.setattr(selfguard, "_installer_running", lambda: False)
    monkeypatch.setattr(selfguard, "_offer_crash_report", lambda pid: order.append("report"))
    monkeypatch.setattr(selfguard, "recover_network", lambda: order.append("network") or [])
    selfguard.watch(123, restart=False)
    assert order == ["report", "network"]
    order.clear()
    monkeypatch.setattr(selfguard, "_forbidden", lambda: True)
    selfguard.watch(123, restart=False)
    assert order == []


def test_watchdog_report_is_a_separate_process(monkeypatch):
    import selfguard
    calls = []
    monkeypatch.setattr(consent, "accepted", lambda: True)
    monkeypatch.setattr(selfguard.subprocess, "Popen", lambda args, **kwargs: calls.append(args))
    selfguard._offer_crash_report(123)
    assert len(calls) == 1 and "--crash-report" in calls[0]
    assert "--autostart" not in calls[0]


def test_watchdog_does_not_offer_report_if_wait_failed(monkeypatch):
    import selfguard
    monkeypatch.setattr(selfguard, "_wait", lambda pid: False)
    monkeypatch.setattr(selfguard, "_offer_crash_report",
                        lambda pid: pytest.fail("процесс не подтверждён завершённым"))
    selfguard.watch(123, restart=False)


def test_global_sha256_exclusion_without_source_file(tmp_path, monkeypatch):
    from scanner import overrides
    from diag import edition
    monkeypatch.setattr(overrides, "RELEASE_FILE", tmp_path / "release_overrides.json")
    monkeypatch.setattr(edition, "is_test", lambda: True)
    digest = "ab" * 32
    assert overrides.exclude_sha256(digest.upper())
    data = overrides.read_file(overrides.RELEASE_FILE)["files"][digest]
    assert set(data["layers"]) == {"hash", "yara"} and data["path"] == ""
    assert not overrides.exclude_sha256(digest)
    with pytest.raises(ValueError):
        overrides.exclude_sha256("../bad")
    monkeypatch.setattr(edition, "is_test", lambda: False)
    with pytest.raises(PermissionError):
        overrides.exclude_sha256("cd" * 32)


def test_vpn_log_does_not_leak_to_app_or_essential_log(tmp_path, monkeypatch):
    from diag import log
    old_handlers = list(log.log.handlers)
    log.log.handlers = []
    monkeypatch.setattr(log, "_ready", False)
    monkeypatch.setattr(log, "LOG_DIR", tmp_path)
    monkeypatch.setattr(log, "LOG_FILE", tmp_path / "app.log")
    try:
        log.setup(worker=True)
        log.get("app").error("application-marker")
        log.get("vpn").error("vpn-marker")
        assert "vpn-marker" not in (tmp_path / "app.log").read_text(encoding="utf-8")
        assert "vpn-marker" in (tmp_path / "vpn-client.log").read_text(encoding="utf-8")
        assert not any(r["component"] == "vpn" for r in support.records(tmp_path, "essential"))
        assert support.records(tmp_path, "vpn")[0]["component"] == "vpn"
    finally:
        for handler in log.log.handlers:
            handler.close()
        log.log.handlers = old_handlers


def test_old_local_bundle_excludes_vpn_by_default(tmp_path, monkeypatch):
    from diag import bundle, edition
    logs = tmp_path / "logs"
    logs.mkdir()
    for name in ("app.log", "vpn-client.log", "vpn-client.log.1", "vpn-events.jsonl"):
        (logs / name).write_text("local", encoding="utf-8")
    monkeypatch.setattr(bundle, "LOGS", logs)
    monkeypatch.setattr(bundle, "SERVICE_LOGS", tmp_path / "absent")
    monkeypatch.setattr(bundle, "_snapshot", lambda: "")
    monkeypatch.setattr(bundle, "windows_info", lambda: {})
    monkeypatch.setattr(edition, "is_test", lambda: False)
    target = tmp_path / "local.zip"
    bundle.collect(target)
    with zipfile.ZipFile(target) as z:
        assert "logs/app.log" in z.namelist()
        assert not any("vpn-" in name for name in z.namelist())


def test_zip_contains_readable_eula_next_to_exe(tmp_path, monkeypatch):
    import build_release
    root = tmp_path / "project"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "EULA.txt").write_text("TEST EULA", encoding="utf-8")
    (root / "docs" / "PRIVACY.txt").write_text("TEST PRIVACY", encoding="utf-8")
    (root / "LICENSE").write_text("TEST MIT", encoding="utf-8")
    folder = root / "dist" / "StretchBIT"
    folder.mkdir(parents=True)
    (folder / "StretchBIT.exe").write_bytes(b"not executable")
    monkeypatch.setattr(build_release, "ROOT", root)
    archive = build_release.make_zip(folder)
    with zipfile.ZipFile(archive) as z:
        assert z.read("StretchBIT/EULA.txt").decode("utf-8") == "TEST EULA"
        assert z.read("StretchBIT/LICENSE").decode("utf-8") == "TEST MIT"
        assert z.read("StretchBIT/PRIVACY.txt").decode("utf-8") == "TEST PRIVACY"
