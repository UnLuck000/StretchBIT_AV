"""Регрессии аудита 1.2.2: только временные файлы, без сети и настоящих процессов."""
import hashlib
import json
import socket
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import ed25519
import public_http
import quarantine
import updater
from recovery import threatlog
from scanner import engine, overrides, yara_engine

ROOT = Path(__file__).resolve().parent.parent


def test_benign_png_cannot_trigger_automatic_action(tmp_path, monkeypatch):
    import yara
    monkeypatch.setattr(overrides, "RELEASE_FILE", ROOT / "signatures/release_overrides.json")
    overrides._cache = None
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    png += chunk(b"tEXt", b"Comment\0PHP tutorial: <?php echo 'A harmless educational example';")
    png += chunk(b"IDAT", zlib.compress(b"\0\xff\xff\xff")) + chunk(b"IEND", b"")
    path = tmp_path / "tutorial.png"
    path.write_bytes(png)
    rules = yara.compile(filepath=str(ROOT / "signatures/rules/community/bartblaze/Webshell_in_image.yar"))
    reason = engine.check_file(path, set(), rules, heuristics=False, use_cache=False)
    assert reason.startswith(engine.CHECK_PREFIX)
    assert reason.sha256 == hashlib.sha256(png).hexdigest()
    assert not engine.automatic_action(reason)


def test_real_tools_document_is_not_a_threat(tmp_path, monkeypatch):
    import yara
    monkeypatch.setattr(overrides, "RELEASE_FILE", ROOT / "signatures/release_overrides.json")
    overrides._cache = None
    path = ROOT / "signatures/rules/community/signature-base/thor-hacktools.yar"
    source, external, _, error = yara_engine.fix_rules_source(path.read_text(encoding="utf-8"))
    assert source is not None, error
    rules = yara.compile(sources={"0_thor-hacktools": source}, externals=external)
    data = b"Basic PortScanner\nNow scanning port:\n" + (
        "\0ASPACK.EXE\0CLOSEDFOLDER\0ASPack compressor\0").encode("utf-16-le")
    document = tmp_path / "documentation.dat"
    document.write_bytes(data)
    reason = engine.check_file(document, set(), rules, heuristics=False, use_cache=False)
    assert "ASPack_ASPACK" in reason
    assert reason.startswith(engine.WEAK_PREFIX)
    assert not engine.automatic_action(reason)
    assert not engine.automatic_action("неизвестная причина")


def test_quarantine_checks_scanned_hash_before_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    path = tmp_path / "replaced.bin"
    path.write_bytes(b"replacement")
    actions = []
    with pytest.raises(OSError, match="изменилось"):
        quarantine.quarantine_file(path, "YARA: Test",
                                   expected_sha256=hashlib.sha256(b"scanned").hexdigest(),
                                   before_delete=lambda: actions.append("kill"))
    assert path.read_bytes() == b"replacement"
    assert not actions
    assert not list((tmp_path / "q").glob("*.quar"))
    assert not list((tmp_path / "q").glob("*.json"))


def test_autodetection_rechecked_on_locked_content(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    path = tmp_path / "benign.bin"
    path.write_bytes(b"harmless")
    digest = hashlib.sha256(b"harmless").hexdigest()
    effects = []
    # Хэш мог быть посчитан до другой задачи YARA: совпадение хэша само по себе
    # не подтверждает устаревший/смешанный вердикт.
    with pytest.raises(OSError, match="не подтвердила"):
        quarantine.quarantine_file(
            path, "YARA: Stale", expected_sha256=digest,
            before_delete=lambda: effects.append("kill"),
            verify=lambda fin: engine.confirm_automatic(path, fin, set(), None))
    assert path.exists() and not effects
    # Положительный случай: тестовый хэш в подставной базе, без запуска файла.
    qid = quarantine.quarantine_file(
        path, "hash match", expected_sha256=digest,
        before_delete=lambda: effects.append("kill"),
        verify=lambda fin: engine.confirm_automatic(path, fin, {digest}, None))
    assert not path.exists() and effects == ["kill"]
    assert quarantine._read_meta(qid)["sha256"] == digest


@pytest.mark.skipif(sys.platform != "win32", reason="Windows HANDLE")
def test_file_key_uses_os_handle(tmp_path):
    path = tmp_path / "identity"
    path.write_bytes(b"safe")
    with path.open("rb") as stream:
        assert quarantine._file_key(stream) is not None
        assert quarantine._same_file(path, quarantine._file_key(stream))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows HANDLE")
def test_quarantine_locks_writes_until_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    path = tmp_path / "identity"
    path.write_bytes(b"original")
    def callback():
        with pytest.raises(PermissionError):
            path.write_bytes(b"replacement")
        with pytest.raises(PermissionError):
            path.rename(tmp_path / "renamed")
    qid = quarantine.quarantine_file(path, "test", before_delete=callback,
                                     expected_sha256=hashlib.sha256(b"original").hexdigest())
    assert not path.exists()
    assert quarantine._read_meta(qid)["sha256"] == hashlib.sha256(b"original").hexdigest()


def test_sid_filter_does_not_reintroduce_foreign_quarantine(tmp_path, monkeypatch):
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "threats.json")
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    records = [{"id": "foreign", "sid": "B", "status": "quarantined", "qid": "abc",
                "path": "private", "text": "private"}]
    monkeypatch.setattr(threatlog, "_read", lambda: [dict(r) for r in records])
    monkeypatch.setattr(quarantine, "list_quarantine", lambda **kw: [
        {"id": "abc", "sid": "B", "status": "quarantined", "original_path": "private",
         "quarantined_at": "2026-01-01T00:00:00"},
        {"id": "legacy", "status": "quarantined", "original_path": "old-private",
         "quarantined_at": "2026-01-01T00:00:00"}])
    assert threatlog.merged(True, sid="A") == []
    assert len(threatlog.merged(True)) == 2


def test_threat_deduplication_separates_users(tmp_path, monkeypatch):
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "threats.json")
    a = threatlog.add("same", "suspicious", "same", sid="A")
    b = threatlog.add("same", "suspicious", "same", sid="B")
    assert a != b
    assert a == threatlog.add("same", "suspicious", "same", sid="A")


def test_legacy_record_is_not_implicitly_public(tmp_path, monkeypatch):
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "threats.json")
    monkeypatch.setattr(quarantine, "list_quarantine", lambda **kw: [])
    threatlog._write([{"id": "old", "status": "found", "text": "old private", "path": "private"}])
    assert threatlog.merged(True, sid="A") == []
    machine = threatlog.add("machine", "suspicious", "common")
    assert [r["id"] for r in threatlog.merged(True, sid="A")] == [machine]


@pytest.mark.parametrize("url", [
    "http://127.1/", "http://2130706433/", "http://0x7f000001/",
    "http://localhost./", "http://[::ffff:127.0.0.1]/", "http://[::1]/",
    "http://192.168.0.1/", "http://user@public.example/", "file:///C:/file"])
def test_block_local_initial_urls_and_redirects(url):
    assert public_http.blocked_url(url)


def test_dns_checked_at_connect_no_second_lookup(monkeypatch):
    calls, connected = [], []
    def lookup(*args, **kw):
        calls.append(args)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    class Sock:
        def settimeout(self, timeout):
            pass
        def connect(self, address):
            connected.append(address)
        def getpeername(self):
            return ("8.8.8.8", 443)
        def close(self):
            pass
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(socket, "socket", lambda *a: Sock())
    public_http.public_connection(("public.example", 443), timeout=1)
    assert len(calls) == 1 and connected == [("8.8.8.8", 443)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(OSError, match="непубличный"):
        public_http.public_connection(("public.example", 443))
    assert len(connected) == 1


def test_https_opener_keeps_certificate_validation():
    conn = public_http._HTTPSConnection("example.com")
    import ssl
    assert conn._context.verify_mode == ssl.CERT_REQUIRED
    assert conn._context.check_hostname


def test_mirror_requires_a_pinned_public_key(monkeypatch):
    monkeypatch.setattr(updater, "FEEDS_PUBLIC_KEY", "")
    with pytest.raises(updater.MirrorError, match="публичный ключ"):
        updater._verify_feeds_signature({})


def test_ed25519_rejects_noncanonical_points_and_scalar():
    secret = bytes(range(32))
    public = ed25519.public_key(secret)
    sig = ed25519.sign(secret, b"test")
    altered = sig[:32] + (int.from_bytes(sig[32:], "little") + ed25519.L).to_bytes(32, "little")
    assert not ed25519.verify(public, b"test", altered)
    for point in [b"\0" * 32, b"\x01" + b"\0" * 31,
                  ed25519.p.to_bytes(32, "little"), b"\x01" + b"\0" * 30 + b"\x80"]:
        assert not ed25519.verify(point, b"test", sig)
        assert not ed25519.verify(public, b"test", point + sig[32:])
    with pytest.raises(ValueError):
        ed25519.sign(b"", b"test")


def test_virusshare_get_failure_uses_mirror(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path)
    monkeypatch.setattr(updater, "_virusshare_last", lambda hint: 1)
    monkeypatch.setattr(updater, "_download", lambda *a, **kw: (_ for _ in ()).throw(TimeoutError()))
    calls = []
    monkeypatch.setattr(updater, "mirror_file",
                        lambda key: calls.append(key) or b"a" * 32 + b"\n")
    assert updater.update_virusshare(files=1) is True
    assert calls == ["virusshare_00001"]


def test_incomplete_virusshare_mirror_is_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path)
    monkeypatch.setattr(updater, "_mirror_manifest", lambda: {"files": {"virusshare_00001": {}}})
    monkeypatch.setattr(updater, "mirror_file", lambda key: b"a" * 32 + b"\n")
    assert updater._virusshare_from_mirror(2, None, None) == "partial"


def test_manifest_zip_limit_applies_before_json(tmp_path, monkeypatch):
    from tools import import_reports
    monkeypatch.setattr(import_reports, "MAX_MANIFEST", 16)
    archive = tmp_path / "report.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps({"padding": "x" * 100}))
    with pytest.raises(ValueError, match="manifest.json"):
        import_reports.import_zip(archive, tmp_path / "reports")
    assert not (tmp_path / "reports").exists()


def test_update_in_tray_does_not_mark_changelog_shown(monkeypatch):
    from mainwindow.databases import DatabasesMixin
    from ui import settings as cfg
    import updatecheck
    saved = {"update/shown": "", "update/skipped": ""}
    monkeypatch.setattr(cfg, "get", lambda key: saved[key])
    monkeypatch.setattr(cfg, "set_", lambda key, value: saved.update({key: value}))
    monkeypatch.setattr(updatecheck, "newer", lambda version: True)
    notices = []
    window = SimpleNamespace(isHidden=lambda: True, _notify_update=notices.append)
    release = SimpleNamespace(version="99.0", notes="test")
    DatabasesMixin._on_release_found(window, release, "")
    DatabasesMixin._on_release_found(window, release, "")
    assert len(notices) == 1 and saved["update/shown"] == ""
    # Новый экземпляр после рестарта снова предложит обновление.
    DatabasesMixin._on_release_found(
        SimpleNamespace(isHidden=lambda: True, _notify_update=notices.append), release, "")
    assert len(notices) == 2


def test_autostart_setting_is_rolled_back_on_task_error(monkeypatch):
    from ui import pages, settings as cfg
    state = {"startup/autostart": False}
    checked = []
    monkeypatch.setattr(cfg, "get", lambda key: state[key])
    monkeypatch.setattr(cfg, "set_", lambda key, value: state.update({key: value}))
    monkeypatch.setattr(cfg, "set_autostart", lambda enabled: (_ for _ in ()).throw(OSError("denied")))
    monkeypatch.setattr(pages.QMessageBox, "warning", lambda *args: None)
    widget = SimpleNamespace(blockSignals=lambda value: None, setChecked=checked.append)
    pages.SettingsPage._on_autostart(SimpleNamespace(chk_autostart=widget), True)
    assert not state["startup/autostart"] and checked == [False]


def test_installer_registers_recovery_even_when_gui_autostart_off():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "--session-start" in text
    assert 'ValueName: "GuiEnabled"; ValueData: "0"' in text
    assert "Tasks: not autostart" in text
