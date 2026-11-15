"""Исправления по журналам 15.11.2026: вылеты (QSettings из потоков, сборщик мусора), свои
файлы и процессы, ложные срабатывания на кэше правил YARA, счётчик хэшей, проверка DNS без
bash.ws, «Описание» с переносом по словам."""
import json
import os
import threading

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


def test_settings_shared_between_threads(qapp):
    from ui import settings as cfg
    main = cfg.store()
    seen = []

    def worker():
        seen.append(cfg.store())
        cfg.set_("general/on_top", True)
        seen.append(cfg.get("general/on_top"))
    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(s is main for s in seen[0::2])        # один объект на всю программу
    assert main._qs.thread() is qapp.thread()       # и живёт в главном потоке
    assert all(seen[1::2]) and cfg.get("general/on_top") is True
    cfg.set_("general/on_top", False)


def test_main_thread_gc_collects_on_timer(qapp):
    import gc

    from diag.crash import MainThreadGC
    collector = MainThreadGC()
    try:
        assert not gc.isenabled()
        for _ in range(collector.threshold[0] + 10):
            a = []
            a.append(a)                              # циклы — для сборщика
        del a
        before = gc.get_count()[0]
        collector.check()
        assert gc.get_count()[0] < before
    finally:
        collector.stop()
    assert gc.isenabled()


def test_compiled_rules_skip_yara(tmp_path):
    from scanner import engine
    cache = tmp_path / "yara_b9e6c09ac71a.bin"
    cache.write_bytes(b"YARA" + b"\0" * 64)
    script = tmp_path / "evil.ps1"
    script.write_bytes(b"YARA\nWrite-Host 1")
    assert engine.compiled_rules(cache)
    assert not engine.compiled_rules(script)                # скрипт так YARA не обойдёт
    assert not engine.compiled_rules(tmp_path / "missing.bin")
    assert engine.compiled_rules(cache, data=b"YARA....")


def test_count_hashes(tmp_path):
    from scanner.hashing import count_hashes
    (tmp_path / "hashes.txt").write_text("# своя база\n" + "a" * 64 + "\n\n" + "b" * 32 + "\n")
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "mb.txt").write_text("c" * 64 + "\n")
    assert count_hashes(tmp_path) == 3


def test_own_files_both_editions(tmp_path, monkeypatch):
    import ownproc
    release = tmp_path / "StretchBIT"
    release.mkdir()
    monkeypatch.setenv("ProgramW6432", str(tmp_path))
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.setattr(ownproc, "_safe_dirs", {})
    import winacl
    monkeypatch.setattr(winacl, "admin_only", lambda path: (True, ""))
    assert ownproc.is_own_file(str(release / "StretchBIT.exe"))
    assert ownproc.is_own_file(str(release / "app" / "vpn" / "bin" / "xray.exe"))
    assert not ownproc.is_own_file(str(tmp_path / "Other" / "StretchBIT.exe"))
    monkeypatch.setattr(ownproc, "_safe_dirs", {})
    monkeypatch.setattr(winacl, "admin_only", lambda path: (False, "открыта"))
    assert not ownproc.is_own_file(str(release / "StretchBIT.exe"))  # открытая папка


def test_dns_check_akamai():
    from vpn import leaks

    def get(url, timeout=10):
        data = {"https://ipwho.is/": {"success": True, "ip": "203.0.113.5",
                                      "country": "Netherlands",
                                      "connection": {"isp": "Hosting"}},
                "https://ipwho.is/198.51.100.7": {"success": True, "ip": "198.51.100.7",
                                                  "country": "Russia",
                                                  "connection": {"isp": "Provider"}},
                "https://ipwho.is/203.0.113.9": {"success": True, "ip": "203.0.113.9",
                                                 "country": "Netherlands",
                                                 "connection": {"isp": "Cloudflare"}}}[url]
        return json.dumps(data).encode()
    found = leaks.dns_check_akamai(get, lambda name: "198.51.100.7")
    assert found.level == leaks.BAD and "Russia" in found.detail
    ok = leaks.dns_check_akamai(get, lambda name: "203.0.113.9")
    assert ok.level == leaks.OK and "Cloudflare" in ok.detail


def test_details_wraps_by_words(qapp):
    from PySide6.QtWidgets import QTextBrowser

    from ui.details import show_details
    dialog = show_details(None, "Описание", [("Что найдено", "YARA: " + ", ".join(
        f"Rule_{i}" for i in range(200))), ("Файл", r"C:\x\y.bin")])
    try:
        view = dialog.findChild(QTextBrowser)
        assert view is not None and "Rule_199" in view.toPlainText()
        from PySide6.QtGui import QTextOption
        assert view.wordWrapMode() == QTextOption.WrapMode.WordWrap
    finally:
        dialog.close()


def test_protect_journal_shortens_long_text(qapp, tmp_path, monkeypatch):
    from recovery import threatlog
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "threats.json")
    threatlog.add(str(tmp_path / "yara_x.bin"), "threat",
                  "Угроза: YARA: " + ", ".join(f"Rule_{i}" for i in range(2000)), "Полная проверка")
    from ui.protect_journal import SHOWN_TEXT, ProtectJournalPage
    page = ProtectJournalPage()
    text = page.tree.topLevelItem(0).text(2)
    assert len(text) <= SHOWN_TEXT + 1 and text.endswith("…")


def test_fullscan_skips_closed_install_dirs(tmp_path, monkeypatch):
    import ownproc
    from scanner import fullscan
    folder = tmp_path / "StretchBIT-test"
    folder.mkdir()
    monkeypatch.setattr(ownproc, "install_dirs", lambda: [os.path.normcase(str(folder)) + os.sep])
    monkeypatch.setattr(ownproc, "_dir_closed", lambda f: True)
    assert os.path.normcase(str(folder)) in fullscan.own_dirs()
    monkeypatch.setattr(ownproc, "_dir_closed", lambda f: False)
    assert os.path.normcase(str(folder)) not in fullscan.own_dirs()


def test_remote_backend_names_cores():
    from service.remote import RemoteBackend
    backend = RemoteBackend.__new__(RemoteBackend)
    backend.kind = "vless"
    assert backend.exe == "sing-box + Xray в службе защиты"
