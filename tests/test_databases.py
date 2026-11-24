import hashlib

import pytest

import updater
from monitor import RealtimeMonitor
from processmanager import memscan
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.yara_engine import fix_rules_source, load_rules, match_file


def test_fix_rules_keeps_good_rules():
    src = '''rule ok1 { strings: $a = "abc" condition: $a }
rule bad_mod { condition: cuckoo.network.http_request(/x/) }
rule ok2 { condition: filename == "x.exe" and myvar == "" }
rule ok1 { condition: true }
rule dep { condition: bad_mod }
rule info { meta: category = "INFO" condition: true }
rule ok3 { strings: $b = "zzz" condition: $b }
'''
    text, externals, fixes, error = fix_rules_source(src)
    assert error == "" and text is not None
    for name in ("ok1", "ok2", "ok3"):
        assert f"rule {name}" in text
    for name in ("bad_mod", "dep", "info"):
        assert f"rule {name}" not in text
    assert "myvar" in externals and "filename" in externals
    assert text.count("\n") == src.count("\n")  # номера строк не сдвигаются


def test_unfixable_file_is_reported():
    text, _, _, error = fix_rules_source('import "nonexistent_module"\nrule a { condition: true }')
    assert text is None and error


def test_load_rules_uses_cache_and_externals(tmp_path, monkeypatch):
    import scanner.yara_engine as ye
    monkeypatch.setattr(ye, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(ye, "LOG_FILE", tmp_path / "yara.log")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text('rule by_name { condition: filename == "evil.bin" }')
    rules, errors = load_rules(rules_dir)
    assert rules is not None and errors == []
    assert list((tmp_path / "cache").glob("yara_*.bin"))
    target = tmp_path / "evil.bin"
    target.write_bytes(b"x")
    assert match_file(rules, target) == ["by_name"]
    cached, _ = load_rules(rules_dir)  # второй раз из кэша
    assert match_file(cached, target) == ["by_name"]


def test_hashdb_text_and_binary(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"malware sample")
    md5 = hashlib.md5(sample.read_bytes()).hexdigest()
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    others = [hashlib.md5(str(i).encode()).hexdigest() for i in range(1000)]
    raw = "\n".join(others + [md5]).encode()
    (feeds / "virusshare_00001.md5.bin").write_bytes(updater.md5_bin(raw))
    (feeds / "x.txt").write_text("# c\n" + "a" * 64 + "\n")
    db = load_all_signatures(tmp_path)
    assert len(db) == 1002
    assert md5 in db and md5.upper() in db and "a" * 64 in db
    assert "b" * 32 not in db and "b" * 64 not in db and "zz" not in db
    assert check_file(sample, db, heuristics=False) == "hash match (MD5)"


def test_update_due_counts_from_1970():
    day = updater.UPDATE_INTERVAL
    assert updater.update_due(0, now=1_000_000_000)  # ни разу: обновить сразу
    assert not updater.update_due(1000, now=1000 + day - 1)
    assert updater.update_due(1000, now=1000 + day)
    assert updater.update_due(5000, now=1000)  # часы перевели назад


def test_monitor_filters_system_folders(tmp_path):
    user, system, startup = tmp_path / "user", tmp_path / "sys", tmp_path / "startup"
    mon = RealtimeMonitor([user], tmp_path, tmp_path, [], lambda *a: None,
                          system=[(system, False, False), (startup, True, True)])
    assert mon._wanted(user / "deep" / "notes.txt")          # папка пользователя: всё
    assert mon._wanted(system / "evil.exe")
    assert not mon._wanted(system / "log.etl")               # системная: только исполняемые
    assert not mon._wanted(system / "sub" / "evil.exe")      # без подпапок
    assert mon._wanted(startup / "a" / "task")               # автозагрузка: все файлы
    assert not mon._wanted(user / "file.crdownload")


def test_monitor_skips_excluded_folder(tmp_path):
    """Собственная папка программы (exclude) не проверяется: файлы внутри не сканируются.

    В журналах и отчётах программы лежат названия YARA-правил прошлых находок, и правила
    совпадают сами с собой — без исключения защита зацикливалась бы на своих же файлах."""
    events = []
    own = tmp_path / "own"
    log = own / "logs" / "app.log"
    log.parent.mkdir(parents=True)
    log.write_text("SharpAdidnsdump", encoding="utf-8")
    mon = RealtimeMonitor([tmp_path / "user"], tmp_path, tmp_path, [own],
                          lambda kind, text: events.append((kind, text)))
    mon._handle(log, 0)
    assert events == []  # ни «OK», ни «угроза»: файл в собственной папке пропущен


def test_memory_batches_join_small_regions():
    regions = [(i, b"a" * 1000) for i in range(10)] + [(99, b"b" * memscan.BATCH)]
    blocks = sorted(memscan._batches(regions), key=len)
    assert len(blocks) == 2  # мелкие склеены в один блок, крупный отдельно
    assert blocks[0].count(b"a") == 10_000 and blocks[1] == b"b" * memscan.BATCH


@pytest.mark.skipif(memscan._read_native is None, reason="нет собранного модуля C++")
def test_native_reader_finds_marker():
    import os
    marker = bytearray(b"SBIT_NATIVE_" + b"Z" * 20)  # живёт в куче этого процесса
    chunks = memscan.read_regions(os.getpid())
    assert any(bytes(marker) in data for _, data in chunks)
    with pytest.raises(OSError):
        memscan.read_regions(4)  # System: нет доступа даже у администратора к памяти


def test_missing_bases_are_due(tmp_path, monkeypatch):
    """Время обновления пережило переустановку, а базы — нет: обновлять сразу."""
    monkeypatch.setattr(updater, "COMMUNITY_RULES_DIR", tmp_path / "rules" / "community")
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    now = 10 * updater.UPDATE_INTERVAL
    assert updater.bases_missing() and updater.needs_update(now - 60, now=now)
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "virusshare_00001.md5.bin").write_bytes(bytes(16))
    assert not updater.bases_missing() and not updater.needs_update(now - 60, now=now)
    assert updater.needs_update(0, now=now)


def test_virusshare_last_is_bounded(monkeypatch):
    """Поиск последнего списка VirusShare — не больше VIRUSSHARE_PROBES HEAD-запросов."""
    calls = []

    def exists(n, timeout=15):
        calls.append(n)
        return 0 < n <= 511

    monkeypatch.setattr(updater, "_virusshare_exists", exists)
    assert updater._virusshare_last(505) == 511
    assert len(calls) <= updater.VIRUSSHARE_PROBES


def test_virusshare_last_returns_none_not_walk_hundreds(monkeypatch):
    """Всё 404 рядом с подсказкой — вернуть None за ~10 проб, а не перебирать вниз сотни."""
    calls = []
    monkeypatch.setattr(updater, "_virusshare_exists",
                        lambda n, timeout=15: calls.append(n) or False)
    assert updater._virusshare_last(505) is None
    assert len(calls) <= updater.VIRUSSHARE_PROBES
    assert max(calls) <= 505 and min(calls) >= 505 - updater.VIRUSSHARE_PROBES


def test_virusshare_step_respects_budget(tmp_path, monkeypatch, capsys):
    """Шаг VirusShare не бесконечен: общий бюджет обрывает докачку, состояние сохраняется."""
    import json
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    monkeypatch.setattr(updater, "_virusshare_last", lambda hint: 511)
    monkeypatch.setattr(updater, "VIRUSSHARE_BUDGET", 0)   # лимит исчерпан сразу
    progress = []
    assert updater.update_virusshare(progress=progress.append) is True
    assert any("список 1 из 50" in p for p in progress)
    assert "не успел" in capsys.readouterr().out
    assert json.loads((tmp_path / "feeds" / "virusshare.json").read_text()) == {"last": 511}


def test_virusshare_step_passes_file_timeout(tmp_path, monkeypatch):
    """Каждый список качается с общим DOWNLOAD_TIMEOUT (30 с), а не 300 с."""
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    monkeypatch.setattr(updater, "_virusshare_last", lambda hint: 511)
    seen = {}

    def download(url, timeout=120, data=None, headers=None, limit=updater.MAX_DOWNLOAD):
        seen["timeout"] = timeout
        return b"0123456789abcdef0123456789abcdef\n"

    monkeypatch.setattr(updater, "_download", download)
    assert updater.update_virusshare(files=2) is True
    assert seen["timeout"] == updater.DOWNLOAD_TIMEOUT
    assert len(list((tmp_path / "feeds").glob("virusshare_*.md5.bin"))) == 2


def test_virusshare_nothing_new_says_all_present(tmp_path, monkeypatch, capsys):
    """Списки уже на диске — «все списки на месте», а не пугающее «скачано 0»."""
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "virusshare.json").write_text('{"last": 505}')
    for n in (504, 505):
        (tmp_path / "feeds" / f"virusshare_{n:05d}.md5.bin").write_bytes(bytes(16))
    monkeypatch.setattr(updater, "_virusshare_last", lambda hint: 505)
    assert updater.update_virusshare(files=2) is True
    assert "все списки на месте" in capsys.readouterr().out


def test_virusshare_from_mirror(tmp_path, monkeypatch, capsys):
    """Фолбэк на зеркало: списки берутся из manifest ветки feeds и пишутся как md5.bin."""
    import json
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    raw = b"0123456789abcdef0123456789abcdef\n"
    manifest = {"version": updater.MIRROR_MANIFEST_VERSION, "generated": 0,
                "files": {f"virusshare_{n:05d}": {"name": f"virusshare_{n:05d}-202601010000.md5.gz",
                                                  "sha256": "x", "size": len(raw)}
                          for n in (510, 511)}}
    monkeypatch.setattr(updater, "_mirror_manifest", lambda: manifest)
    monkeypatch.setattr(updater, "mirror_file", lambda key: raw)
    assert updater._virusshare_from_mirror(2, None, None) is True
    assert len(list((tmp_path / "feeds").glob("virusshare_*.md5.bin"))) == 2
    assert json.loads((tmp_path / "feeds" / "virusshare.json").read_text()) == {"last": 511}


def test_virusshare_falls_back_to_mirror_on_timeout(tmp_path, monkeypatch, capsys):
    """Сайт virusshare.com не отвечает — update_virusshare уходит в зеркало."""
    monkeypatch.setattr(updater, "FEEDS_DIR", tmp_path / "feeds")
    monkeypatch.setattr(updater, "_virusshare_last",
                        lambda hint: (_ for _ in ()).throw(TimeoutError("read timed out")))
    monkeypatch.setattr(updater, "_virusshare_from_mirror",
                        lambda files, progress, part: True)
    assert updater.update_virusshare() is True
    assert "пробую зеркало" in capsys.readouterr().out


def test_read_limited_rejects_oversized():
    class Resp:
        def __init__(self, data, headers=None):
            self._data, self.headers = data, headers or {}

        def read(self, n):
            return self._data[:n]

    with pytest.raises(ValueError):
        updater._read_limited(Resp(b"x" * 99, {"Content-Length": "99"}), 10)  # заявлено больше
    with pytest.raises(ValueError):
        updater._read_limited(Resp(b"x" * 99), 10)                            # не помещается
    assert updater._read_limited(Resp(b"x" * 5), 10) == b"x" * 5
