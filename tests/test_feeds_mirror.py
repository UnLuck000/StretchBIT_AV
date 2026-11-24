"""Зеркало баз abuse.ch на GitHub: сборка (tools/feeds_mirror.py) и чтение в updater.py.
Сеть не нужна: загрузки подменяются."""
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

import updater

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import feeds_mirror  # noqa: E402

KEY = "k3y-secret-0123456789"
SHA = "a" * 64
MB_RAW = f"# MalwareBazaar recent\n{SHA},x\n".encode()
TF_RAW = json.dumps({"query_status": "ok", "data": [
    {"ioc_type": "sha256_hash", "ioc": "b" * 64},
    {"ioc_type": "ip:port", "ioc": "8.8.4.4:443"},
    {"ioc_type": "domain", "ioc": "evil-c2-example.com"}]}).encode()
URLHAUS_RAW = b'# URLhaus online\n"1","2026","http://bad-host-example.com/x","online"\n'
FEODO_RAW = b"# Feodo Tracker\n1.2.3.4\n"
SSLBL_RAW = b"# SSLBL\n5.6.7.8\n"
JA3_RAW = b"# ja3_md5,firstseen,lastseen,Listingreason\n" + b"c" * 32 + b",a,b,Evil\n"


@pytest.fixture(autouse=True)
def _virusshare_offline(monkeypatch):
    """VirusShare в тестах не трогает сеть: пробу последнего номера глушим (None — сайт не
    отвечает). Отдельный тест ниже проверяет само зеркалирование с подменой загрузки."""
    monkeypatch.setattr(feeds_mirror, "_virusshare_last", lambda hint: None)
    import ed25519
    secret = bytes(range(32))  # только тестовый ключ, не используется в выпуске
    monkeypatch.setenv("FEEDS_SIGN_KEY", secret.hex())
    monkeypatch.setattr(updater, "FEEDS_PUBLIC_KEY", ed25519.public_key(secret).hex())


def fake_sources(fail=()):
    def make(raw, kind):
        def fetch(key):
            if kind in fail:
                raise TimeoutError("нет связи")
            return raw
        return fetch
    src = dict(feeds_mirror.SOURCES)
    raws = {"malwarebazaar": MB_RAW, "threatfox": TF_RAW, "urlhaus": URLHAUS_RAW,
            "feodo": FEODO_RAW, "sslbl": SSLBL_RAW, "ja3": JA3_RAW}
    return {k: (ext, needs, make(raws[k], k), check)
            for k, (ext, needs, _f, check) in src.items()}


def test_build_writes_manifest_and_hides_key(tmp_path):
    manifest = feeds_mirror.build(tmp_path, KEY, fake_sources(fail=("urlhaus",)))
    assert set(manifest["files"]) == {"malwarebazaar", "threatfox", "feodo", "sslbl", "ja3"}
    assert manifest["errors"]["urlhaus"] == "TimeoutError"
    assert manifest["errors"]["virusshare"] == "последний список не найден"
    for info in manifest["files"].values():
        packed = (tmp_path / info["name"]).read_bytes()
        assert hashlib.sha256(packed).hexdigest() == info["sha256"]
        assert info["size"] == len(gzip.decompress(packed))
    sums = (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")
    assert all(info["name"] in sums for info in manifest["files"].values())
    for f in tmp_path.iterdir():  # ключ — ни в одном файле
        data = f.read_bytes()
        assert KEY.encode() not in (gzip.decompress(data) if f.suffix == ".gz" else data)


def test_build_without_key_and_bad_answer(tmp_path):
    src = fake_sources()
    ext, needs, _fetch, check = src["feodo"]
    src["feodo"] = (ext, needs, lambda key: b"<html>blocked</html>", check)
    manifest = feeds_mirror.build(tmp_path, "", src)
    assert set(manifest["files"]) == {"sslbl", "ja3"}
    assert manifest["errors"]["feodo"] == "ValueError"
    assert "ключа" in manifest["errors"]["threatfox"]


def test_build_keeps_previous_file_when_source_fails(tmp_path):
    """Источник сбоит, но есть прежний файл — он остаётся (устаревший лучше, чем ничего)."""
    out = tmp_path / "out"
    first = feeds_mirror.build(out, KEY, fake_sources())
    out2 = tmp_path / "out2"
    manifest = feeds_mirror.build(out2, KEY, fake_sources(fail=("threatfox",)), previous=out)
    assert "threatfox" in manifest["files"]                  # прежний файл сохранён
    assert "взят прежний" in manifest["errors"]["threatfox"]  # но помечен как сбой
    assert manifest["files"]["threatfox"]["name"] == first["files"]["threatfox"]["name"]
    packed = (out2 / manifest["files"]["threatfox"]["name"]).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == manifest["files"]["threatfox"]["sha256"]


def test_mirror_virusshare_lists(tmp_path, monkeypatch):
    """VirusShare зеркалится по спискам (50 последних), файлы сжаты и внесены в manifest."""
    raw = b"0123456789abcdef0123456789abcdef\n"
    monkeypatch.setattr(feeds_mirror, "_virusshare_last", lambda hint: 511)
    calls = []

    def download(url, timeout=300):
        calls.append(url)
        return raw

    monkeypatch.setattr(feeds_mirror, "_download", download)
    files = feeds_mirror._mirror_virusshare(tmp_path, None, {}, "202601010000", {})
    assert set(files) == {f"virusshare_{n:05d}" for n in range(511, 461, -1)}
    assert len(calls) == 50
    info = files["virusshare_00511"]
    packed = (tmp_path / info["name"]).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == info["sha256"]
    assert gzip.decompress(packed) == raw


def test_mirror_keeps_virusshare_manifest_on_timeout(tmp_path, monkeypatch):
    previous = tmp_path / "prev"
    previous.mkdir()
    packed = gzip.compress(b"a" * 32 + b"\n")
    name = "virusshare_00001-202601010000.md5.gz"
    (previous / name).write_bytes(packed)
    files = {"virusshare_00001": {"name": name, "sha256": hashlib.sha256(packed).hexdigest()}}
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(feeds_mirror, "_virusshare_last",
                        lambda hint: (_ for _ in ()).throw(TimeoutError()))
    assert feeds_mirror._mirror_virusshare(out, previous, files, "now", {}) == files
    assert (out / name).read_bytes() == packed


def test_mirror_wont_resign_untrusted_previous_manifest(tmp_path):
    previous = tmp_path / "prev"
    feeds_mirror.build(previous, KEY, fake_sources())
    manifest = json.loads((previous / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["threatfox"]["sha256"] = "0" * 64
    (previous / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    output = feeds_mirror.build(tmp_path / "out", KEY, fake_sources(fail=("threatfox",)),
                                previous=previous)
    assert "threatfox" not in output["files"]


def test_mirror_refuses_unsigned_publication(tmp_path, monkeypatch):
    monkeypatch.delenv("FEEDS_SIGN_KEY")
    with pytest.raises(ValueError, match="FEEDS_SIGN_KEY"):
        feeds_mirror.build(tmp_path, KEY, fake_sources())


def test_client_reads_signed_virusshare_md5_file(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds_mirror, "_virusshare_last", lambda hint: 0)
    monkeypatch.setattr(feeds_mirror, "_download", lambda *a, **kw: b"a" * 32 + b"\n")
    manifest = feeds_mirror.build(tmp_path, KEY, {})
    def read(url, **kwargs):
        return (tmp_path / url.rsplit("/", 1)[-1]).read_bytes()
    monkeypatch.setattr(updater, "_download", read)
    updater.reset_mirror()
    try:
        assert updater.mirror_file("virusshare_00000") == b"a" * 32 + b"\n"
        assert manifest["files"]["virusshare_00000"]["name"].endswith(".md5.gz")
    finally:
        updater.reset_mirror()


@pytest.fixture
def mirror(tmp_path, monkeypatch):
    """Зеркало на диске + updater, который вместо сети читает его; прямые источники —
    только по словарю direct."""
    out = tmp_path / "release"
    manifest = feeds_mirror.build(out, KEY, fake_sources())
    calls, direct = [], {}

    def download(url, timeout=120, data=None, headers=None):
        calls.append(url)
        base = updater.mirror_base()
        if url.startswith(base):
            path = out / url[len(base):]
            if not path.exists():
                raise OSError("404")
            return path.read_bytes()
        for part, raw in direct.items():
            if part in url:
                return raw
        raise OSError("нет сети")
    monkeypatch.setattr(updater, "_download", download)
    monkeypatch.setattr(updater, "_get_key", lambda: "")
    for name in ("FEEDS_DIR", "NETFEEDS_DIR"):
        monkeypatch.setattr(updater, name, tmp_path / name.lower())
    monkeypatch.setattr(updater, "DOMAINS_DIR", tmp_path / "netfeeds_dir" / "domains")
    monkeypatch.setattr(updater, "JA3_DIR", tmp_path / "netfeeds_dir" / "ja3")
    updater.reset_mirror()
    yield {"out": out, "manifest": manifest, "calls": calls, "direct": direct, "tmp": tmp_path}
    updater.reset_mirror()


def test_without_key_everything_comes_from_mirror(mirror):
    tmp = mirror["tmp"]
    assert updater.update_hashes()
    assert SHA in (tmp / "feeds_dir" / "malwarebazaar.txt").read_text(encoding="utf-8")
    assert updater.update_threatfox()
    assert "b" * 64 in (tmp / "feeds_dir" / "threatfox.txt").read_text(encoding="utf-8")
    assert "8.8.4.4" in (tmp / "netfeeds_dir" / "threatfox.txt").read_text(encoding="utf-8")
    assert updater.update_domains()
    assert "bad-host-example.com" in (tmp / "netfeeds_dir" / "domains" / "urlhaus.txt").read_text(
        encoding="utf-8")
    assert "Evil" in (tmp / "netfeeds_dir" / "ja3" / "sslbl.txt").read_text(encoding="utf-8")
    mirror["direct"]["C2IntelFeeds"] = b"#ip,ioc\n9.9.9.9,x\n"
    assert updater.update_ips()
    assert "1.2.3.4" in (tmp / "netfeeds_dir" / "feodo.txt").read_text(encoding="utf-8")
    # manifest.json — один раз за обновление
    assert sum(u.endswith("manifest.json") for u in mirror["calls"]) == 1
    assert not any("abuse.ch" in u for u in mirror["calls"])  # напрямую без ключа — нет


def test_bad_hash_is_rejected_and_direct_used(mirror):
    info = mirror["manifest"]["files"]["feodo"]
    path = mirror["out"] / info["name"]
    path.write_bytes(gzip.compress(b"# Feodo Tracker\n6.6.6.6\n"))  # подменили файл
    mirror["direct"]["feodotracker"] = FEODO_RAW
    raw, where = updater._fetch("feodo", lambda: updater._download(
        "https://feodotracker.abuse.ch/x"), updater._marker("Feodo Tracker"))
    assert where == "напрямую" and raw == FEODO_RAW
    with pytest.raises(updater.MirrorError, match="SHA-256"):
        updater.mirror_file("feodo")


def test_stale_mirror_is_not_used(mirror):
    import ed25519
    manifest = dict(mirror["manifest"], generated=int(time.time()) - 5 * 86400)
    manifest["signature"] = ed25519.sign(bytes(range(32)), ed25519.signable(manifest)).hex()
    (mirror["out"] / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    updater.reset_mirror()
    assert not updater.update_hashes()                  # без ключа и без свежего зеркала
    with pytest.raises(updater.MirrorError, match="не обновлялось"):
        updater.mirror_file("malwarebazaar")


def test_with_key_direct_first(mirror, monkeypatch):
    monkeypatch.setattr(updater, "_get_key", lambda: KEY)
    mirror["direct"]["mb-api.abuse.ch"] = f"# x\n{'d' * 64}\n".encode()
    assert updater.update_hashes()
    text = (mirror["tmp"] / "feeds_dir" / "malwarebazaar.txt").read_text(encoding="utf-8")
    assert "d" * 64 in text and SHA not in text          # зеркало не понадобилось


def test_gunzip_limit():
    with pytest.raises(updater.MirrorError):
        updater._gunzip(gzip.compress(b"0" * 5000), limit=1000)
    with pytest.raises(updater.MirrorError):
        updater._gunzip(gzip.compress(b"0" * 5000)[:-10])
    assert updater._gunzip(gzip.compress(b"ok")) == b"ok"


def test_feeds_signature_roundtrip(tmp_path, monkeypatch):
    """Манифест подписывается (закрытый ключ в Secrets) и проверяется публичным ключом."""
    import ed25519
    secret = bytes(range(32))
    public = ed25519.public_key(secret)
    monkeypatch.setattr(updater, "FEEDS_PUBLIC_KEY", public.hex())
    monkeypatch.setenv("FEEDS_SIGN_KEY", secret.hex())
    manifest = feeds_mirror.build(tmp_path, KEY, fake_sources())
    assert "signature" in manifest
    data = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    updater._verify_feeds_signature(data)          # подпись верна — не поднимает
    data["files"]["malwarebazaar"]["sha256"] = "0" * 64  # подменили
    with pytest.raises(updater.MirrorError, match="подпись"):
        updater._verify_feeds_signature(data)
    with pytest.raises(updater.MirrorError, match="не подписан"):  # ключ задан, подписи нет
        updater._verify_feeds_signature({"version": 1, "files": {}})


def test_workflow_uses_secret_and_branch():
    text = (ROOT / ".github" / "workflows" / "feeds-mirror.yml").read_text(encoding="utf-8")
    assert "secrets.ABUSECH_AUTH_KEY" in text and "tools/feeds_mirror.py out" in text
    assert "feeds:refs/heads/feeds" in text            # ветка, а не выпуск
    assert "gh release upload" not in text and "gh release delete feeds" in text


def test_mirror_base_is_branch(monkeypatch):
    import appinfo
    monkeypatch.setattr(appinfo, "REPO_URL", "https://github.com/Owner/repo")
    assert updater.mirror_base() ==         "https://raw.githubusercontent.com/Owner/repo/refs/heads/feeds/"
