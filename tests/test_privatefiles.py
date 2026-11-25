"""DPAPI и DACL: только временные файлы, без VPN, служб и настоящих конфигураций."""
import json
import sys
from pathlib import Path

import pytest

import privatefiles
from vpn import profiles, subscriptions


def test_sddl_replaces_inheritance_and_has_only_intended_principals(monkeypatch):
    from service import winapi
    monkeypatch.setattr(winapi, "current_sid", lambda: "S-1-5-21-123")
    assert privatefiles._sddl(True, False) == (
        "D:P(A;OICI;FA;;;S-1-5-21-123)(A;OICI;FA;;;SY)")
    assert privatefiles._sddl(False, True).endswith("(A;;FA;;;BA)")
    assert privatefiles._sddl(True, False, True) == (
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    monkeypatch.setattr(winapi, "current_sid", lambda: "")
    with pytest.raises(OSError):
        privatefiles._sddl(True, False)


def test_atomic_write_protects_file_before_secret_is_written(tmp_path, monkeypatch):
    target = tmp_path / "private" / "secret"
    real = privatefiles._set_acl
    checked = []

    def check(path, *args):
        if path.is_file():
            assert path.read_bytes() == b""
            checked.append(path)
        real(path, *args)

    monkeypatch.setattr(privatefiles, "_set_acl", check)
    privatefiles.write_bytes(target, b"secret-token")
    assert checked and target.read_bytes() == b"secret-token"
    assert list(target.parent.iterdir()) == [target]


def test_acl_failure_does_not_replace_existing_secret(tmp_path, monkeypatch):
    target = tmp_path / "secret"
    target.write_bytes(b"old")

    def fail(*args):
        raise PermissionError("ACL")

    monkeypatch.setattr(privatefiles, "_set_acl", fail)
    with pytest.raises(PermissionError):
        privatefiles.write_bytes(target, b"new")
    assert target.read_bytes() == b"old"
    assert list(tmp_path.iterdir()) == [target]


def test_file_acl_failure_cleans_empty_temporary_file(tmp_path, monkeypatch):
    real = privatefiles._set_acl

    def fail(path, *args):
        if path.is_file():
            raise PermissionError("ACL")
        real(path, *args)

    monkeypatch.setattr(privatefiles, "_set_acl", fail)
    with pytest.raises(PermissionError):
        privatefiles.write_bytes(tmp_path / "secret", b"new")
    assert not list(tmp_path.iterdir())


def test_does_not_follow_directory_junction(tmp_path):
    import subprocess
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "keep"
    secret.write_bytes(b"unchanged")
    link = tmp_path / "link"
    if sys.platform == "win32":
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                                capture_output=True)
        assert result.returncode == 0
    else:
        link.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(OSError):
            privatefiles.write_bytes(link / "keep", b"changed")
        with pytest.raises(OSError):
            privatefiles.protect_directory(link, recursive=True)
        from vpn import xray
        with pytest.raises(OSError):
            xray.write_config({"secret": "test"}, link)
        assert not (outside / "xray.json").exists()
        assert secret.read_bytes() == b"unchanged"
    finally:
        link.rmdir() if sys.platform == "win32" else link.unlink()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI и DACL")
def test_real_dpapi_roundtrip_and_no_plaintext_on_disk(tmp_path):
    secret = "vpn-private-key-test-only"
    path = tmp_path / "vpn" / "profiles.dat"
    profiles.save([profiles.Profile("test", "wireguard", config=secret)], path)
    assert secret.encode() not in path.read_bytes()
    assert profiles.load(path)[0].config == secret
    assert json.loads(profiles._dpapi(path.read_bytes(), False))[0]["config"] == secret
    subpath = path.with_name("subscriptions.dat")
    subscriptions.save([subscriptions.Subscription("test", "test",
                                                   "https://example.invalid/token-secret")], subpath)
    assert b"token-secret" not in subpath.read_bytes()
    assert subscriptions.load(subpath)[0].url.endswith("token-secret")
    assert not list(path.parent.glob(".sbit-*"))


@pytest.mark.skipif(sys.platform != "win32", reason="DACL Windows")
def test_existing_explicit_broad_grants_are_removed_and_new_files_inherit(tmp_path):
    import ctypes
    import winacl
    from service.winapi import current_sid
    root = tmp_path / "private"
    root.mkdir()
    existing = root / "old"
    existing.write_bytes(b"old")
    # Выдать Everyone доступ только тестовому файлу, затем убедиться в полном удалении ACE.
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    adv.SetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p]
    sd = ctypes.c_void_p()
    assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:P(A;;FA;;;WD)", 1, ctypes.byref(sd), None)
    try:
        assert adv.SetFileSecurityW(str(existing), 0x80000004, sd)
    finally:
        ctypes.windll.kernel32.LocalFree(sd)
    privatefiles.protect_directory(root, recursive=True)
    inherited = root / "new"
    inherited.write_bytes(b"new")
    for path in (root, existing, inherited):
        got = winacl.access(path)
        assert got is not None
        assert {sid for sid, mask in got[1]} == {current_sid(), "S-1-5-18"}


def test_dpapi_does_not_fall_back_to_plaintext(monkeypatch):
    monkeypatch.setattr(profiles.sys, "platform", "not-windows")
    with pytest.raises(OSError, match="DPAPI"):
        profiles._dpapi(b"secret", True)


def test_encryption_failure_preserves_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "profiles.dat"
    target.write_bytes(b"existing")

    def fail(*args, **kwargs):
        raise OSError("DPAPI")

    monkeypatch.setattr(profiles, "_dpapi", fail)
    with pytest.raises(OSError):
        profiles.save([], target)
    assert target.read_bytes() == b"existing"
    assert list(tmp_path.iterdir()) == [target]


def test_runtime_xray_config_uses_protected_writer(tmp_path, monkeypatch):
    from vpn import xray
    calls = []
    monkeypatch.setattr(privatefiles, "write_text",
                        lambda path, text, **kw: calls.append((path, text, kw)))
    path = xray.write_config({"secret": "test"}, tmp_path)
    assert calls == [(path, json.dumps({"secret": "test"}, ensure_ascii=False, indent=1),
                      {"administrators": True})]


def test_userdata_protects_existing_config_tree(tmp_path, monkeypatch):
    import userdata
    calls = []
    monkeypatch.setattr(userdata, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(privatefiles, "protect_directory",
                        lambda path, **kw: calls.append((Path(path), kw)))
    userdata.protect_config()
    assert calls == [(tmp_path, {"recursive": True})]
