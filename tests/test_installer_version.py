"""Версия установщика проверяется без компиляции и запуска Inno Setup."""
import subprocess

import pytest

import appinfo
import build_release


@pytest.mark.parametrize(("version", "expected"), [
    ("1.3.0-beta1", "1.3.0.0"),
    ("1.3.0-rc2+build.7", "1.3.0.0"),
    ("2.4.6", "2.4.6.0"),
    ("2.4.6.8", "2.4.6.8"),
    ("2", "2.0.0.0"),
])
def test_numeric_version(version, expected):
    assert build_release.installer_numeric_version(version) == expected


@pytest.mark.parametrize("version", ["", "beta1", "1..3", "1.2.3.4.5", "65536.0.0"])
def test_invalid_numeric_version_is_rejected(version):
    with pytest.raises(ValueError):
        build_release.installer_numeric_version(version)


@pytest.mark.parametrize("edition", ["release", "test"])
def test_installer_receives_both_versions(tmp_path, monkeypatch, edition):
    monkeypatch.setattr(build_release, "find_iscc", lambda: tmp_path / "ISCC.exe")
    monkeypatch.setattr(appinfo, "VERSION", "1.3.0-beta1")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: calls.append((args, kw)))
    folder = tmp_path / ("StretchBIT" if edition == "release" else "StretchBIT-test")
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    (folder / "app" / "docs").mkdir(parents=True)
    for name in ("LICENSE", "docs/EULA.txt", "docs/PRIVACY.txt"):
        (folder / "app" / name).write_text(name, encoding="utf-8")
    result = build_release.make_installer(folder, edition)
    args, kwargs = calls[0]
    assert "/DAppVersion=1.3.0-beta1" in args
    assert "/DAppNumericVersion=1.3.0.0" in args
    assert f"/DEdition={edition}" in args
    assert kwargs["check"] is True
    assert result.name == f"{folder.name}-1.3.0-beta1-setup.exe"
    from diag import consent
    import hashlib
    text = consent.text(folder / "app")
    assert (tmp_path / "build" / f"installer-legal-{edition}.txt").read_text(
        encoding="utf-8-sig") == text
    assert f"/DLegalRevision={hashlib.sha256(text.encode('utf-8')).hexdigest()}" in args


def test_inno_uses_explicit_exe_versions_and_has_no_zero_fallback():
    script = (build_release.ROOT / "installer.iss").read_text(encoding="utf-8")
    for directive in ("VersionInfoVersion={#AppNumericVersion}",
                      "VersionInfoTextVersion={#AppVersion}",
                      "VersionInfoProductVersion={#AppNumericVersion}",
                      "VersionInfoProductTextVersion={#AppVersion}"):
        assert directive in script
    assert '#define AppVersion "0.0.0"' not in script
