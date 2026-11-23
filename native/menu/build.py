r"""Сборка пункта контекстного меню Windows 11 (IExplorerCommand): python native/menu/build.py.

Нужна Visual Studio (C++, Windows SDK): cl.exe, makeappx.exe, signtool.exe. Результат:
  native/menu/bin/sbit_menu.dll           — COM-сервер (IExplorerCommand)
  native/menu/bin/sbit_menu.msix          — sparse-пакет (подписан, если задан сертификат)

Развёртывание на машине (один раз):
  1. Самоподписанный сертификат (PowerShell, от администратора):
       $c = New-SelfSignedCertificate -Type Custom -Subject "CN=StretchBIT" `
             -KeyUsage DigitalSignature -FriendlyName "StretchBIT" `
             -CertStoreLocation Cert:\CurrentUser\My -TextExtension `
             @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
       Export-Certificate -Cert $c -FilePath cert.cer
  2. Доверить сертификат: установить cert.cer в «Доверенные лица» (Trusted People) текущего
     пользователя.
  3. Подписать и зарегистрировать пакет (этот скрипт с --cert <cert.pfx> --register).
  4. Скопировать sbit_menu.dll в папку программы (рядом со StretchBIT.exe).

Меню появляется в новом контекстном меню Проводника для всех файлов (Type="*").
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE / "bin"
CLSID = "7f3d2c1a-9b4e-4d6f-a831-c25d7e0f1a9b"
VS_ROOTS = [Path("C:/Program Files/Microsoft Visual Studio"),
            Path("C:/Program Files (x86)/Microsoft Visual Studio")]
CFLAGS = "/nologo /O2 /MT /EHsc /W4 /DUNICODE /D_UNICODE /std:c++17"


def find_vcvarsall() -> Path | None:
    found = []
    for root in VS_ROOTS:
        if root.is_dir():
            found += root.glob("*/*/VC/Auxiliary/Build/vcvarsall.bat")
    return max(found, default=None, key=lambda p: p.parts[-6])


def _run(cmd: str, cwd=None) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="oem",
                            errors="replace", cwd=cwd, shell=True)
    if result.returncode:
        raise SystemExit(f"Не удалось:\n{cmd}\n{result.stdout}\n{result.stderr}")


def build() -> list[Path]:
    vcvars = find_vcvarsall()
    if vcvars is None:
        raise SystemExit("Не найдена Visual Studio с C++ (vcvarsall.bat)")
    BIN.mkdir(exist_ok=True)
    obj = BIN / "obj"
    obj.mkdir(exist_ok=True)
    dll = BIN / "sbit_menu.dll"
    _run(f'call "{vcvars}" x64 >nul && cd /d "{HERE}" && cl {CFLAGS} /LD '
         f'/Fo"{obj}\\\\" command.cpp /link /DEF:sbit_menu.def /OUT:"{dll}" '
         f'/IMPLIB:"{obj / "sbit_menu.lib"}" ole32.lib shell32.lib shlwapi.lib')
    return [dll]


def package(cert: str | None = None, password: str | None = None) -> Path:
    """Собрать и подписать sparse-пакет (makeappx + signtool)."""
    layout = BIN / "layout"
    if layout.exists():
        import shutil
        shutil.rmtree(layout)
    (layout / "Assets").mkdir(parents=True)
    import shutil as _sh
    _sh.copy2(BIN / "sbit_menu.dll", layout / "sbit_menu.dll")
    icon = HERE / "Assets" / "icon.png"
    if not icon.exists():
        icon.write_bytes(b"")  # заглушка: без значка пакет всё равно соберётся
    _sh.copy2(icon, layout / "Assets" / "icon.png")
    _sh.copy2(HERE / "AppxManifest.xml", layout / "AppxManifest.xml")
    msix = BIN / "sbit_menu.msix"
    msix.unlink(missing_ok=True)
    _run(f'makeappx pack /d "{layout}" /p "{msix}" /o')
    if cert:
        pwd = f" /p {password}" if password else ""
        _run(f'signtool sign /fd SHA256 /f "{cert}"{pwd} "{msix}"')
    return msix


def register() -> None:
    _run('powershell -NoProfile -Command "Add-AppxPackage -Register '
         f'"{BIN / "layout" / "AppxManifest.xml"}" -ForceApplicationShutdown"')
    print("Пакет зарегистрирован. Скопируйте sbit_menu.dll в папку программы и "
          "перезапустите Проводник.")


if __name__ == "__main__":
    args = sys.argv[1:]
    build()
    print("DLL собран:", BIN / "sbit_menu.dll")
    cert = None
    if "--cert" in args:
        cert = args[args.index("--cert") + 1]
    password = None
    if "--password" in args:
        password = args[args.index("--password") + 1]
    msix = package(cert, password)
    print("Пакет:", msix, "(подписан)" if cert else "(НЕ подписан)")
    if "--register" in args:
        register()
