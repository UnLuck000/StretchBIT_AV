"""Показанная редакция MIT/EULA/политики определяется хэшем всех трёх документов."""
import hashlib
from pathlib import Path

EULA_FILE = Path(__file__).resolve().parent.parent / "docs" / "EULA.txt"
LICENSE_FILE = Path(__file__).resolve().parent.parent / "LICENSE"
PRIVACY_FILE = Path(__file__).resolve().parent.parent / "docs" / "PRIVACY.txt"


def text(root: Path | None = None) -> str:
    paths = ((root / "LICENSE", root / "docs" / "EULA.txt", root / "docs" / "PRIVACY.txt")
             if root is not None else (LICENSE_FILE, EULA_FILE, PRIVACY_FILE))
    return "\n\n".join(path.read_text(encoding="utf-8")
                       for path in paths)


def revision() -> str:
    return hashlib.sha256(text().encode("utf-8")).hexdigest()


def accepted() -> bool:
    from ui import settings as cfg
    try:
        return cfg.get("privacy/eula_revision") == revision()
    except OSError:
        return False


def accept() -> None:
    from ui import settings as cfg
    cfg.set_("privacy/eula_revision", revision())
    cfg.store().sync()  # сторож/процесс после UAC должен увидеть согласие сразу


def accept_from_installer(expected_revision: str) -> bool:
    """Только показанная мастером редакция, в процессе исходного пользователя.

    Вызывается мастером после интерактивного принятия, не при тихой установке.
    Это ознакомление, а не разрешение на отправку диагностики.
    """
    if expected_revision != revision():
        return False
    import userdata
    userdata.protect_config()
    # До settings.ini: иначе отметка сама помешает переносу при первом запуске,
    # а запрошенный перенос другой редакции позже затрёт уже записанное ознакомление.
    userdata.migrate()
    from service import transfer
    transfer.window()
    userdata.protect_config()
    accept()
    return True
