"""Показанная редакция MIT/EULA/политики определяется хэшем всех трёх документов."""
import hashlib
from pathlib import Path

EULA_FILE = Path(__file__).resolve().parent.parent / "docs" / "EULA.txt"
LICENSE_FILE = Path(__file__).resolve().parent.parent / "LICENSE"
PRIVACY_FILE = Path(__file__).resolve().parent.parent / "docs" / "PRIVACY.txt"


def text() -> str:
    return "\n\n".join(path.read_text(encoding="utf-8")
                       for path in (LICENSE_FILE, EULA_FILE, PRIVACY_FILE))


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
