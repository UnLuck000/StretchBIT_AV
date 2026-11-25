"""Редакция EULA определяется хэшем полного текста, без молчаливой миграции согласия."""
import hashlib
from pathlib import Path

EULA_FILE = Path(__file__).resolve().parent.parent / "docs" / "EULA.txt"


def text() -> str:
    return EULA_FILE.read_text(encoding="utf-8")


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
