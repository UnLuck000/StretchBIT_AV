"""Генерация пары ключей Ed25519 для подписи манифеста баз (updater.FEEDS_PUBLIC_KEY).

    python tools/feeds_keygen.py

Выводит:
  FEEDS_SIGN_KEY — закрытый ключ (hex): в Secrets GitHub Actions (workflow feeds-mirror.yml),
                  НИКОГДА не в репозиторий и не в программу;
  FEEDS_PUBLIC_KEY — публичный (hex): в updater.FEEDS_PUBLIC_KEY (вшивается в программу).
"""
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ed25519  # noqa: E402

secret = secrets.token_bytes(32)
public = ed25519.public_key(secret)
print("FEEDS_SIGN_KEY (Secrets GitHub Actions, не в репозиторий):")
print(secret.hex())
print()
print("FEEDS_PUBLIC_KEY (updater.py):")
print(public.hex())
