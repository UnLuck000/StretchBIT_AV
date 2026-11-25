"""Ed25519 (RFC 8032): подпись и проверка без внешних пакетов (как x25519 в vpn/warp.py).

Нужно для подписи манифеста баз (updater._mirror_manifest, tools/feeds_mirror.py): публичный
ключ закреплён в программе, закрытый — в Secrets GitHub Actions. Подмена ветки feeds
без ключа не пройдёт проверку. Доверенный workflow CI имеет доступ к ключу и остаётся
частью границы доверия (ветка docs/ai-reference, ai/operations/FEEDS_SIGNING.md).

Проверено тестами на векторах RFC 8032 (tests/test_ed25519.py).
"""
import hashlib
import json

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p  # -121665/121666 по модулю p
SQRT_M1 = pow(2, (p - 1) // 4, p)        # sqrt(-1)


def _x_from_y(y: int) -> int:
    """x из y на кривой; x нечётный — замена на p - x (каноническая форма)."""
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = x * SQRT_M1 % p
    if x % 2 != 0:
        x = p - x
    return x


# базовая точка B (X, Y, Z, T — расширенные координаты)
By = 4 * pow(5, p - 2, p) % p
Bx = _x_from_y(By)
B = (Bx % p, By % p, 1, (Bx * By) % p)


def _add(a, b):
    """Сложение точек в расширенных координатах (a, b — кортежи (X, Y, Z, T))."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % p
    bb = (y1 + x1) * (y2 + x2) % p
    cc = 2 * t1 * t2 * d % p
    dd = 2 * z1 * z2 % p
    ee = bb - aa
    ff = dd - cc
    gg = dd + cc
    hh = bb + aa
    return (ee * ff % p, gg * hh % p, ff * gg % p, ee * hh % p)


def _mul(point, scalar: int):
    """[scalar]·point."""
    q = (0, 1, 1, 0)  # нейтральный элемент
    while scalar:
        if scalar & 1:
            q = _add(q, point)
        point = _add(point, point)
        scalar >>= 1
    return q


def _encode(point) -> bytes:
    """Точка → 32 байта: y, старший бит — чётность x."""
    x, y, z, _ = point
    zi = pow(z, p - 2, p)
    x = x * zi % p
    y = y * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(enc: bytes):
    """32 байта → точка."""
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if len(enc) != 32 or y >= p:
        raise ValueError("неканоническая точка Ed25519")
    x = _x_from_y(y)
    if (x * x * (d * y * y + 1) - (y * y - 1)) % p:
        raise ValueError("точка вне кривой Ed25519")
    if x == 0 and enc[31] >> 7:
        raise ValueError("неканонический знак точки Ed25519")
    if x & 1 != enc[31] >> 7:
        x = p - x
    return (x, y, 1, x * y % p)


def _clamp(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(secret: bytes) -> bytes:
    """Публичный ключ (32 байта) из закрытого (32 байта)."""
    if len(secret) != 32:
        raise ValueError("закрытый ключ Ed25519 должен содержать 32 байта")
    h = hashlib.sha512(secret).digest()
    return _encode(_mul(B, _clamp(h)))


def sign(secret: bytes, message: bytes) -> bytes:
    """Подпись (64 байта) сообщения закрытым ключом (32 байта)."""
    if len(secret) != 32:
        raise ValueError("закрытый ключ Ed25519 должен содержать 32 байта")
    h = hashlib.sha512(secret).digest()
    a = _clamp(h)
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    big_r = _mul(B, r)
    pub = _encode(_mul(B, a))
    k = int.from_bytes(hashlib.sha512(_encode(big_r) + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return _encode(big_r) + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Проверка подписи (64 байта) сообщения публичным ключом (32 байта)."""
    if len(public) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    try:
        big_a = _decode(public)
        big_r = _decode(signature[:32])
    except ValueError:
        return False
    identity = b"\x01" + b"\x00" * 31
    # Ключ и R — ненулевые точки главной подгруппы, не точки малого порядка.
    for point in (big_a, big_r):
        if _encode(point) == identity or _encode(_mul(point, L)) != identity:
            return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(),
                       "little") % L
    left = _mul(B, s)
    right = _add(big_r, _mul(big_a, k))
    return _encode(left) == _encode(right)


def signable(data: dict) -> bytes:
    """Канонические байты словаря для подписи (без поля «signature»). Подписывающая и
    проверяющая стороны обязаны использовать одну и ту же форму."""
    return json.dumps({k: v for k, v in data.items() if k != "signature"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
