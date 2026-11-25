import re
from pathlib import Path

from scanner import media, overrides, verdict_cache
from scanner.hashing import data_hashes, file_hashes
from scanner.heuristics import analyze_pe, get_threshold
from scanner.relations import CONFIRM, STRONG, WEAK, rule_tier, signed_partner, weak_match
from scanner.yara_engine import match_details, rules_version
from scanner.signature import (INVALID, REVOKED, UNSIGNED, VALID, check_revocation, trusted_fast,
                               inspect_signature)

ENGINE_VERSION = "10"  # слабые признаки не разрешают автоматическое удаление
# файлы до этого размера читаются один раз: хэши, YARA и эвристика берут байты из памяти
ONE_READ_LIMIT = 32 * 1024 * 1024  # меняется вместе с логикой проверки: старые вердикты в кэше не годятся

# проверять отзыв сертификата, прежде чем по подписи признать срабатывание ложным
# (настройка scan/revocation; нужен интернет, без связи подпись считается как раньше)
_revocation = True


def set_revocation(on: bool) -> None:
    global _revocation
    _revocation = bool(on)


def revocation_enabled() -> bool:
    return _revocation


def _trusted_signature(p: Path, sig, revocation: bool):
    """Подпись, которой можно снять срабатывание: действительна и сертификат не отозван."""
    if sig.status == VALID and revocation:
        sig = check_revocation(p, sig)
    return sig


def _partner(p: Path):
    """signed_partner для движка. Сбой разбора (нарочно испорченный файл или его сосед) —
    «связи нет»: срабатывание остаётся. Без этого ошибка здесь превращала уже найденное
    совпадение правила в «файл не проверен»."""
    try:
        return signed_partner(p)
    except Exception:  # noqa: BLE001 — причина выше
        from diag.log import swallowed
        swallowed("engine: связь с подписанной программой")
        return None


def cache_version(signatures, rules, heuristics: bool = True) -> str | None:
    """Версия проверки для кэша вердиктов. None: базы неизвестного происхождения
    (например, обычное множество хэшей в тестах), кэш не используется."""
    hashes = getattr(signatures, "version", None)
    ruleset = rules_version(rules)
    if hashes is None or ruleset is None:
        return None
    threshold = get_threshold() if heuristics else "-"
    return (f"{ENGINE_VERSION}|{hashes}|{ruleset}|{overrides.version()}|{threshold}"
            f"|{int(_revocation)}")


class Finding(str):
    """Причина вместе с хэшем проверенного содержимого (для безопасного автокарантина)."""

    def __new__(cls, reason: str, sha256: str):
        obj = super().__new__(cls, reason)
        obj.sha256 = sha256
        return obj


def finding(reason: str | None, digest: str, path: Path | None = None):
    if path is not None and digest:
        from diag.anon import register_file
        register_file(path, digest)
    return Finding(reason, digest) if reason else None


def check_file(p: Path, signatures, rules=None,
               whitelist: set[str] | None = None, heuristics: bool = True,
               use_cache: bool = True) -> str | None:
    """Возвращает причину обнаружения или None, если файл чистый.
    Может бросить OSError, если файл нельзя прочитать.

    Неизменённый файл при тех же базах повторно не читается: ответ берётся из кэша."""
    st = p.stat()
    version = cache_version(signatures, rules, heuristics) if use_cache else None
    if version:
        cached = verdict_cache.get(p, st, version)
        if cached is not None:
            digest, reason = cached
            return None if whitelist and digest in whitelist else finding(reason, digest, p)
    kind = media.plain_media(p, st.st_size)  # видео и аудио: без YARA и эвристики
    if kind and st.st_size > media.MEDIA_HASH_LIMIT:
        digest, reason = "", None  # крупный медиафайл целиком не читается
    else:
        data = read_small(p, st.st_size)  # одно чтение на хэши, YARA и эвристику
        digest, md5 = data_hashes(data) if data is not None else file_hashes(p)
        if whitelist and digest in whitelist:
            return None
        found = hash_verdict(st.st_size, digest, md5, signatures)
        if found is None and not kind:
            from scanner import archive
            found = analyze(p, rules, heuristics, data=data)
            # вложенные файлы ZIP: правила — сразу, хэши сверяются с базами здесь же
            found = archive.resolve(archive.pack(found, p, data, rules), signatures,
                                    hash_verdict)
        reason = overrides.filter_reason(digest, found)
    if version:
        verdict_cache.put(p, st, version, digest, reason)
    return finding(reason, digest, p)


def hash_verdict(size: int, digest: str, md5: str, signatures) -> str | None:
    """Слой хэшей. Пустой файл есть в любой базе (MD5 d41d8cd9...): по хэшу его не судим."""
    if size > 0:
        if digest in signatures and not overrides.hash_ignored(digest):
            return "hash match"
        if md5 in signatures and not overrides.hash_ignored(md5):  # VirusShare: только MD5
            return "hash match (MD5)"
    return None


def read_small(p: Path, size: int) -> bytes | None:
    """Содержимое файла до ONE_READ_LIMIT (для одного чтения на все слои), иначе None."""
    return p.read_bytes() if size <= ONE_READ_LIMIT else None


LAUNCHER_SCHEMES = ("steam", "com.epicgames.launcher", "uplay", "origin", "origin2", "battlenet",
                    "heroic", "goggalaxy", "minecraft", "roblox-player", "discord", "spotify",
                    "ms-settings", "ms-windows-store", "tg", "zoommtg")
_URL_RE = re.compile(rb"^\s*URL\s*=\s*([a-z0-9.+\-]+):", re.I | re.M)


# причина-«подозрительно» от слабых правил YARA (инструменты, нежелательное): начинается с
# «YARA» — исключения программ из слоя yara (overrides.filter_reason) действуют и на неё
WEAK_PREFIX = "YARA (слабое): "


# только вторая очередь, подписи нет или недействительна — «проверить» (не угроза)
CHECK_PREFIX = "YARA (проверить): "


def reason_level(reason: str) -> str:
    """Уровень причины движка без интерфейса (как analyzer.folderview.classify)."""
    if reason.startswith(("Heuristic", WEAK_PREFIX, CHECK_PREFIX)):
        return "suspicious"
    return "threat"


def automatic_action(reason: str) -> bool:
    """Автодействие только по хэшу/сильному YARA, неизвестная причина — не разрешение."""
    return bool(reason) and reason.startswith(("hash match", "YARA: "))


def confirm_automatic(path: Path, stream, signatures, rules, whitelist=None) -> bool:
    """Повторная проверка неизменяемого открытого объекта перед автодействием.

    Большие файлы в пуле проверяются разными заданиями: их хэш и YARA могли читать
    разные версии пути. Поэтому одного совпавшего ожидаемого хэша недостаточно.
    """
    from scanner import archive
    from scanner.yara_engine import MAX_FILE_SIZE
    import hashlib
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    if size <= MAX_FILE_SIZE:
        data = stream.read(MAX_FILE_SIZE + 1)
        digest, md5 = data_hashes(data)
    else:
        data = None
        sha, md = hashlib.sha256(), hashlib.md5()
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            sha.update(chunk)
            md.update(chunk)
        digest, md5 = sha.hexdigest(), md.hexdigest()
    if whitelist and digest in whitelist:
        return False
    reason = hash_verdict(size, digest, md5, signatures)
    if reason is None and data is not None:
        reason = analyze(path, rules, data=data)
        reason = archive.resolve(archive.pack(reason, path, data, rules), signatures,
                                 hash_verdict)
    return automatic_action(overrides.filter_reason(digest, reason))


def compiled_rules(p: Path, data: bytes | None = None) -> bool:
    """Скомпилированные правила YARA (кэш yara_*.bin программы, заголовок «YARA»): в них
    строки всех правил, и правила совпадают сами с собой — полная проверка 15.11.2026 нашла
    десятки «угроз» в старых кэшах из Корзины. Только не исполняемые файлы: скрипт с «YARA»
    в начале так YARA не обойдёт. Хэши такие файлы проходят как обычно."""
    if p.suffix.lower() in media.EXECUTABLE_EXTS:
        return False
    if data is not None:
        return data[:4] == b"YARA"
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"YARA"
    except OSError:
        return False


def launcher_shortcut(p: Path, data: bytes | None = None) -> bool:
    """Интернет-ярлык (.url), который открывает известную программу: Steam, Epic, Discord..."""
    if p.suffix.lower() != ".url":
        return False
    try:
        text = data if data is not None else p.read_bytes()[:8192]
    except OSError:
        return False
    schemes = [s.decode("ascii", "replace").lower() for s in _URL_RE.findall(text[:8192])]
    return bool(schemes) and all(s in LAUNCHER_SCHEMES for s in schemes)


SIGNATURE_FIRST = 256 * 1024  # с этого размера у программы сначала проверяется подпись


def _large_program(p: Path, data: bytes | None) -> bool:
    """PE-файл от SIGNATURE_FIRST: проверка подписи (3–8 мс) дешевле YARA по такому файлу."""
    try:
        if data is not None:
            return len(data) >= SIGNATURE_FIRST and data[:2] == b"MZ"
        if p.stat().st_size < SIGNATURE_FIRST:
            return False
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def analyze(p: Path, rules, heuristics: bool = True, threshold: int | None = None,
            revocation: bool | None = None, data: bytes | None = None) -> str | None:
    """Слои без хэшей: YARA, эвристика PE, подпись и связь с подписанной программой.
    Выполняется и в рабочих процессах (scanner.pool), поэтому настройки передаются явно."""
    threshold = get_threshold() if threshold is None else threshold
    revocation = _revocation if revocation is None else revocation
    sig = None
    partner = False  # False: связь ещё не искали
    if _large_program(p, data):
        # Быстрый путь. При действительной подписи совпадения YARA и эвристика всё равно
        # отбрасываются (ниже), а YARA — 88% времени проверки файла: крупную подписанную
        # программу правилами не проверяем. Отозванный сертификат — обычный путь.
        sig = trusted_fast(p, inspect_signature(p), revocation)
        if sig.status == VALID:
            return None
    # Вторая очередь даёт «проверить». Только сильное правило или хэш разрешает
    # автоматическое действие: сочетание слабых/эвристических признаков этого не меняет.
    confirm: list[str] = []
    if rules is not None and not compiled_rules(p, data):
        matches = match_details(rules, p, data=data)
        if matches and launcher_shortcut(p, data):
            # ярлык игры (steam://rungameid/...): правила «Methodology» ловят любую схему,
            # кроме http — это способ запуска, а не признак вредоноса
            matches = [m for m in matches if not m.rule.startswith("Methodology_")]
        tiers = {m.rule: rule_tier(m) for m in matches}
        confirm = [m.rule for m in matches if tiers[m.rule] == CONFIRM]
        first = [m for m in matches if tiers[m.rule] != CONFIRM]
        if first:
            sig = sig or _trusted_signature(p, inspect_signature(p), revocation)
            names = ", ".join(m.rule for m in first)
            also = f" (подтверждают: {', '.join(confirm)})" if confirm else ""
            strong = any(tiers[m.rule] == STRONG for m in first)
            if sig.status == REVOKED:
                return ("YARA: " if strong else WEAK_PREFIX) + names + also + \
                    " [сертификат отозван]"
            # действительная подпись доверенного издателя (Microsoft, JetBrains...):
            # совпадение правила считается ложным, как и у эвристики ниже
            if sig.status != VALID:
                if all(weak_match(m) or tiers[m.rule] == WEAK for m in first):
                    partner = _partner(p)
                if not partner:
                    # Инструменты/нежелательное остаются подозрительными и при confirm.
                    return ("YARA: " if strong else WEAK_PREFIX) + names + also
    if heuristics:
        report = analyze_pe(p, data)
        if report.score >= threshold:
            sig = sig or _trusted_signature(p, inspect_signature(p), revocation)
            if sig.status == VALID:
                return None  # подписан доверенным издателем: эвристику не применяем
            if partner is False:
                partner = _partner(p)
            if partner:  # библиотека подписанной программы из той же папки
                return _check_reason(confirm, partner) if confirm else None
            note = {UNSIGNED: " [нет подписи]", INVALID: " [подпись недействительна]",
                    REVOKED: " [сертификат отозван]"}
            if confirm:  # коррелирующие слабые признаки — проверка, не автокарантин
                return (f"{CHECK_PREFIX}{', '.join(confirm)} (совпало с эвристикой: "
                        f"{report.summary()}){note.get(sig.status, '')}")
            return "Heuristic: " + report.summary() + note.get(sig.status, "")
    if confirm:
        # первая очередь ничего не нашла: совпадение второй — «проверить», не угроза; при
        # действительной подписи самого файла — не учитывается. Библиотека подписанной
        # программы — тоже «проверить»: подпись соседа снимает подозрение, но подмену
        # библиотеки не исключает (пожелание 15.11.2026: проверку довести до конца)
        sig = sig or _trusted_signature(p, inspect_signature(p), revocation)
        if sig.status != VALID:
            if partner is False:
                partner = _partner(p)
            return _check_reason(confirm, partner)
    return None


def _check_reason(confirm: list[str], partner) -> str:
    """«Проверить» по правилам второй очереди; partner — подписанная программа рядом."""
    name = partner[0] if isinstance(partner, tuple) and partner else ""  # (файл, как связаны)
    note = f" [библиотека подписанной программы {name}]" if name else (
        " [библиотека подписанной программы]" if partner else "")
    return CHECK_PREFIX + ", ".join(confirm) + note


def scan_tree(root: Path, signatures: set[str], rules=None,
              exclude: list[Path] | None = None, on_file=None, stop=None,
              whitelist: set[str] | None = None, heuristics: bool = True):
    """Обходит папку и выдаёт пары (путь, причина) для подозрительных файлов."""
    excluded = [e.resolve() for e in (exclude or [])]

    for p in root.rglob("*"):
        if stop is not None and stop.is_set():
            return
        try:
            if not p.is_file():
                continue
            rp = p.resolve()
            if any(e in rp.parents for e in excluded):
                continue
            if on_file:
                on_file(p)
            reason = check_file(p, signatures, rules, whitelist, heuristics)
            if reason:
                yield p, reason
        except (PermissionError, OSError):
            continue
