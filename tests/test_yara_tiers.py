"""Две очереди правил YARA (15.11.2026): правила с ложными срабатываниями не отключаются, а
только подтверждают находки других слоёв; инструменты и нежелательное — «подозрительно»."""
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from scanner import engine, overrides, relations


@dataclass
class Match:
    rule: str
    namespace: str = "x"
    meta: dict = field(default_factory=dict)


@pytest.fixture
def confirm_list(monkeypatch):
    data = {"hashes": {}, "rules": {}, "files": {}, "confirm": {"Impacket": {}}}
    monkeypatch.setattr(overrides, "load", lambda: data)
    return data


def test_rule_tier(confirm_list):
    assert relations.rule_tier(Match("Impacket", meta={"category": "TOOL"})) == relations.CONFIRM
    assert relations.rule_tier(Match("Hunt_Lnk", meta={"category": "hunting"})) == relations.CONFIRM
    assert relations.rule_tier(Match("LaZagne", meta={"category": "TOOL"})) == relations.WEAK
    assert relations.rule_tier(Match("HKTL_Mimikatz")) == relations.WEAK
    assert relations.rule_tier(Match("X", meta={"score": 50})) == relations.WEAK
    assert relations.rule_tier(Match("AgentTesla", meta={"category": "MALWARE"})) == \
        relations.STRONG


def _analyze(monkeypatch, tmp_path, matches, heuristic_score=0, signature="unsigned"):
    p = tmp_path / "a.dll"
    p.write_bytes(b"MZ" + b"\0" * 100)
    monkeypatch.setattr(engine, "match_details", lambda rules, path, data=None: list(matches))
    monkeypatch.setattr(engine, "inspect_signature", lambda path: SimpleNamespace(status=signature))
    monkeypatch.setattr(engine, "_partner", lambda path: None)
    report = SimpleNamespace(score=heuristic_score, summary=lambda: "упаковщик")
    monkeypatch.setattr(engine, "analyze_pe", lambda path, data=None: report)
    return engine.analyze(p, rules=object(), threshold=60, revocation=False)


def test_confirm_alone_is_check_not_threat(confirm_list, monkeypatch, tmp_path):
    # первая очередь ничего не нашла, подписи нет — «проверить»
    reason = _analyze(monkeypatch, tmp_path, [Match("Impacket", meta={"category": "TOOL"})])
    assert reason == engine.CHECK_PREFIX + "Impacket"
    assert engine.reason_level(reason) == "suspicious"
    from analyzer.folderview import classify
    assert classify(reason)[1] == "Проверить: YARA (вторая очередь): Impacket"
    # подпись действительна — вторая очередь не учитывается
    assert _analyze(monkeypatch, tmp_path, [Match("Impacket")], signature="valid") is None
    # библиотека подписанной программы — тоже
    monkeypatch.setattr(engine, "_partner", lambda path: ("x", "Program"))
    monkeypatch.setattr(engine, "inspect_signature", lambda path: SimpleNamespace(status="unsigned"))
    p = tmp_path / "a.dll"
    assert engine.analyze(p, rules=object(), threshold=60, revocation=False) is None


def test_confirm_raises_heuristic_to_threat(confirm_list, monkeypatch, tmp_path):
    reason = _analyze(monkeypatch, tmp_path, [Match("Impacket")], heuristic_score=80)
    assert reason.startswith("YARA: Impacket (подтверждено эвристикой")
    assert engine.reason_level(reason) == "threat"


def test_weak_alone_is_suspicious(confirm_list, monkeypatch, tmp_path):
    reason = _analyze(monkeypatch, tmp_path, [Match("LaZagne", meta={"category": "TOOL"})])
    assert reason.startswith(engine.WEAK_PREFIX) and engine.reason_level(reason) == "suspicious"
    from analyzer.folderview import classify
    assert classify(reason) == ("suspicious", "Подозрительно: YARA: LaZagne")


def test_weak_confirmed_and_strong_are_threats(confirm_list, monkeypatch, tmp_path):
    reason = _analyze(monkeypatch, tmp_path, [Match("LaZagne", meta={"category": "TOOL"}),
                                              Match("Impacket")])
    assert reason == "YARA: LaZagne (подтверждают: Impacket)"
    reason = _analyze(monkeypatch, tmp_path, [Match("AgentTesla")])
    assert reason == "YARA: AgentTesla" and engine.reason_level(reason) == "threat"
    # исключение программы из слоя yara действует и на «слабую» причину
    assert overrides.filter_reason.__doc__ and engine.WEAK_PREFIX.startswith("YARA")


def test_release_overrides_keep_rules_in_second_queue():
    import json
    from pathlib import Path
    release = Path(__file__).resolve().parent.parent / "signatures" / "release_overrides.json"
    data = json.loads(release.read_text(encoding="utf-8"))  # conftest подменяет RELEASE_FILE
    assert {"Extract_MachineKey_SharePoint", "Impacket"} <= set(data["confirm"])
    assert not {"Extract_MachineKey_SharePoint", "Impacket"} & set(data["rules"])
