"""Профиль маршрутизации 15.11.2026: «Обход WARP», outbound по умолчанию и вкладки редактора
(«Домены и геометки», «Дополнительно» — vpn/routingtabs.py)."""
import pytest
from PySide6.QtWidgets import QApplication

from vpn import routing, xray


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


def _config(options: dict) -> dict:
    config = {"inbounds": [{"protocol": "socks", "tag": "socks-in"}],
              "outbounds": [{"tag": "proxy", "protocol": "vless"},
                            {"tag": "direct", "protocol": "freedom"},
                            {"tag": "block", "protocol": "blackhole"}],
              "routing": {"domainStrategy": "AsIs", "rules": []}}
    return xray.apply_options(config, {}, options)


def test_profile_fields_roundtrip():
    p = routing.from_dict({"name": "X", "default_outbound": "direct",
                           "rules_nowarp": "chatgpt.com\n\nopenai.com"})
    assert p.default_outbound == "direct" and p.rules_nowarp == ["chatgpt.com", "", "openai.com"]
    assert routing.from_dict({"name": "Y", "default_outbound": "куда-то"}).default_outbound \
        == "proxy"
    o = routing.options(p, download=False)
    assert o["default_outbound"] == "direct" and o["rules_nowarp"] == ["chatgpt.com", "openai.com"]
    assert "остальное напрямую" in p.summary()


def test_xray_default_outbound_and_nowarp():
    rules = _config({"default_outbound": "direct", "rules_nowarp": ["chatgpt.com"]})["routing"]["rules"]
    assert rules[-1] == {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
    nowarp = next(r for r in rules if r.get("domain") == ["domain:chatgpt.com"])
    assert nowarp["outboundTag"] == "proxy"
    plain = _config({})["routing"]["rules"]
    assert not any(r.get("network") == "tcp,udp" for r in plain)   # по умолчанию — туннель


def test_builtin_lines_by_column():
    from vpn.routingwindow import builtin_lines
    p = routing.RoutingProfile("t", "T", default_outbound="direct")
    lines = builtin_lines(p)
    assert set(lines) == set(routing.RULE_LISTS)
    assert lines["rules_direct"][-1].startswith("# всё, что не попало")
    assert lines["rules_nowarp"] == ["# WARP выключен — строки работают как «Туннель»"]


def test_domains_tab_collects(qapp):
    from vpn.routingtabs import DomainsTab
    tab = DomainsTab()
    p = routing.RoutingProfile("t", "T", rules_proxy=["geosite:youtube"])
    tab.load(p)
    tab.columns["rules_nowarp"].edit.setPlainText("chatgpt.com\n\n")
    tab.default.setCurrentIndex(tab.default.findData("direct"))
    tab.collect(p)
    assert p.rules_proxy == ["geosite:youtube"] and p.rules_nowarp == ["chatgpt.com"]
    assert p.default_outbound == "direct"
    tab.set_builtin({"rules_direct": ["geoip:ru"]})
    assert tab.columns["rules_direct"].builtin.text() == "geoip:ru"
    assert tab.columns["rules_block"].builtin.isHidden()


def test_advanced_tab_edits_rule(qapp):
    from vpn.routingtabs import AdvancedTab
    tab = AdvancedTab()
    tab.load([{"name": "Торренты", "outbound": "direct", "protocol": ["bittorrent"]}])
    assert set(tab.rows) == {"protocol", "outbound"}  # outbound есть всегда (цель правила)
    assert tab.attr_boxes["protocol"].isChecked() and not tab.attr_boxes["domain"].isChecked()
    tab._create()                                        # новое правило без условий
    assert "Условий нет" in tab.warning.text()
    tab._toggle_attr("domain", True)                     # отметка слева добавляет условие
    tab.rows["domain"].field.setPlainText("example.com\nbad domain")
    assert "с пробелом" in tab.warning.text()
    tab.rows["domain"].field.setPlainText("example.com")
    tab.rows["outbound"].field.setCurrentIndex(tab.rows["outbound"].field.findData("block"))
    rules = tab.collect()
    assert rules[1]["domain"] == ["example.com"] and rules[1]["outbound"] == "block"
    assert '"outboundTag": "block"' in tab.preview.toPlainText()
    tab._remove_condition("domain")                      # крестик чипса снимает отметку слева
    assert tab.collect()[1]["domain"] == []
    assert not tab.attr_boxes["domain"].isChecked()
    tab._move(-1)
    assert tab.collect()[0]["outbound"] == "block"
    tab._delete()
    assert [r["name"] for r in tab.collect()] == ["Торренты"]


def test_advanced_tab_singbox_options(qapp):
    """Параметры действия sing-box (route-options/reject): чекбоксы слева, предупреждения,
    предпросмотр показывает и правило sing-box."""
    from vpn.routingtabs import AdvancedTab
    tab = AdvancedTab()
    tab.load([{"name": "Фрагментация", "outbound": "direct",
               "domain_suffix": ["youtube.com"]}])
    assert not tab.attr_boxes["tls_fragment"].isChecked()
    tab._toggle_attr("tls_record_fragment", True)
    tab._toggle_attr("tls_fragment", True)          # обе фрагментации — взаимоисключение
    assert "взаимоисключающие" in tab.warning.text()
    tab._remove_condition("tls_fragment")
    tab._toggle_attr("tls_spoof", True)
    tab.rows["tls_spoof"].field.setText("youtube.com")
    tab._toggle_attr("method", True)                # method — только при блокировке
    assert "outbound = block" in tab.warning.text()
    assert "только в режиме TUN" in tab.warning.text()
    rule = tab.collect()[0]
    assert rule["tls_record_fragment"] is True and rule["tls_spoof"] == "youtube.com"
    assert rule["method"] == "default"
    preview = tab.preview.toPlainText()
    assert '"action": "route-options"' in preview and "sing-box" in preview
    tab._remove_condition("method")
    tab.rows["tls_spoof"].field.clear()
    tab._remove_condition("tls_spoof")
    tab._remove_condition("tls_record_fragment")
    assert not any(tab.collect()[0].get(k) for k in
                   ("tls_fragment", "tls_record_fragment", "tls_spoof", "method"))
    assert "sing-box" not in tab.preview.toPlainText()


def test_singbox_route_options_rule():
    """Правило «Дополнительно» с параметрами действия → правило sing-box (TUN)."""
    from vpn import singbox
    rule = routing.normalize_rule({"outbound": "direct", "domain_suffix": ["youtube.com"],
                                   "tls_fragment": True, "tls_record_fragment": True,
                                   "tls_fragment_fallback_delay": "600ms"})
    sb = singbox.sbox_rule(rule)
    assert sb["action"] == "route-options" and sb["domain_suffix"] == ["youtube.com"]
    # фрагментации взаимоисключающие: остаётся record_fragment
    assert sb["tls_record_fragment"] is True and "tls_fragment" not in sb
    block = routing.normalize_rule({"outbound": "block", "port": "443",
                                    "method": "default", "no_drop": True})
    assert singbox.sbox_rule(block) == {"port": [443], "action": "reject",
                                        "method": "default", "no_drop": True}
    # условия не переносятся (geosite) — правило не строится, параметры не «утекут» на весь трафик
    assert singbox.sbox_rule(routing.normalize_rule(
        {"outbound": "direct", "domain": ["geosite:youtube"], "tls_fragment": True})) is None
    # входящее без TUN — правило в sing-box не нужно
    assert singbox.sbox_rule(routing.normalize_rule(
        {"outbound": "direct", "inbound": ["proxy"], "tls_fragment": True})) is None
    override = routing.normalize_rule({"outbound": "proxy", "ip": ["1.2.3.4"],
                                       "override_address": "5.6.7.8",
                                       "override_port": "8443",
                                       "tls_spoof": "youtube.com",
                                       "tls_spoof_method": "wrong-checksum"})
    sb = singbox.sbox_rule(override)
    assert sb["ip_cidr"] == ["1.2.3.4/32"] and sb["override_port"] == 8443
    assert sb["tls_spoof_method"] == "wrong-checksum"
    config = singbox.build_config(10808, r"C:\x\xray.exe", advanced=[rule, block])
    rules = config["route"]["rules"]
    assert any(r.get("action") == "route-options" for r in rules)   # после sniff
    assert any(r.get("action") == "reject" and r.get("method") == "default" for r in rules)
