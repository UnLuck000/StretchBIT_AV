from networkmonitor.connections import Conn, analyze, is_external
from networkmonitor.ioc import load_ip_blocklist

def conn(**kw):
    base = dict(pid=1, name="app.exe", exe=r"C:\Program Files\App\app.exe",
                create_time=1.0, rip="8.8.8.8", rport=443, inbound=False)
    base.update(kw)
    return Conn(**base)


def test_is_external():
    assert is_external("8.8.8.8")
    assert is_external("::ffff:8.8.8.8")
    assert not is_external("192.168.1.10")
    assert not is_external("127.0.0.1")


def test_rules():
    assert analyze(conn(), set()) == []
    assert analyze(conn(), {"8.8.8.8"})[0][:2] == ("critical", "IOC")
    assert analyze(conn(name="PowerShell.exe"), set())[0][1] == "LOLBIN"
    temp = conn(exe=r"C:\Users\me\AppData\Local\Temp\x.exe")
    assert analyze(temp, set())[0][1] == "USERDIR"


def test_load_blocklist(tmp_path):
    (tmp_path / "f.txt").write_text("# comment\n1.2.3.4\nnot-an-ip\n\n5.6.7.8\n")
    assert load_ip_blocklist(tmp_path) == {"1.2.3.4", "5.6.7.8"}


def _monitor(tmp_path, events):
    from networkmonitor.netmon import NetworkMonitor
    return NetworkMonitor(tmp_path, tmp_path, tmp_path, lambda *args: events.append(args),
                          watch_dns=False, watch_tls=False)


def test_system_periodicity_is_not_a_suspicious_process(tmp_path):
    from networkmonitor.beacon import MIN_EVENTS
    events = []
    mon = _monitor(tmp_path, events)
    for i in range(MIN_EVENTS):
        found = mon.beacons.feed("System", "", "example.invalid", 100 + i * 60, "tcp", pid=4)
        if found:
            mon._on_beacon(found)
    assert any(kind == "beacon" for kind, _ in events)
    assert not any(kind == "alert" for kind, _ in events)
    assert mon.beacons.current()[0].pid == 4


def test_fake_system_name_does_not_suppress_beacon_warning(tmp_path):
    from networkmonitor.beacon import MIN_EVENTS
    events = []
    mon = _monitor(tmp_path, events)
    for i in range(MIN_EVENTS):
        found = mon.beacons.feed("System", "", "example.invalid", 100 + i * 60, "tcp", pid=12345)
        if found:
            mon._on_beacon(found)
    alert = next(payload for kind, payload in events if kind == "alert")
    assert alert.pid == 12345 and alert.rule == "BEACON" and alert.level == "warning"


def test_system_ioc_and_ja3_are_not_whitelisted(tmp_path):
    events = []
    mon = _monitor(tmp_path, events)
    c = conn(pid=4, name="System", exe="")
    assert analyze(c, {c.rip})[0][:2] == ("critical", "IOC")
    for rule in ("IOC", "DOMAIN", "SNI", "JA3"):
        mon._alert("critical", rule, 4, "example.invalid", "test", "System", "")
    assert {payload.rule for kind, payload in events if kind == "alert"} == {
        "IOC", "DOMAIN", "SNI", "JA3"}


def test_processes_without_exe_do_not_merge_by_name():
    from networkmonitor.beacon import BeaconDetector, MIN_EVENTS
    detector = BeaconDetector()
    # Вместе событий хватило бы на маячок, но это два разных процесса.
    for i in range(MIN_EVENTS):
        assert detector.feed("System", "", "example.invalid", 100 + i * 60, "dns",
                             pid=4 if i % 2 else 12345) is None
    assert detector.current() == []
