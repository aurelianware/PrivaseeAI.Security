"""Integration tests for the timeline engine against real 2026-08-31 log shapes.

These use inline fixtures (no PII) modelled on an actual WireGuard iOS session:
NWPathMonitor storms, isExpensive flaps, sleep/wake handshake gaps, userInitiated
server switches, and DNS64 remappings. The goal is that normal Proton/iOS churn
never scores HIGH/CRITICAL, while genuinely anomalous log-time patterns do.
"""
import datetime

import pytest

from privaseeai_security.collectors.vpn_log_parser import parse_vpn_log_lines
from privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor
from privaseeai_security.monitors.vpn_session_report import (
    render_report,
    should_warn_disconnect,
)
from privaseeai_security.crypto.cert_validator import ThreatLevel

UTC = datetime.timezone.utc


def _ts(dt):
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture
def monitor():
    return VPNIntegrityMonitor()


def _no_high_critical(report):
    return report.max_severity() not in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)


def test_scenario1_clean_udp_five_bumps_storm_low_no_high(monitor):
    """(1) Clean UDP session with 5 identical satisfied path bumps -> STORM LOW."""
    start = datetime.datetime(2026, 8, 31, 16, 13, 1, tzinfo=UTC)
    lines = []
    for i in range(5):
        t = _ts(start + datetime.timedelta(seconds=i * 10))
        lines.append(f"{t} | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.")
        lines.append(f"{t} | INFO | PROTOCOL | NWPath: Optional(")
        lines.append("\tstatus: satisfied, isExpensive: NO, isViable: NO, mtu: 1428")
        lines.append(")")
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert kinds["PATH_MONITOR_STORM"]["severity"] == ThreatLevel.LOW
    assert _no_high_critical(report)
    assert not should_warn_disconnect(report)


def test_scenario2_sleep_gap_is_info_not_forced_reconnection(monitor):
    """(2) sleep(), +20s handshake retry 15s, wake(), response -> GAP INFO."""
    start = datetime.datetime(2026, 8, 31, 16, 16, 55, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | sleep()",
        f"{_ts(start + datetime.timedelta(seconds=20))} | INFO | PROTOCOL | "
        "Retrying handshake because we stopped hearing back after 15 seconds",
        f"{_ts(start + datetime.timedelta(seconds=45))} | INFO | PROTOCOL | wake()",
        f"{_ts(start + datetime.timedelta(seconds=46))} | INFO | PROTOCOL | "
        "Receiving handshake response from peer rPDCApAI",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert kinds["SLEEP_HANDSHAKE_GAP"]["severity"] == ThreatLevel.INFO
    assert "FORCED_RECONNECTION" not in kinds
    assert _no_high_critical(report)


def test_scenario3_user_stop_new_peer_new_dns64_is_peer_switch_no_hopping(monitor):
    """(3) userInitiated stop + new peer + DNS64 new IP -> PEER_SWITCH INFO, no hop."""
    start = datetime.datetime(2026, 8, 31, 17, 17, 52, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | Receiving handshake response from peer rPDCApAI",
        f"{_ts(start + datetime.timedelta(seconds=1))} | INFO | PROTOCOL | DNS64: mapped 185.159.158.193 to itself.",
        f"{_ts(start + datetime.timedelta(seconds=2))} | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)",
        f"{_ts(start + datetime.timedelta(seconds=5))} | INFO | PROTOCOL | Starting tunnel",
        f"{_ts(start + datetime.timedelta(seconds=6))} | INFO | PROTOCOL | Receiving handshake response from peer cxkp3kDI",
        f"{_ts(start + datetime.timedelta(seconds=7))} | INFO | PROTOCOL | DNS64: mapped 185.159.158.200 to itself.",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert kinds["PEER_SWITCH"]["severity"] == ThreatLevel.INFO
    assert "DNS64_IP_HOPPING" not in kinds
    assert "UNEXPECTED_PEER_SWITCH" not in kinds
    assert _no_high_critical(report)


def test_scenario4_four_dns64_in_seven_minutes_log_time_is_medium(monitor):
    """(4) Four DNS64 IPs in 7 min of LOG time, no user stop -> hopping MEDIUM."""
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    ips = ["185.159.157.99", "185.159.156.78", "185.159.158.12", "185.159.159.45"]
    lines = []
    for i, ip in enumerate(ips):
        t = _ts(start + datetime.timedelta(minutes=i * 2, seconds=15))
        lines.append(f"{t} | INFO | VPN | DNS64: mapped {ip} to itself.")
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert kinds["DNS64_IP_HOPPING"]["severity"] == ThreatLevel.MEDIUM


def test_scenario5_tcp_then_udp_no_transport_manipulation(monitor):
    """(5) socketType tcp then 2 min later udp -> no transport-manipulation threat."""
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | New socketType value: tcp",
        f"{_ts(start + datetime.timedelta(minutes=2))} | INFO | PROTOCOL | New socketType value: udp",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"] for j in report.judgments}
    assert "TRANSPORT_TCP_PERSISTENT" not in kinds
    assert _no_high_critical(report)

    # And per-line observation is INFO, not a manipulation attack.
    det = monitor.analyze_transport_protocol(lines[0])
    assert det.attack_type == "TRANSPORT_TCP"
    assert det.threat_level == ThreatLevel.INFO


def test_scenario6_historical_log_uses_log_time_not_utcnow(monitor):
    """(6) utcnow() regression: a Jan-2026 log scanned "now" must use Jan-2026.

    Four DNS64 IPs are stamped 2026-01-26 but spread three hours apart. Using
    wall-clock time (scanning in Aug 2026) they would all land in one "recent"
    window and falsely trigger hopping. Using LOG time they are far apart, so no
    hopping fires.
    """
    base = datetime.datetime(2026, 1, 26, 4, 20, 0, tzinfo=UTC)
    ips = ["185.159.157.99", "185.159.156.78", "185.159.158.12", "185.159.159.45"]
    lines = []
    for i, ip in enumerate(ips):
        t = _ts(base + datetime.timedelta(hours=i))  # 1 hour apart -> outside 10 min
        lines.append(f"{t} | INFO | VPN | DNS64: mapped {ip} to itself.")
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"] for j in report.judgments}
    assert "DNS64_IP_HOPPING" not in kinds, "must use log time, not utcnow()"

    # Same four IPs within 7 log-time minutes DO trip hopping -> proves the window
    # is anchored to log timestamps, not wall-clock.
    tight = []
    for i, ip in enumerate(ips):
        t = _ts(base + datetime.timedelta(minutes=i * 2, seconds=10))
        tight.append(f"{t} | INFO | VPN | DNS64: mapped {ip} to itself.")
    tight_report = VPNIntegrityMonitor().analyze_session(parse_vpn_log_lines(tight))
    assert "DNS64_IP_HOPPING" in {j["kind"] for j in tight_report.judgments}


def test_full_aug31_style_session_exits_clean(monitor):
    """A path-bump + keepalive + userInitiated switch session yields no HIGH."""
    start = datetime.datetime(2026, 8, 31, 16, 13, 1, tzinfo=UTC)
    lines = []
    for i in range(120):
        t = _ts(start + datetime.timedelta(seconds=i * 20))
        lines.append(f"{t} | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.")
        lines.append(f"{t} | INFO | PROTOCOL | NWPath: Optional(")
        exp = "YES" if i % 6 == 0 else "NO"
        lines.append(f"\tstatus: satisfied, isExpensive: {exp}, isViable: NO, mtu: 1428")
        lines.append(")")
        if i % 4 == 0:
            lines.append(
                f"{_ts(start + datetime.timedelta(seconds=i * 20 + 1))} | INFO | PROTOCOL | "
                "Sending keepalive packet to peer rPDCApAI"
            )
    stop = start + datetime.timedelta(minutes=45)
    lines += [
        f"{_ts(stop)} | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)",
        f"{_ts(stop + datetime.timedelta(seconds=5))} | INFO | PROTOCOL | Starting tunnel",
        f"{_ts(stop + datetime.timedelta(seconds=6))} | INFO | PROTOCOL | New socketType value: udp",
        f"{_ts(stop + datetime.timedelta(seconds=7))} | INFO | PROTOCOL | Receiving handshake response from peer cxkp3kDI",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))

    assert report.metrics["bump_count"] == 120
    assert report.metrics["bumps_per_hour"] > 60
    assert report.metrics["user_stops"] == 1
    assert report.metrics["error_lines"] == 0
    assert _no_high_critical(report)
    assert not should_warn_disconnect(report)

    text = render_report(report)
    assert "Timeline" in text
    assert "PATH_MONITOR_STORM" in text
    # The alarming guidance must not be printed for this normal session.
    assert "Disconnect immediately" not in text
