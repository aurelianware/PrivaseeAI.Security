"""Unit tests for the VPNIntegrityMonitor session engine and new scoring policy.

These tests exercise ``analyze_session`` (observations + judgments + metrics) and
the per-line policy changes: TCP/cooldown as INFO, short-fingerprint rejection,
and log-time (not wall-clock) hopping windows.
"""
import datetime

import pytest

from privaseeai_security.collectors.vpn_log_parser import parse_vpn_log_lines
from privaseeai_security.monitors.vpn_integrity import (
    SessionReport,
    VPNIntegrityMonitor,
)
from privaseeai_security.crypto.cert_validator import ThreatLevel


UTC = datetime.timezone.utc


def _ts(dt: datetime.datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture
def monitor():
    return VPNIntegrityMonitor()


def _build_bump_lines(n: int, start: datetime.datetime, step_s: int = 10):
    lines = []
    for i in range(n):
        t = _ts(start + datetime.timedelta(seconds=i * step_s))
        lines.append(f"{t} | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.")
        lines.append(f"{t} | INFO | PROTOCOL | NWPath: Optional(")
        lines.append("\tstatus: satisfied, isExpensive: NO, isViable: YES, mtu: 1428")
        lines.append(")")
    return lines


def test_clean_udp_session_with_bumps_is_low_no_high(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 13, 1, tzinfo=UTC)
    events = parse_vpn_log_lines(_build_bump_lines(5, start))
    report = monitor.analyze_session(events)

    kinds = {j["kind"]: j for j in report.judgments}
    assert "PATH_MONITOR_STORM" in kinds
    assert kinds["PATH_MONITOR_STORM"]["severity"] == ThreatLevel.LOW
    # No HIGH/CRITICAL anywhere.
    assert report.max_severity() in (ThreatLevel.INFO, ThreatLevel.LOW, ThreatLevel.MEDIUM)
    assert report.max_severity() == ThreatLevel.LOW
    assert report.metrics["bump_count"] == 5


def test_tcp_single_line_is_info_observation(monitor):
    det = monitor.analyze_transport_protocol(
        "2026-08-31T16:00:00.000000Z | INFO | PROTOCOL | New socketType value: tcp"
    )
    assert det is not None
    assert det.attack_type == "TRANSPORT_TCP"
    assert det.threat_level == ThreatLevel.INFO


def test_cooldown_is_info_observation(monitor):
    det = monitor.detect_api_rate_limiting(
        '2026-08-31T16:00:00.000000Z | ERROR | API | {"error":"cooldown(2026-08-31 17:00:00 +0000)"}'
    )
    assert det is not None
    assert det.attack_type == "API_COOLDOWN"
    assert det.threat_level == ThreatLevel.INFO


def test_short_fingerprint_is_rejected(monitor):
    det = monitor.validate_vpn_certificate(
        "DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: 'deadbeef'"
    )
    assert det is None


def test_unknown_long_fingerprint_is_low(monitor):
    fp = "abcdef0123456789" * 4  # 64 hex chars
    det = monitor.validate_vpn_certificate(
        f"DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: '{fp}'"
    )
    assert det is not None
    assert det.threat_level == ThreatLevel.LOW
    assert det.attack_type == "UNKNOWN_CERT_FINGERPRINT"


def test_cert_up_to_date_emits_no_threat(monitor):
    det = monitor.validate_vpn_certificate(
        "2026-08-31T16:00:00.000000Z | INFO | PROTOCOL | Certificate seems up to date"
    )
    assert det is None


def test_sleep_handshake_gap_is_info_not_disruption(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | sleep()",
        f"{_ts(start + datetime.timedelta(seconds=20))} | INFO | PROTOCOL | "
        "Retrying handshake because we stopped hearing back after 15 seconds",
        f"{_ts(start + datetime.timedelta(seconds=40))} | INFO | PROTOCOL | wake()",
        f"{_ts(start + datetime.timedelta(seconds=41))} | INFO | PROTOCOL | "
        "Receiving handshake response from peer rPDCApAI",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "SLEEP_HANDSHAKE_GAP" in kinds
    assert kinds["SLEEP_HANDSHAKE_GAP"]["severity"] == ThreatLevel.INFO
    assert "FORCED_RECONNECTION" not in kinds
    assert "CONNECTION_DISRUPTION" not in kinds


def test_user_initiated_stop_makes_peer_switch_info(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | Receiving handshake response from peer rPDCApAI",
        f"{_ts(start + datetime.timedelta(seconds=30))} | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)",
        f"{_ts(start + datetime.timedelta(seconds=35))} | INFO | PROTOCOL | Starting tunnel",
        f"{_ts(start + datetime.timedelta(seconds=40))} | INFO | PROTOCOL | Receiving handshake response from peer cxkp3kDI",
        f"{_ts(start + datetime.timedelta(seconds=41))} | INFO | PROTOCOL | DNS64: mapped 185.159.158.200 to itself.",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "PEER_SWITCH" in kinds
    assert kinds["PEER_SWITCH"]["severity"] == ThreatLevel.INFO
    assert "UNEXPECTED_PEER_SWITCH" not in kinds
    # A single DNS64 IP with a user reconnect must not fire hopping.
    assert "DNS64_IP_HOPPING" not in kinds


def test_peer_switch_without_stop_is_medium(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | Receiving handshake response from peer rPDCApAI",
        f"{_ts(start + datetime.timedelta(seconds=30))} | INFO | PROTOCOL | Receiving handshake response from peer cxkp3kDI",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "UNEXPECTED_PEER_SWITCH" in kinds
    assert kinds["UNEXPECTED_PEER_SWITCH"]["severity"] == ThreatLevel.MEDIUM


def test_four_dns64_ips_in_seven_minutes_log_time_is_medium(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    ips = [
        "185.159.157.99",
        "185.159.156.78",
        "185.159.158.12",
        "185.159.159.45",
    ]
    lines = []
    for i, ip in enumerate(ips):
        t = _ts(start + datetime.timedelta(minutes=i * 2 + 0.5))  # spread over ~7 min
        lines.append(f"{t} | INFO | VPN | DNS64: mapped {ip} to itself.")
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "DNS64_IP_HOPPING" in kinds
    assert kinds["DNS64_IP_HOPPING"]["severity"] == ThreatLevel.MEDIUM


def test_expensive_flap_low_when_path_stays_viable(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = []
    for i in range(4):
        t = _ts(start + datetime.timedelta(seconds=i * 10))
        exp = "YES" if i % 2 == 0 else "NO"
        lines.append(f"{t} | INFO | PROTOCOL | NWPath: Optional(")
        lines.append(f"\tstatus: satisfied, isExpensive: {exp}, isViable: YES, mtu: 1428")
        lines.append(")")
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "EXPENSIVE_FLAP" in kinds
    assert kinds["EXPENSIVE_FLAP"]["severity"] == ThreatLevel.LOW
    assert report.metrics["expensive_flips"] >= 2


def test_metrics_use_log_time_duration(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | Starting tunnel",
        f"{_ts(start + datetime.timedelta(minutes=10))} | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    assert report.metrics["duration_seconds"] == 600.0
    assert report.metrics["user_stops"] == 1
    assert report.metrics["tunnel_starts"] == 1
    assert report.start_ts == start


def test_error_lines_counted(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | ERROR | PROTOCOL | Something failed",
        f"{_ts(start + datetime.timedelta(seconds=1))} | INFO | PROTOCOL | New socketType value: udp",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    assert report.metrics["error_lines"] == 1


def test_persistent_tcp_escalates_to_low(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | New socketType value: tcp",
        # 20 minutes later, still nothing but TCP, no user stop, no UDP recovery.
        f"{_ts(start + datetime.timedelta(minutes=20))} | INFO | PROTOCOL | Sending keepalive packet to peer rPDCApAI",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"]: j for j in report.judgments}
    assert "TRANSPORT_TCP_PERSISTENT" in kinds
    assert kinds["TRANSPORT_TCP_PERSISTENT"]["severity"] == ThreatLevel.LOW


def test_tcp_then_udp_does_not_escalate(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)
    lines = [
        f"{_ts(start)} | INFO | PROTOCOL | New socketType value: tcp",
        f"{_ts(start + datetime.timedelta(minutes=2))} | INFO | PROTOCOL | New socketType value: udp",
    ]
    report = monitor.analyze_session(parse_vpn_log_lines(lines))
    kinds = {j["kind"] for j in report.judgments}
    assert "TRANSPORT_TCP_PERSISTENT" not in kinds


def test_judgments_carry_confidence_and_alternatives(monitor):
    start = datetime.datetime(2026, 8, 31, 16, 13, 1, tzinfo=UTC)
    report = monitor.analyze_session(parse_vpn_log_lines(_build_bump_lines(5, start)))
    for j in report.judgments:
        assert 0.0 <= j["confidence"] <= 1.0
        assert isinstance(j["alternatives"], list) and len(j["alternatives"]) >= 1


def test_empty_session_returns_empty_metrics(monitor):
    report = monitor.analyze_session([])
    assert isinstance(report, SessionReport)
    assert report.judgments == []
    assert report.metrics["bump_count"] == 0
