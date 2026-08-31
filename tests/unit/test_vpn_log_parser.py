"""Unit tests for the shared VPN log event parser.

Fixtures are inline strings copied from the real WireGuard/Proton iOS log line
shapes (no PII). The parser is observation-only: it records what a line said and
sources the event timestamp from the line prefix, never wall-clock time.
"""
import datetime

import pytest

from privaseeai_security.collectors.vpn_log_parser import (
    VpnLogEvent,
    parse_vpn_log_line,
    parse_vpn_log_lines,
)


def test_timestamp_is_parsed_timezone_aware_utc():
    line = "2026-08-31T16:13:01.724260Z | INFO | PROTOCOL | NWPathMonitor: bumping tunnel."
    ev = parse_vpn_log_line(line)
    assert ev is not None
    assert ev.ts == datetime.datetime(
        2026, 8, 31, 16, 13, 1, 724260, tzinfo=datetime.timezone.utc
    )
    assert ev.ts.tzinfo is not None
    assert ev.level == "INFO"
    assert ev.component == "PROTOCOL"
    assert ev.is_path_bump is True


def test_line_without_timestamp_is_skipped():
    assert parse_vpn_log_line("just some text without a prefix") is None
    events = parse_vpn_log_lines(["garbage", "more garbage"])
    assert events == []


def test_sleep_and_wake_flags():
    sleep_ev = parse_vpn_log_line(
        "2026-08-31T16:16:55.748424Z | INFO | PROTOCOL | INFO  |  | sleep() |"
    )
    assert sleep_ev is not None and sleep_ev.is_sleep is True
    wake_ev = parse_vpn_log_line(
        "2026-08-31T16:20:00.000000Z | INFO | PROTOCOL | wake()"
    )
    assert wake_ev is not None and wake_ev.is_wake is True


def test_stop_reason_user_initiated():
    ev = parse_vpn_log_line(
        "2026-08-31T17:17:52.345125Z | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)"
    )
    assert ev is not None
    assert ev.stop_reason == "userInitiated"


def test_socket_type_udp_and_tcp():
    udp = parse_vpn_log_line(
        "2026-08-31T17:17:57.770017Z | INFO | PROTOCOL | New socketType value: udp"
    )
    tcp = parse_vpn_log_line(
        "2026-08-31T17:17:57.770017Z | INFO | PROTOCOL | New socketType value: tcp"
    )
    assert udp is not None and udp.socket_type == "udp"
    assert tcp is not None and tcp.socket_type == "tcp"


def test_dns64_ip_extracted():
    ev = parse_vpn_log_line(
        "2026-08-31T17:17:57.866925Z | INFO | PROTOCOL | DNS64: mapped 185.159.158.193 to itself."
    )
    assert ev is not None
    assert ev.dns64_ip == "185.159.158.193"


def test_handshake_states():
    retry = parse_vpn_log_line(
        "2026-08-31T16:20:01.000000Z | INFO | PROTOCOL | Retrying handshake because we stopped hearing back after 15 seconds"
    )
    timeout = parse_vpn_log_line(
        "2026-08-31T16:20:02.000000Z | INFO | PROTOCOL | Handshake did not complete after 5 seconds, retrying"
    )
    response = parse_vpn_log_line(
        "2026-08-31T16:20:03.000000Z | INFO | PROTOCOL | Receiving handshake response from peer cxkp3kDI"
    )
    assert retry is not None and retry.is_handshake_retry_15s is True
    assert timeout is not None and timeout.is_handshake_timeout_5s is True
    assert response is not None and response.is_handshake_response is True
    assert response.peer == "cxkp3kDI"


def test_certificate_up_to_date_is_flagged():
    ev = parse_vpn_log_line(
        "2026-08-31T16:20:03.000000Z | INFO | PROTOCOL | Certificate seems up to date, no refresh needed"
    )
    assert ev is not None
    assert ev.is_cert_ok_refresh is True


def test_tunnel_start():
    ev = parse_vpn_log_line(
        "2026-08-31T17:17:56.000000Z | INFO | PROTOCOL | Starting tunnel"
    )
    assert ev is not None and ev.is_tunnel_start is True


def test_nwpath_multiline_block_is_folded_into_one_event():
    """A multi-line NWPath: Optional( ... ) dump attaches to ONE event."""
    lines = [
        "2026-08-31T16:13:01.700000Z | INFO | PROTOCOL | NWPath: Optional(",
        "\tstatus: satisfied,",
        "\tisExpensive: NO,",
        "\tisViable: YES,",
        "\tmtu: 1428",
        ")",
        "2026-08-31T16:13:02.000000Z | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.",
    ]
    events = parse_vpn_log_lines(lines)
    # One folded NWPath event + one bump event.
    assert len(events) == 2
    path_ev = events[0]
    assert path_ev.has_path_block is True
    assert path_ev.path_status == "satisfied"
    assert path_ev.path_expensive is False
    assert path_ev.path_viable is True
    assert path_ev.mtu == 1428
    assert events[1].is_path_bump is True


def test_nwpath_single_line_block():
    ev = parse_vpn_log_line(
        "2026-08-31T16:13:01.700000Z | INFO | PROTOCOL | "
        "NWPath: Optional( status: satisfied, isExpensive: YES, isViable: NO, mtu: 1428 )"
    )
    assert ev is not None
    assert ev.path_status == "satisfied"
    assert ev.path_expensive is True
    assert ev.path_viable is False
    assert ev.mtu == 1428


def test_line_numbers_are_preserved_across_blocks():
    lines = [
        "2026-08-31T16:13:01.700000Z | INFO | PROTOCOL | NWPath: Optional(",
        "\tstatus: satisfied",
        ")",
        "2026-08-31T16:13:05.000000Z | INFO | PROTOCOL | New socketType value: udp",
    ]
    events = parse_vpn_log_lines(lines)
    assert events[0].line_no == 1
    # The socketType event is line 4 (block consumed lines 1-3).
    assert events[1].line_no == 4
    assert events[1].socket_type == "udp"


def test_keepalive_send_and_recv():
    send = parse_vpn_log_line(
        "2026-08-31T16:14:00.000000Z | INFO | PROTOCOL | Sending keepalive packet to peer rPDCApAI"
    )
    recv = parse_vpn_log_line(
        "2026-08-31T16:14:05.000000Z | INFO | PROTOCOL | Receiving keepalive packet from peer rPDCApAI"
    )
    assert send is not None and send.is_keepalive_send is True
    assert recv is not None and recv.is_keepalive_recv is True


def test_events_sorted_are_chronological():
    lines = [
        "2026-08-31T16:13:01.000000Z | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.",
        "2026-08-31T16:13:11.000000Z | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.",
    ]
    events = parse_vpn_log_lines(lines)
    assert [e.ts for e in events] == sorted(e.ts for e in events)
