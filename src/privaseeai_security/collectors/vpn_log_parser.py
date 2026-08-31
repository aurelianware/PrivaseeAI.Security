"""Shared VPN log event parser.

This module turns raw WireGuard / Proton VPN (iOS Network Extension) log lines
into structured :class:`VpnLogEvent` records. It is deliberately independent of
any scoring or judgment logic: a parser records *observations only* (what the
line literally said), and higher layers (see
:mod:`privaseeai_security.monitors.vpn_integrity`) decide what, if anything,
those observations mean.

Design rules:

* The event timestamp (``ts``) is ALWAYS taken from the log line prefix. We never
  substitute ``datetime.utcnow()`` for the time an event happened -- a log scanned
  months later must still be reasoned about using the timestamps in the file.
* A line without a parseable timestamp prefix is skipped as a standalone event
  (but may be consumed as a continuation of a multi-line ``NWPath`` block).

Typical line shapes handled::

    2026-08-31T16:13:01.724260Z | INFO | PROTOCOL | NWPathMonitor: bumping tunnel.
    2026-08-31T16:16:55.748424Z | INFO | PROTOCOL | INFO  |  | sleep() |
    2026-08-31T17:17:52.345125Z | INFO | PROTOCOL | Stopping tunnel. Reason: userInitiated (1)
    2026-08-31T17:17:57.770017Z | INFO | PROTOCOL | New socketType value: udp
    2026-08-31T17:17:57.866925Z | INFO | PROTOCOL | DNS64: mapped 185.159.158.193 to itself.

Multi-line NWPath dumps are folded into the single event that opened them::

    2026-08-31T16:13:01.700000Z | INFO | PROTOCOL | NWPath: Optional(
        status: satisfied,
        isExpensive: NO,
        isViable: YES,
        mtu: 1428
    )
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional
import datetime
import re

# --------------------------------------------------------------------------- #
# Regular expressions
# --------------------------------------------------------------------------- #

# Timestamp prefix, e.g. 2026-08-31T16:13:01.724260Z
_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
)

# socketType value: udp / tcp
_SOCKET_RE = re.compile(r"socketType value:\s*(?P<sock>udp|tcp)", re.IGNORECASE)

# DNS64: mapped 185.159.158.193 [to ...]
_DNS64_RE = re.compile(r"DNS64:\s*mapped\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)

# Stopping tunnel. Reason: userInitiated (1)
_STOP_REASON_RE = re.compile(r"Reason:\s*(?P<reason>[A-Za-z][A-Za-z0-9_]*)")

# NWPath attributes -- tolerant of ":" or "=" separators and YES/NO tokens.
_EXPENSIVE_RE = re.compile(r"isExpensive\s*[:=]\s*(?P<v>YES|NO|true|false)", re.IGNORECASE)
_VIABLE_RE = re.compile(r"isViable\s*[:=]\s*(?P<v>YES|NO|true|false)", re.IGNORECASE)
_STATUS_RE = re.compile(r"status\s*[:=]\s*(?P<v>satisfied|unsatisfied|satisfiable)", re.IGNORECASE)
_MTU_RE = re.compile(r"\bmtu\s*[:=]\s*(?P<v>\d+)", re.IGNORECASE)

# WireGuard peer identifier, e.g. "from peer rPDC...ApAI" / "peer: cxkp...3kDI".
# Peer ids are base64-ish tokens; we keep it permissive but require enough length
# to avoid matching ordinary words.
_PEER_RE = re.compile(
    r"peer[:\s]+(?P<peer>[A-Za-z0-9+/=.…]{4,})",
    re.IGNORECASE,
)

_TRUE_TOKENS = {"yes", "true"}
_FALSE_TOKENS = {"no", "false"}


def _parse_timestamp(raw_ts: str) -> Optional[datetime.datetime]:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime.

    Returns ``None`` if the value cannot be parsed. A trailing ``Z`` is treated
    as ``+00:00``. Naive values are assumed to already be UTC.
    """
    text = raw_ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _yesno(token: Optional[str]) -> Optional[bool]:
    if token is None:
        return None
    t = token.strip().lower()
    if t in _TRUE_TOKENS:
        return True
    if t in _FALSE_TOKENS:
        return False
    return None


@dataclass
class VpnLogEvent:
    """A single structured observation parsed from one VPN log event.

    All boolean ``is_*`` flags describe *what the line literally said* -- never a
    judgment about whether it is good or bad. ``ts`` is always sourced from the
    log line prefix.
    """

    ts: datetime.datetime  # timezone-aware UTC, sourced from the line prefix
    raw: str
    line_no: int
    level: Optional[str] = None
    component: Optional[str] = None
    message: str = ""

    peer: Optional[str] = None
    socket_type: Optional[str] = None  # "udp" | "tcp" | None
    dns64_ip: Optional[str] = None

    path_expensive: Optional[bool] = None
    path_viable: Optional[bool] = None
    path_status: Optional[str] = None  # "satisfied" / "unsatisfied" / ...
    mtu: Optional[int] = None

    is_path_bump: bool = False
    is_sleep: bool = False
    is_wake: bool = False
    is_handshake_retry_15s: bool = False
    is_handshake_timeout_5s: bool = False
    is_handshake_response: bool = False
    is_keepalive_send: bool = False
    is_keepalive_recv: bool = False
    stop_reason: Optional[str] = None  # "userInitiated", etc.
    is_tunnel_start: bool = False
    is_cert_ok_refresh: bool = False  # "Certificate seems up to date"

    # True when a NWPath block was folded into this event.
    has_path_block: bool = False


def _classify_message(event: VpnLogEvent, text: str) -> None:
    """Populate the boolean/observation fields on ``event`` from ``text``.

    ``text`` is the full message body (including any folded NWPath block) so that
    path attributes on continuation lines are picked up.
    """
    low = text.lower()

    # NWPathMonitor bump
    if "bumping tunnel" in low or ("nwpathmonitor" in low and "bump" in low):
        event.is_path_bump = True

    # sleep()/wake()
    if "sleep()" in low:
        event.is_sleep = True
    if "wake()" in low:
        event.is_wake = True

    # Handshake states
    if "retrying handshake" in low and "15 second" in low:
        event.is_handshake_retry_15s = True
    if "handshake did not complete after 5 second" in low:
        event.is_handshake_timeout_5s = True
    if "handshake response" in low or "receiving handshake response" in low:
        event.is_handshake_response = True

    # Keepalives
    if "sending keepalive" in low:
        event.is_keepalive_send = True
    if "receiving keepalive" in low or "received keepalive" in low:
        event.is_keepalive_recv = True

    # Tunnel start / stop
    if "starting tunnel" in low:
        event.is_tunnel_start = True
    if "stopping tunnel" in low or "device closed" in low:
        m = _STOP_REASON_RE.search(text)
        if m:
            event.stop_reason = m.group("reason")

    # Certificate refresh success is NORMAL background behaviour.
    if "seems up to date" in low or ("certificate" in low and "up to date" in low):
        event.is_cert_ok_refresh = True

    # socketType
    m = _SOCKET_RE.search(text)
    if m:
        event.socket_type = m.group("sock").lower()

    # DNS64 mapping
    m = _DNS64_RE.search(text)
    if m:
        event.dns64_ip = m.group("ip")

    # Peer id (handshake / tunnel lines)
    m = _PEER_RE.search(text)
    if m:
        peer = m.group("peer").rstrip(".,)")
        # Guard against matching plain words like "peer failure".
        if peer.lower() not in {"failure", "handshake", "response"}:
            event.peer = peer

    # NWPath attributes (single-line or folded block)
    m = _STATUS_RE.search(text)
    if m:
        event.path_status = m.group("v").lower()
    m = _EXPENSIVE_RE.search(text)
    if m:
        event.path_expensive = _yesno(m.group("v"))
    m = _VIABLE_RE.search(text)
    if m:
        event.path_viable = _yesno(m.group("v"))
    m = _MTU_RE.search(text)
    if m:
        try:
            event.mtu = int(m.group("v"))
        except ValueError:
            event.mtu = None


def _split_prefix(after_ts: str) -> tuple[Optional[str], Optional[str], str]:
    """Split ``LEVEL | COMPONENT | message...`` from the post-timestamp remainder.

    The remainder normally starts with `` | LEVEL | COMPONENT | ...``. The message
    keeps everything after the component, even if it contains further `` | ``.
    """
    remainder = after_ts.strip()
    if remainder.startswith("|"):
        remainder = remainder[1:]
    raw_parts = remainder.split("|")
    stripped = [p.strip() for p in raw_parts]
    level: Optional[str] = None
    component: Optional[str] = None
    if len(raw_parts) >= 3:
        level = stripped[0] or None
        component = stripped[1] or None
        # Keep everything after the component as the message, preserving any
        # internal " | " separators of the message body.
        message = "|".join(raw_parts[2:]).strip()
    elif len(raw_parts) == 2:
        level = stripped[0] or None
        message = raw_parts[1].strip()
    else:
        message = stripped[0] if stripped else ""
    return level, component, message


def parse_vpn_log_line(line: str, line_no: int = 1) -> Optional[VpnLogEvent]:
    """Parse a single log line into a :class:`VpnLogEvent`.

    Returns ``None`` when the line has no parseable timestamp prefix. This is the
    single-line convenience wrapper; multi-line NWPath blocks require
    :func:`parse_vpn_log_lines`.
    """
    m = _TS_RE.match(line.strip())
    if not m:
        return None
    ts = _parse_timestamp(m.group("ts"))
    if ts is None:
        return None

    after_ts = line.strip()[m.end():]
    level, component, message = _split_prefix(after_ts)
    event = VpnLogEvent(
        ts=ts,
        raw=line.rstrip("\n"),
        line_no=line_no,
        level=level,
        component=component,
        message=message,
    )
    _classify_message(event, message)
    return event


def parse_vpn_log_lines(lines: Iterable[str]) -> List[VpnLogEvent]:
    """Parse an iterable of raw log lines into ordered :class:`VpnLogEvent`s.

    Handles multi-line ``NWPath: Optional(`` blocks: when a line opens such a
    block without closing it on the same line, following lines are consumed
    (until a line containing ``)``) and folded into the opening event so path
    attributes are attached to ONE event rather than lost across lines.

    Lines without a timestamp prefix that are not part of an open NWPath block
    are skipped.
    """
    raw_lines = list(lines)
    events: List[VpnLogEvent] = []
    i = 0
    n = len(raw_lines)
    while i < n:
        line = raw_lines[i]
        m = _TS_RE.match(line.strip())
        if not m:
            i += 1
            continue

        ts = _parse_timestamp(m.group("ts"))
        if ts is None:
            i += 1
            continue

        after_ts = line.strip()[m.end():]
        level, component, message = _split_prefix(after_ts)

        # Detect an unclosed NWPath block and fold continuation lines into it.
        block_text = message
        folded_block = False
        if "NWPath:" in message and "Optional(" in message and ")" not in message:
            folded_block = True
            j = i + 1
            collected = [message]
            while j < n:
                cont = raw_lines[j]
                # A continuation line that itself begins a new timestamped event
                # ends the block defensively (malformed logs).
                if _TS_RE.match(cont.strip()):
                    break
                collected.append(cont.strip())
                if ")" in cont:
                    j += 1
                    break
                j += 1
            block_text = "\n".join(collected)
            next_i = j
        else:
            next_i = i + 1

        event = VpnLogEvent(
            ts=ts,
            raw=line.rstrip("\n"),
            line_no=i + 1,
            level=level,
            component=component,
            message=message,
        )
        if folded_block:
            event.has_path_block = True
        _classify_message(event, block_text)
        events.append(event)
        i = next_i

    return events


__all__ = ["VpnLogEvent", "parse_vpn_log_line", "parse_vpn_log_lines"]
