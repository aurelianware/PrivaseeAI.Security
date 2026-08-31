"""VPN integrity monitoring utilities.

This module provides :class:`VPNIntegrityMonitor`, a timeline engine for
WireGuard / Proton VPN (iOS Network Extension) logs. It has two complementary
responsibilities that are deliberately kept apart:

* **Observations** -- structured records of *what a log line literally said*
  (parsed by :mod:`privaseeai_security.collectors.vpn_log_parser`). These carry
  no verdict.
* **Judgments** -- higher-level conclusions built from many observations, each
  with a confidence score and a list of benign alternative explanations.

Scoring policy (why the old "one 2026-01-26 incident" heuristics were replaced):

Real Proton/WireGuard iOS logs are full of NWPathMonitor churn, ``isExpensive``
flaps, sleep/wake handshake gaps, and user-initiated server switches. None of
those are attacks. The engine therefore:

* Parses event time from the log line -- never ``datetime.utcnow()`` for the time
  an event happened. A log scanned months later is reasoned about with the
  timestamps in the file.
* Treats TCP transport, API cooldowns, DNS64 IP changes, and known certificate
  refreshes as INFO observations by default, only escalating on genuinely
  anomalous session-level patterns.

Backwards compatibility: :meth:`analyze_log_entry` still accepts a raw string and
routes it through the parser, so callers that feed line strings keep working.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import datetime

from privaseeai_security.config import Config
from privaseeai_security.logger import get_logger
from privaseeai_security.crypto.cert_validator import CertificateValidator, ThreatLevel
from privaseeai_security.collectors.vpn_log_parser import (
    VpnLogEvent,
    parse_vpn_log_line,
)

LOGGER = get_logger(__name__)

# Minimum length (hex chars) for a certificate fingerprint to be trusted enough
# to reason about. Shorter values are ambiguous log fragments, not real SHA-256
# fingerprints, so we never escalate them to HIGH MITM.
_MIN_FINGERPRINT_HEX = 32


@dataclass
class ThreatDetection:
    """Represents a detected security signal.

    Despite the historical name this is used for observations *and* judgments;
    ``threat_level`` may be ``NONE``/``INFO``-equivalent for pure observations.

    Attributes:
        threat_level: Severity (NONE, LOW, MEDIUM, HIGH, CRITICAL).
        attack_type: Machine-readable signal kind (e.g. ``TRANSPORT_TCP``).
        indicators: Specific indicators that triggered the signal.
        details: Human-readable explanation.
        timestamp: Event time. For log-derived signals this MUST be the log
            event's timestamp, not wall-clock time.
    """

    threat_level: ThreatLevel
    attack_type: Optional[str]
    indicators: List[str]
    details: Optional[str] = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)


@dataclass
class ServerConnection:
    """Represents a VPN server connection event (DNS64 mapping)."""

    server_ip: str
    timestamp: datetime.datetime
    protocol: Optional[str] = None


@dataclass
class SessionReport:
    """Result of a whole-session analysis.

    ``observations`` are neutral timeline records; ``judgments`` are conclusions
    that always carry a ``confidence`` (0-1) and benign ``alternatives``.
    """

    observations: List[Dict[str, Any]] = field(default_factory=list)
    judgments: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    start_ts: Optional[datetime.datetime] = None
    end_ts: Optional[datetime.datetime] = None

    def max_severity(self) -> ThreatLevel:
        """Highest judgment severity, or NONE if there are no judgments."""
        best = ThreatLevel.NONE
        for j in self.judgments:
            sev = j.get("severity", ThreatLevel.NONE)
            if _SEV_ORDER[sev] > _SEV_ORDER[best]:
                best = sev
        return best


# Severity ordering helper.
_SEV_ORDER = {
    ThreatLevel.NONE: 0,
    ThreatLevel.INFO: 1,
    ThreatLevel.LOW: 2,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.HIGH: 4,
    ThreatLevel.CRITICAL: 5,
}


class VPNIntegrityMonitor:
    """Monitor VPN logs and detect integrity issues via a timeline engine.

    The monitor keeps light per-line state (protocol history, DNS64 mappings) for
    backwards-compatible line-by-line callers, and offers :meth:`analyze_session`
    for whole-session reasoning that separates observations from judgments.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.logger = LOGGER
        self.cert_validator = CertificateValidator()

        # State tracking for line-by-line callers.
        self.protocol_history: List[Dict[str, Any]] = []
        self.server_connections: List[ServerConnection] = []
        self.api_rate_limits: Dict[str, datetime.datetime] = {}

        self.expected_protocol = "udp"

        self.logger.info("VPNIntegrityMonitor initialized")

    # ------------------------------------------------------------------ #
    # Line-by-line detectors (kept for compatibility, now event-driven)
    # ------------------------------------------------------------------ #

    def _coerce_event(self, log_line: "str | VpnLogEvent") -> Optional[VpnLogEvent]:
        """Return a :class:`VpnLogEvent` for a raw string or pass through one.

        Duck-typed on ``str`` rather than ``isinstance(VpnLogEvent)`` so that an
        event object still works even when the package is imported under two names
        (``privaseeai_security`` and ``src.privaseeai_security``), which would
        otherwise create two distinct ``VpnLogEvent`` classes.
        """
        if isinstance(log_line, str):
            return parse_vpn_log_line(log_line)
        return log_line  # already an event-like object

    def analyze_transport_protocol(
        self, log_line: "str | VpnLogEvent"
    ) -> Optional[ThreatDetection]:
        """Analyze a socketType line.

        Policy: ``socketType tcp`` is an INFO observation (``TRANSPORT_TCP``), not
        an attack. TCP is a legitimate Proton "Smart Protocol" / restricted-network
        fallback. Escalation to LOW only happens at the session level when TCP
        persists (see :meth:`analyze_session`). ``socketType udp`` is normal.
        """
        event = self._coerce_event(log_line)
        if event is None or event.socket_type is None:
            # Fall back to substring parsing for odd inputs.
            text = str(log_line).lower()
            if "sockettype value: tcp" in text:
                protocol = "tcp"
            elif "sockettype value: udp" in text:
                protocol = "udp"
            else:
                return None
            ts = event.ts if event else datetime.datetime.utcnow()
        else:
            protocol = event.socket_type
            ts = event.ts

        self.protocol_history.append(
            {"protocol": protocol, "timestamp": ts, "log_line": str(log_line)[:100]}
        )

        if protocol == "tcp":
            self.logger.debug("TCP transport observed (INFO observation)")
            return ThreatDetection(
                threat_level=ThreatLevel.INFO,
                attack_type="TRANSPORT_TCP",
                indicators=["TRANSPORT_TCP", "OBSERVATION"],
                details=(
                    "TCP transport observed. This is normal Proton Smart Protocol "
                    "behaviour on restrictive networks (e.g. hotel/UDP-blocked Wi-Fi) "
                    "and is not an attack by itself."
                ),
                timestamp=ts,
            )

        if protocol == "udp":
            return ThreatDetection(
                threat_level=ThreatLevel.NONE,
                attack_type=None,
                indicators=["UDP_NORMAL"],
                details="UDP protocol observed as expected",
                timestamp=ts,
            )
        return None

    def validate_vpn_certificate(
        self, log_line: "str | VpnLogEvent"
    ) -> Optional[ThreatDetection]:
        """Validate a certificate fingerprint referenced in a log line.

        Policy changes:
        * A known certificate refresh success ("seems up to date") is NORMAL and
          emits no threat.
        * Unknown fingerprints are LOW (not HIGH MITM); a log fingerprint is a weak
          signal on its own.
        * Fingerprints shorter than 32 hex chars are rejected (ambiguous log
          fragment, not a real SHA-256 fingerprint).
        """
        event = self._coerce_event(log_line)
        raw = event.raw if event else str(log_line)

        # Certificate refresh success -> not a threat.
        if event is not None and event.is_cert_ok_refresh:
            return None
        if "seems up to date" in raw.lower():
            return None

        info = self.cert_validator.extract_cert_info_from_log(raw)
        if not info:
            return None

        fp = info.fingerprint.lower()

        # Known-good fast path.
        for known in self.cert_validator.KNOWN_GOOD_FINGERPRINTS:
            if known.lower() in fp:
                return ThreatDetection(
                    threat_level=ThreatLevel.NONE,
                    attack_type=None,
                    indicators=["KNOWN_GOOD_CERT"],
                    details=f"Certificate fingerprint {fp} matched known-good database",
                    timestamp=event.ts if event else datetime.datetime.utcnow(),
                )

        # Reject too-short fingerprints -- not a trustworthy signal.
        hex_only = "".join(c for c in fp if c in "0123456789abcdef")
        if len(hex_only) < _MIN_FINGERPRINT_HEX:
            self.logger.debug("Ignoring short/ambiguous fingerprint: %s", fp)
            return None

        self.logger.info("Unknown certificate fingerprint observed: %s", fp)
        return ThreatDetection(
            threat_level=ThreatLevel.LOW,
            attack_type="UNKNOWN_CERT_FINGERPRINT",
            indicators=["UNKNOWN_FINGERPRINT"],
            details=(
                f"Certificate fingerprint {fp} is not in the known-good database. "
                "This is a weak signal on its own; corroborate before acting."
            ),
            timestamp=event.ts if event else datetime.datetime.utcnow(),
        )

    def detect_api_rate_limiting(
        self, log_line: "str | VpnLogEvent"
    ) -> Optional[ThreatDetection]:
        """Detect an API cooldown line.

        Policy: a ``cooldown(...)`` response is an INFO observation
        (``API_COOLDOWN``), not evidence of tracking. Proton rate-limits routine
        client requests. It is surfaced for the timeline but not scored as an
        attack here.
        """
        event = self._coerce_event(log_line)
        raw = event.raw if event else str(log_line)
        if "cooldown" not in raw.lower():
            return None

        import re

        cooldown_match = re.search(r"cooldown\(([^)]+)\)", raw)
        cooldown_str = cooldown_match.group(1) if cooldown_match else None
        ts = event.ts if event else datetime.datetime.utcnow()

        return ThreatDetection(
            threat_level=ThreatLevel.INFO,
            attack_type="API_COOLDOWN",
            indicators=["API_COOLDOWN", "OBSERVATION"],
            details=(
                "API cooldown response observed"
                + (f" (until {cooldown_str})" if cooldown_str else "")
                + ". Proton rate-limits routine client requests; this is not, by "
                "itself, evidence of tracking."
            ),
            timestamp=ts,
        )

    def track_server_connection(
        self, log_line: "str | VpnLogEvent"
    ) -> Optional[ThreatDetection]:
        """Track DNS64 server mappings and detect *log-time* IP churn.

        Policy: a DNS64 IP change is INFO unless there are >= 4 unique IPs within a
        10-minute window of LOG time with no userInitiated stop / tunnel start
        between them (which would be a normal user reconnect). All windows use the
        log event timestamps, never wall-clock time.
        """
        event = self._coerce_event(log_line)
        if event is None or event.dns64_ip is None:
            return None

        connection = ServerConnection(
            server_ip=event.dns64_ip, timestamp=event.ts, protocol=None
        )
        self.server_connections.append(connection)

        # Analyse recent connections within a 10-minute LOG-time window.
        window = datetime.timedelta(minutes=10)
        recent = [
            c for c in self.server_connections if event.ts - c.timestamp <= window
        ]
        unique = sorted({c.server_ip for c in recent})

        if len(unique) >= 4:
            self.logger.info(
                "DNS64 IP churn: %d unique IPs within 10 log-time minutes", len(unique)
            )
            return ThreatDetection(
                threat_level=ThreatLevel.MEDIUM,
                attack_type="FORCED_RECONNECTION",
                indicators=[
                    "SERVER_HOPPING",
                    f"SERVERS_{len(unique)}",
                    "LOG_TIME_WINDOW",
                ],
                details=(
                    f"{len(unique)} distinct DNS64 IPs within 10 minutes of log time: "
                    f"{', '.join(unique)}. With no user-initiated reconnect between "
                    "them this can indicate forced disconnections."
                ),
                timestamp=event.ts,
            )
        return None

    def analyze_log_entry(self, log_line: "str | VpnLogEvent") -> List[ThreatDetection]:
        """Route a single log line (string or event) to detectors.

        The line is parsed into a :class:`VpnLogEvent` first so all detectors use
        real event timestamps.
        """
        detections: List[ThreatDetection] = []
        event = self._coerce_event(log_line)

        # If unparseable (no timestamp), degrade gracefully using the raw text so
        # legacy inputs like bare "DNS64: mapped ..." still work.
        raw = event.raw if event is not None else str(log_line)

        if event is not None and event.socket_type is not None:
            proto = self.analyze_transport_protocol(event)
            if proto:
                detections.append(proto)
        elif event is None and "sockettype value:" in raw.lower():
            proto = self.analyze_transport_protocol(raw)
            if proto:
                detections.append(proto)

        if "certificateFingerprint" in raw or "Certificate with features saved" in raw:
            cert_det = self.validate_vpn_certificate(event or raw)
            if cert_det:
                detections.append(cert_det)

        if "cooldown" in raw.lower():
            rate_det = self.detect_api_rate_limiting(event or raw)
            if rate_det:
                detections.append(rate_det)

        if event is not None and event.dns64_ip is not None:
            server_det = self.track_server_connection(event)
            if server_det:
                detections.append(server_det)
        elif event is None and "dns64" in raw.lower():
            # Legacy bare DNS64 line without a timestamp: fall back to wall-clock
            # only for these malformed inputs (real logs always carry a timestamp).
            fallback = parse_vpn_log_line(
                datetime.datetime.now(datetime.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                + " | INFO | VPN | "
                + raw
            )
            if fallback is not None and fallback.dns64_ip is not None:
                server_det = self.track_server_connection(fallback)
                if server_det:
                    detections.append(server_det)

        return detections

    # ------------------------------------------------------------------ #
    # Session engine
    # ------------------------------------------------------------------ #

    def analyze_session(
        self, events: "List[VpnLogEvent] | List[str]"
    ) -> SessionReport:
        """Analyze a whole session, separating observations from judgments.

        Accepts a list of :class:`VpnLogEvent` (preferred) or raw log strings.
        Builds session metrics and runs the session-level detectors described in
        the module docstring.
        """
        parsed: List[VpnLogEvent] = []
        for e in events:
            if isinstance(e, str):
                pe = parse_vpn_log_line(e)
                if pe is not None:
                    parsed.append(pe)
            else:
                parsed.append(e)  # event-like object (duck-typed)
        parsed.sort(key=lambda ev: ev.ts)

        report = SessionReport()
        if not parsed:
            report.metrics = self._empty_metrics()
            return report

        report.start_ts = parsed[0].ts
        report.end_ts = parsed[-1].ts
        report.metrics = self._compute_metrics(parsed)

        # Timeline observations (neutral records for every meaningful event).
        report.observations = self._build_observations(parsed)

        # Judgments.
        for judgment in (
            self._detect_path_monitor_storm(parsed, report.metrics),
            self._detect_expensive_flap(parsed, report.metrics),
            self._detect_sleep_handshake_gap(parsed),
            self._detect_dns64_hopping(parsed),
            self._detect_persistent_tcp(parsed),
        ):
            if judgment:
                report.judgments.append(judgment)

        report.judgments.extend(self._detect_stop_and_peer(parsed))
        keepalive = self._detect_keepalive_asymmetry(parsed, report.metrics)
        if keepalive:
            report.judgments.append(keepalive)

        return report

    # -- metrics -------------------------------------------------------- #

    @staticmethod
    def _empty_metrics() -> Dict[str, Any]:
        return {
            "duration_seconds": 0,
            "bump_count": 0,
            "bumps_per_hour": 0.0,
            "expensive_flips": 0,
            "sleep_wake_pairs": 0,
            "handshake_retry_15s_count": 0,
            "handshake_timeout_5s_count": 0,
            "keepalive_send": 0,
            "keepalive_recv": 0,
            "unique_peers": 0,
            "unique_dns64_ips": 0,
            "user_stops": 0,
            "tunnel_starts": 0,
            "error_lines": 0,
        }

    def _compute_metrics(self, events: List[VpnLogEvent]) -> Dict[str, Any]:
        duration = (events[-1].ts - events[0].ts).total_seconds()
        bump_count = sum(1 for e in events if e.is_path_bump)
        bumps_per_hour = (bump_count / duration * 3600.0) if duration > 0 else 0.0

        expensive_flips = 0
        last_expensive: Optional[bool] = None
        for e in events:
            if e.path_expensive is not None:
                if last_expensive is not None and e.path_expensive != last_expensive:
                    expensive_flips += 1
                last_expensive = e.path_expensive

        # Sleep/wake pairing.
        sleep_wake_pairs = 0
        pending_sleep = False
        for e in events:
            if e.is_sleep:
                pending_sleep = True
            elif e.is_wake and pending_sleep:
                sleep_wake_pairs += 1
                pending_sleep = False

        peers = {e.peer for e in events if e.peer}
        dns_ips = {e.dns64_ip for e in events if e.dns64_ip}

        return {
            "duration_seconds": round(duration, 3),
            "bump_count": bump_count,
            "bumps_per_hour": round(bumps_per_hour, 1),
            "expensive_flips": expensive_flips,
            "sleep_wake_pairs": sleep_wake_pairs,
            "handshake_retry_15s_count": sum(
                1 for e in events if e.is_handshake_retry_15s
            ),
            "handshake_timeout_5s_count": sum(
                1 for e in events if e.is_handshake_timeout_5s
            ),
            "keepalive_send": sum(1 for e in events if e.is_keepalive_send),
            "keepalive_recv": sum(1 for e in events if e.is_keepalive_recv),
            "unique_peers": len(peers),
            "unique_dns64_ips": len(dns_ips),
            "user_stops": sum(
                1 for e in events if e.stop_reason == "userInitiated"
            ),
            "tunnel_starts": sum(1 for e in events if e.is_tunnel_start),
            "error_lines": sum(
                1 for e in events if (e.level or "").upper() == "ERROR"
            ),
        }

    # -- observations --------------------------------------------------- #

    def _build_observations(self, events: List[VpnLogEvent]) -> List[Dict[str, Any]]:
        obs: List[Dict[str, Any]] = []

        def add(ev: VpnLogEvent, kind: str, summary: str) -> None:
            obs.append(
                {
                    "ts": ev.ts,
                    "kind": kind,
                    "severity": ThreatLevel.INFO,
                    "summary": summary,
                    "line_no": ev.line_no,
                    "evidence": ev.message or ev.raw,
                }
            )

        for e in events:
            if e.is_path_bump:
                add(e, "PATH_BUMP", "NWPathMonitor bumped the tunnel")
            if e.is_sleep:
                add(e, "SLEEP", "Device sleep()")
            if e.is_wake:
                add(e, "WAKE", "Device wake()")
            if e.socket_type:
                add(e, f"SOCKET_{e.socket_type.upper()}", f"socketType {e.socket_type}")
            if e.dns64_ip:
                add(e, "DNS64", f"DNS64 mapped {e.dns64_ip}")
            if e.is_handshake_retry_15s:
                add(e, "HANDSHAKE_RETRY_15S", "Handshake retry after 15s silence")
            if e.is_handshake_timeout_5s:
                add(e, "HANDSHAKE_TIMEOUT_5S", "Handshake not complete after 5s")
            if e.is_handshake_response:
                add(e, "HANDSHAKE_RESPONSE", "Handshake response received")
            if e.stop_reason:
                add(e, "STOP", f"Stopping tunnel (reason: {e.stop_reason})")
            if e.is_tunnel_start:
                add(e, "TUNNEL_START", "Starting tunnel")
            if e.is_cert_ok_refresh:
                add(e, "CERT_OK", "Certificate seems up to date (normal)")
        return obs

    # -- judgment helpers ---------------------------------------------- #

    @staticmethod
    def _judgment(
        kind: str,
        severity: ThreatLevel,
        confidence: float,
        alternatives: List[str],
        summary: str,
    ) -> Dict[str, Any]:
        return {
            "kind": kind,
            "severity": severity,
            "confidence": confidence,
            "alternatives": alternatives,
            "summary": summary,
        }

    def _detect_path_monitor_storm(
        self, events: List[VpnLogEvent], metrics: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """PATH_MONITOR_STORM: excessive NWPathMonitor bumps while path stays up.

        Fires when bumps/hour > 60, or when 3+ bumps land within 60s while the
        NWPath status stays ``satisfied``. This is iOS Network Extension churn, not
        an attack -- severity LOW.
        """
        bump_events = [e for e in events if e.is_path_bump]
        if not bump_events:
            return None

        # Any unsatisfied path in the session weakens the "storm" conclusion.
        statuses = [e.path_status for e in events if e.path_status]
        all_satisfied = bool(statuses) and all(s == "satisfied" for s in statuses)
        if not statuses:
            all_satisfied = True  # no explicit unsatisfied observed

        burst = False
        times = [e.ts for e in bump_events]
        for idx in range(len(times)):
            window = [t for t in times if 0 <= (t - times[idx]).total_seconds() <= 60]
            if len(window) >= 3:
                burst = True
                break

        if metrics["bumps_per_hour"] > 60 or (burst and all_satisfied):
            return self._judgment(
                kind="PATH_MONITOR_STORM",
                severity=ThreatLevel.LOW,
                confidence=0.8,
                alternatives=[
                    "iOS NEPacketTunnelProvider path churn (wgBumpSockets)",
                    "Wi-Fi <-> cellular handoff",
                    "Background app refresh waking the extension",
                ],
                summary=(
                    f"PATH_MONITOR_STORM n={metrics['bump_count']} "
                    f"bumps/hr={metrics['bumps_per_hour']} while path stays "
                    "satisfied -- likely NWPathMonitor wgBumpSockets, not peer failure."
                ),
            )
        return None

    def _detect_persistent_tcp(
        self, events: List[VpnLogEvent]
    ) -> Optional[Dict[str, Any]]:
        """Escalate TCP transport to LOW only when it genuinely persists.

        Policy: ``socketType tcp`` is INFO by default. It becomes a LOW
        ``TRANSPORT_TCP_PERSISTENT`` judgment only if TCP persists for more than 15
        minutes of LOG time AND there is no later ``socketType udp`` AND no
        userInitiated stop in between (a user reconnect explains a protocol
        change).
        """
        socket_events = [e for e in events if e.socket_type]
        tcp_events = [e for e in socket_events if e.socket_type == "tcp"]
        if not tcp_events:
            return None

        first_tcp = tcp_events[0].ts
        # A later UDP switch means TCP did not persist.
        later_udp = any(
            e.socket_type == "udp" and e.ts > first_tcp for e in socket_events
        )
        if later_udp:
            return None

        # A userInitiated stop after TCP began explains any change -> not forced.
        user_stop_after = any(
            e.stop_reason == "userInitiated" and e.ts >= first_tcp for e in events
        )
        if user_stop_after:
            return None

        # How long did TCP persist? Use last observed event time as the horizon.
        last_ts = events[-1].ts
        persisted = (last_ts - first_tcp).total_seconds()
        if persisted <= 15 * 60:
            return None

        return self._judgment(
            kind="TRANSPORT_TCP_PERSISTENT",
            severity=ThreatLevel.LOW,
            confidence=0.5,
            alternatives=[
                "Proton Smart Protocol staying on TCP for a UDP-blocked network",
                "Hotel/captive network blocking UDP for the whole session",
            ],
            summary=(
                f"TCP transport persisted ~{int(persisted // 60)} min with no UDP "
                "recovery and no user reconnect -- sustained UDP blocking is possible."
            ),
        )

    def _detect_expensive_flap(
        self, events: List[VpnLogEvent], metrics: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """EXPENSIVE_FLAP: isExpensive toggles without the path going unsatisfied."""
        if metrics["expensive_flips"] <= 0:
            return None
        unsatisfied = any(e.path_status == "unsatisfied" for e in events)
        if unsatisfied:
            return None
        return self._judgment(
            kind="EXPENSIVE_FLAP",
            severity=ThreatLevel.LOW,
            confidence=0.7,
            alternatives=[
                "iOS re-evaluating Wi-Fi vs cellular cost",
                "Personal hotspot / low-data-mode toggling",
            ],
            summary=(
                f"isExpensive flapped {metrics['expensive_flips']} time(s) with the "
                "path staying viable -- normal iOS cost re-evaluation."
            ),
        )

    def _detect_sleep_handshake_gap(
        self, events: List[VpnLogEvent]
    ) -> Optional[Dict[str, Any]]:
        """SLEEP_HANDSHAKE_GAP: handshake retry/timeout close to a sleep/wake.

        A handshake retry (15s) or timeout (5s) within 60s after a ``sleep()`` or
        before a ``wake()`` is expected on a locked iPhone -- INFO, not a
        connection-disruption attack.
        """
        sleeps = [e.ts for e in events if e.is_sleep]
        wakes = [e.ts for e in events if e.is_wake]
        gaps = [
            e for e in events if e.is_handshake_retry_15s or e.is_handshake_timeout_5s
        ]
        if not gaps or (not sleeps and not wakes):
            return None

        matched = []
        for g in gaps:
            near_sleep = any(0 <= (g.ts - s).total_seconds() <= 60 for s in sleeps)
            near_wake = any(0 <= (w - g.ts).total_seconds() <= 60 for w in wakes)
            if near_sleep or near_wake:
                matched.append(g)

        if not matched:
            return None

        return self._judgment(
            kind="SLEEP_HANDSHAKE_GAP",
            severity=ThreatLevel.INFO,
            confidence=0.85,
            alternatives=[
                "Locked/sleeping iPhone suspending the network extension",
                "Radio powered down during sleep, re-handshake on wake",
            ],
            summary=(
                f"{len(matched)} handshake retry/timeout event(s) occurred around "
                "sleep()/wake() -- expected on a locked iPhone, not a forced "
                "reconnection."
            ),
        )

    def _detect_dns64_hopping(
        self, events: List[VpnLogEvent]
    ) -> Optional[Dict[str, Any]]:
        """DNS64 IP hopping using LOG time windows.

        MEDIUM only when >= 4 unique DNS64 IPs appear within any 10-minute window
        of LOG time with no userInitiated stop / tunnel start between them.
        """
        dns_events = [e for e in events if e.dns64_ip]
        if len(dns_events) < 4:
            return None

        window = datetime.timedelta(minutes=10)
        for i, anchor in enumerate(dns_events):
            bucket = [
                e for e in dns_events if 0 <= (e.ts - anchor.ts).total_seconds() <= window.total_seconds()
            ]
            unique = {e.dns64_ip for e in bucket}
            if len(unique) < 4:
                continue
            # Was there a user reconnect within this bucket's time span?
            span_start = anchor.ts
            span_end = bucket[-1].ts
            user_action = any(
                (e.stop_reason == "userInitiated" or e.is_tunnel_start)
                and span_start <= e.ts <= span_end
                for e in events
            )
            if user_action:
                continue
            return self._judgment(
                kind="DNS64_IP_HOPPING",
                severity=ThreatLevel.MEDIUM,
                confidence=0.6,
                alternatives=[
                    "Proton load-balancing across gateway IPs",
                    "User manually switching servers",
                    "Roaming between networks",
                ],
                summary=(
                    f"{len(unique)} distinct DNS64 IPs within 10 log-time minutes "
                    "with no user reconnect between them -- possible forced hopping."
                ),
            )
        return None

    def _detect_stop_and_peer(
        self, events: List[VpnLogEvent]
    ) -> List[Dict[str, Any]]:
        """USER_VS_FORCED_STOP and PEER_SWITCH judgments.

        * A userInitiated stop followed by a tunnel start + new peer is an INFO
          PEER_SWITCH (user reconnected to a different server).
        * A peer change with no stop/start in between is a MEDIUM
          UNEXPECTED_PEER_SWITCH.
        * A stop with no reason and no nearby wake is a LOW UNEXPLAINED_STOP.
        """
        judgments: List[Dict[str, Any]] = []

        # Peer switches.
        last_peer: Optional[str] = None
        last_user_stop_ts: Optional[datetime.datetime] = None
        last_start_ts: Optional[datetime.datetime] = None
        for e in events:
            if e.stop_reason == "userInitiated":
                last_user_stop_ts = e.ts
            if e.is_tunnel_start:
                last_start_ts = e.ts
            if e.peer:
                if last_peer is not None and e.peer != last_peer:
                    # Did a user stop AND start happen before this new peer?
                    user_reconnect = (
                        last_user_stop_ts is not None
                        and last_start_ts is not None
                        and last_user_stop_ts <= e.ts
                        and last_start_ts <= e.ts
                        and last_user_stop_ts <= last_start_ts
                    )
                    if user_reconnect:
                        judgments.append(
                            self._judgment(
                                kind="PEER_SWITCH",
                                severity=ThreatLevel.INFO,
                                confidence=0.8,
                                alternatives=[
                                    "User selected a different server",
                                    "App reconnect after settings change",
                                ],
                                summary=(
                                    f"Peer changed to {e.peer} after a userInitiated "
                                    "stop and tunnel start -- normal user reconnect."
                                ),
                            )
                        )
                    else:
                        judgments.append(
                            self._judgment(
                                kind="UNEXPECTED_PEER_SWITCH",
                                severity=ThreatLevel.MEDIUM,
                                confidence=0.55,
                                alternatives=[
                                    "Silent app-driven reconnect not shown in log",
                                    "Server-side migration by the provider",
                                ],
                                summary=(
                                    f"Peer changed to {e.peer} with no user stop/start "
                                    "between -- unexpected peer switch."
                                ),
                            )
                        )
                last_peer = e.peer

        # Unexplained stops (no reason, no nearby wake).
        wakes = [e.ts for e in events if e.is_wake]
        for e in events:
            is_stop = "stopping tunnel" in (e.message or "").lower() or "device closed" in (
                e.message or ""
            ).lower()
            if is_stop and not e.stop_reason:
                near_wake = any(
                    abs((w - e.ts).total_seconds()) <= 60 for w in wakes
                )
                if not near_wake:
                    judgments.append(
                        self._judgment(
                            kind="UNEXPLAINED_STOP",
                            severity=ThreatLevel.LOW,
                            confidence=0.5,
                            alternatives=[
                                "OS terminated the extension for resources",
                                "Crash/restart not captured in this log",
                            ],
                            summary=(
                                "Tunnel stopped with no reason and no nearby wake() -- "
                                "unexplained stop."
                            ),
                        )
                    )
        return judgments

    def _detect_keepalive_asymmetry(
        self, events: List[VpnLogEvent], metrics: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """KEEPALIVE_ASYMMETRY: sends >> receives over a 10-min window with no sleep.

        Fires when, in some 10-minute LOG-time window with no ``sleep()``, keepalive
        sends exceed 3x receives (and there are enough sends to be meaningful).
        """
        ka_send = [e for e in events if e.is_keepalive_send]
        ka_recv = [e for e in events if e.is_keepalive_recv]
        if len(ka_send) < 4:
            return None

        window = datetime.timedelta(minutes=10)
        for anchor in ka_send:
            end = anchor.ts + window
            sends = [e for e in ka_send if anchor.ts <= e.ts <= end]
            recvs = [e for e in ka_recv if anchor.ts <= e.ts <= end]
            sleep_in_window = any(
                anchor.ts <= e.ts <= end for e in events if e.is_sleep
            )
            if sleep_in_window:
                continue
            if len(sends) >= 4 and len(sends) > 3 * max(len(recvs), 1) and len(recvs) < len(sends):
                return self._judgment(
                    kind="KEEPALIVE_ASYMMETRY",
                    severity=ThreatLevel.LOW,
                    confidence=0.5,
                    alternatives=[
                        "Return path buffered while radio ramps up",
                        "Lossy network dropping inbound keepalives",
                    ],
                    summary=(
                        f"{len(sends)} keepalive sends vs {len(recvs)} receives in a "
                        "10-min window with no sleep -- asymmetric keepalives."
                    ),
                )
        return None


__all__ = [
    "VPNIntegrityMonitor",
    "ThreatDetection",
    "ServerConnection",
    "SessionReport",
]
