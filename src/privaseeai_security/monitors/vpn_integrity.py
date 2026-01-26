"""VPN integrity monitoring utilities.

This module provides `VPNIntegrityMonitor` which watches VPN-related log
entries for indicators such as transport protocol manipulation, API rate
limiting, server hopping, and certificate anomalies. It integrates the
`CertificateValidator` implemented in the crypto package for certificate
checks.

Real-world detection targets based on actual attack:
1. WireGuard log shows "socketType value: tcp" when UDP is expected
2. ProtonVPN app log shows "error":"cooldown(TIMESTAMP)" indicating rate limiting
3. Multiple DNS64 server mappings in short time window (4 servers in 7 minutes)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict
import datetime
import re
import json

from privaseeai_security.config import Config
from privaseeai_security.logger import get_logger
from privaseeai_security.crypto.cert_validator import CertificateValidator, ThreatLevel

LOGGER = get_logger(__name__)


@dataclass
class ThreatDetection:
    """Represents a detected security threat.
    
    Attributes:
        threat_level: Severity of the threat (NONE, LOW, MEDIUM, HIGH, CRITICAL)
        attack_type: Type of attack detected (e.g., 'TRANSPORT_MANIPULATION')
        indicators: List of specific indicators that triggered detection
        details: Optional human-readable details about the threat
        timestamp: When the threat was detected
    """
    threat_level: ThreatLevel
    attack_type: Optional[str]
    indicators: List[str]
    details: Optional[str] = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)


@dataclass
class ServerConnection:
    """Represents a VPN server connection event."""
    server_ip: str
    timestamp: datetime.datetime
    protocol: Optional[str] = None


class VPNIntegrityMonitor:
    """Monitor VPN logs and detect integrity issues.

    This class tracks VPN connection state changes, monitors transport
    protocol (TCP vs UDP), detects API rate limiting from VPN provider logs,
    tracks server hopping patterns, and uses CertificateValidator for
    certificate validation.

    The monitor follows the project's monitor patterns and is intentionally
    lightweight so it can be used in tests and in a long-running daemon.
    
    Real-world detection targets:
    - Transport protocol manipulation (UDP -> TCP fallback)
    - API rate limiting indicating tracking attempts
    - Rapid server hopping indicating forced disconnections
    - Certificate anomalies and MITM indicators
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        """Initialize VPN integrity monitor.
        
        Args:
            config: Optional Config instance. If None, defaults will be loaded.
        """
        self.config = config or Config()
        self.logger = LOGGER
        self.cert_validator = CertificateValidator()
        
        # State tracking for connection patterns
        self.protocol_history: List[Dict[str, any]] = []
        self.server_connections: List[ServerConnection] = []
        self.api_rate_limits: Dict[str, datetime.datetime] = {}
        
        # Expected protocol (can be configured)
        self.expected_protocol = "udp"
        
        self.logger.info("VPNIntegrityMonitor initialized")

    def analyze_transport_protocol(self, log_line: str) -> Optional[ThreatDetection]:
        """Analyze WireGuard protocol lines for TCP/UDP fallback.
        
        Detects when VPN falls back to TCP when UDP is expected, which can
        indicate UDP blocking or network manipulation.
        
        Input format example:
        "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        
        Args:
            log_line: Log line to analyze
            
        Returns:
            ThreatDetection if anomaly found, None otherwise
        """
        protocol = None
        
        # Parse protocol from log line
        if "socketType value: tcp" in log_line.lower() or "new sockettype value: tcp" in log_line.lower():
            protocol = "tcp"
        elif "socketType value: udp" in log_line.lower() or "new sockettype value: udp" in log_line.lower():
            protocol = "udp"
        
        if not protocol:
            return None
        
        # Record protocol in history with timestamp
        self.protocol_history.append({
            "protocol": protocol,
            "timestamp": datetime.datetime.utcnow(),
            "log_line": log_line[:100]  # Store snippet for debugging
        })
        
        # Alert on TCP fallback
        if protocol == "tcp" and self.expected_protocol == "udp":
            self.logger.warning("TCP fallback detected - potential UDP blocking or manipulation")
            return ThreatDetection(
                threat_level=ThreatLevel.MEDIUM,
                attack_type="TRANSPORT_MANIPULATION",
                indicators=["TCP_FALLBACK", "UDP_BLOCKING_SUSPECTED"],
                details="VPN fallback to TCP detected when UDP is expected - possible network manipulation or UDP blocking"
            )
        
        # UDP is normal/expected
        if protocol == "udp":
            self.logger.debug("UDP protocol observed (expected)")
            return ThreatDetection(
                threat_level=ThreatLevel.NONE,
                attack_type=None,
                indicators=["UDP_NORMAL"],
                details="UDP protocol observed as expected"
            )
        
        return None

    def validate_vpn_certificate(self, log_line: str) -> Optional[ThreatDetection]:
        """Extract certificate info from a log line and validate it.

        This method attempts to extract a fingerprint from `log_line`. If a
        full certificate blob is available (PEM/DER) the `CertificateValidator`
        would be called with bytes — in real deployments this should parse the
        certificate. For log-file-driven checks we perform a fingerprint lookup
        against `CertificateValidator.KNOWN_GOOD_FINGERPRINTS` as a fast-path.
        
        Args:
            log_line: Log line potentially containing certificate information
            
        Returns:
            ThreatDetection if certificate issue detected, None otherwise
        """
        info = self.cert_validator.extract_cert_info_from_log(log_line)
        if not info:
            return None

        fp = info.fingerprint.lower()
        
        # Known-good fast path
        for known in self.cert_validator.KNOWN_GOOD_FINGERPRINTS:
            if known.lower() in fp:
                self.logger.debug("Known-good certificate fingerprint detected: %s", fp)
                return ThreatDetection(
                    threat_level=ThreatLevel.NONE,
                    attack_type=None,
                    indicators=["KNOWN_GOOD_CERT"],
                    details=f"Certificate fingerprint {fp} matched known-good database"
                )

        # Unknown fingerprint -> escalate. In future we could call
        # self.cert_validator.validate_vpn_certificate() with full cert bytes
        # when available.
        self.logger.warning("Unknown certificate fingerprint detected: %s", fp)
        return ThreatDetection(
            threat_level=ThreatLevel.HIGH,
            attack_type="MITM_CERTIFICATE",
            indicators=["UNKNOWN_FINGERPRINT"],
            details=f"Certificate fingerprint {fp} is not in known-good database - possible MITM attack"
        )
    
    def detect_api_rate_limiting(self, log_line: str) -> Optional[ThreatDetection]:
        """Detect API rate limiting from ProtonVPN logs.
        
        Detection logic for ProtonVPN API abuse:
        - Parse log entries for API error responses
        - Look for "cooldown" errors with future timestamps
        - Track API request frequency per endpoint
        - Alert on rate limiting as indicator of tracking attempts
        
        Real example to detect:
        'ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}'
        
        Args:
            log_line: Log line to analyze
            
        Returns:
            ThreatDetection if rate limiting detected, None otherwise
        """
        # Look for cooldown errors
        if "cooldown" not in log_line.lower():
            return None
        
        try:
            # Try to extract cooldown timestamp
            # Pattern: cooldown(YYYY-MM-DD HH:MM:SS +0000)
            cooldown_match = re.search(r'cooldown\(([^)]+)\)', log_line)
            if not cooldown_match:
                return None
            
            cooldown_str = cooldown_match.group(1)
            
            # Parse timestamp
            try:
                cooldown_until = datetime.datetime.strptime(cooldown_str, "%Y-%m-%d %H:%M:%S %z")
            except ValueError:
                # Try without timezone
                try:
                    cooldown_until = datetime.datetime.strptime(cooldown_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    self.logger.debug("Could not parse cooldown timestamp: %s", cooldown_str)
                    return None
            
            # Calculate remaining cooldown time
            now = datetime.datetime.utcnow()
            if cooldown_until.tzinfo:
                now = now.replace(tzinfo=datetime.timezone.utc)
            
            remaining = cooldown_until - now
            remaining_minutes = int(remaining.total_seconds() / 60)
            
            # Determine endpoint being rate limited
            endpoint = "unknown"
            if "location" in log_line.lower():
                endpoint = "location"
            elif "user" in log_line.lower():
                endpoint = "user"
            
            # Track rate limit
            self.api_rate_limits[endpoint] = cooldown_until
            
            self.logger.warning("API rate limiting detected on %s endpoint - cooldown until %s (%d minutes)",
                              endpoint, cooldown_until, remaining_minutes)
            
            return ThreatDetection(
                threat_level=ThreatLevel.HIGH,
                attack_type="API_TRACKING",
                indicators=["API_RATE_LIMIT", f"ENDPOINT_{endpoint.upper()}", f"COOLDOWN_{remaining_minutes}MIN"],
                details=f"API rate limit detected on {endpoint} endpoint - cooldown until {cooldown_until} ({remaining_minutes} minutes remaining). This may indicate location tracking attempts."
            )
            
        except Exception as e:
            self.logger.debug("Error parsing cooldown from log: %s", e)
            return None
    
    def track_server_connection(self, log_line: str) -> Optional[ThreatDetection]:
        """Track VPN server connections to detect hopping patterns.
        
        Parses WireGuard logs for "DNS64: mapped X.X.X.X" server IPs and
        tracks connection patterns to detect forced disconnections.
        
        Detection rules:
        - 4+ different servers in under 10 minutes = suspicious
        - Rapid reconnections (< 2 minutes apart) = suspicious
        
        Args:
            log_line: Log line to analyze
            
        Returns:
            ThreatDetection if server hopping detected, None otherwise
        """
        # Look for DNS64 server mappings or connection events
        server_ip = None
        
        # Pattern: DNS64: mapped 1.2.3.4
        dns64_match = re.search(r'DNS64:\s*mapped\s+(\d+\.\d+\.\d+\.\d+)', log_line)
        if dns64_match:
            server_ip = dns64_match.group(1)
        
        # Alternative: look for server connection patterns
        elif "connected to" in log_line.lower() or "connecting to" in log_line.lower():
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
            if ip_match:
                server_ip = ip_match.group(1)
        
        if not server_ip:
            return None
        
        # Record connection
        connection = ServerConnection(
            server_ip=server_ip,
            timestamp=datetime.datetime.utcnow(),
            protocol=None  # Could be extracted from context
        )
        self.server_connections.append(connection)
        
        # Analyze recent connection pattern (last 10 minutes)
        now = datetime.datetime.utcnow()
        recent_window = datetime.timedelta(minutes=10)
        recent_connections = [
            conn for conn in self.server_connections
            if now - conn.timestamp <= recent_window
        ]
        
        # Count unique servers
        unique_servers = set(conn.server_ip for conn in recent_connections)
        
        # Check for rapid hopping (4+ servers in 10 minutes)
        if len(unique_servers) >= 4:
            server_list = ", ".join(sorted(unique_servers))
            self.logger.warning("Rapid server hopping detected: %d servers in %d minutes",
                              len(unique_servers), 10)
            
            return ThreatDetection(
                threat_level=ThreatLevel.MEDIUM,
                attack_type="FORCED_RECONNECTION",
                indicators=["SERVER_HOPPING", f"SERVERS_{len(unique_servers)}", "RAPID_RECONNECTION"],
                details=f"Detected {len(unique_servers)} different VPN servers in 10 minutes: {server_list}. This may indicate forced disconnections or connection disruption attacks."
            )
        
        # Check for very rapid reconnections (< 2 minutes)
        if len(recent_connections) >= 2:
            last_two = sorted(recent_connections, key=lambda c: c.timestamp)[-2:]
            time_diff = last_two[1].timestamp - last_two[0].timestamp
            if time_diff < datetime.timedelta(minutes=2) and last_two[0].server_ip != last_two[1].server_ip:
                self.logger.warning("Rapid reconnection detected: %s seconds between server changes",
                                  time_diff.total_seconds())
                return ThreatDetection(
                    threat_level=ThreatLevel.MEDIUM,
                    attack_type="CONNECTION_DISRUPTION",
                    indicators=["RAPID_RECONNECTION", f"TIME_DIFF_{int(time_diff.total_seconds())}S"],
                    details=f"VPN server changed in {int(time_diff.total_seconds())} seconds - possible connection disruption"
                )
        
        return None

    def analyze_log_entry(self, log_line: str) -> List[ThreatDetection]:
        """Route a single log line to detectors and collect detections.
        
        This is the main entry point for processing VPN log entries. It runs
        all detection methods and returns a list of detected threats.
        
        Args:
            log_line: A single log line to analyze
            
        Returns:
            List of ThreatDetection objects for any threats found
        """
        detections: List[ThreatDetection] = []

        # Transport protocol analysis
        proto = self.analyze_transport_protocol(log_line)
        if proto:
            detections.append(proto)

        # Certificate checks — look for certificate fingerprint strings
        if "certificateFingerprint" in log_line or "Certificate with features saved" in log_line:
            cert_det = self.validate_vpn_certificate(log_line)
            if cert_det:
                detections.append(cert_det)
        
        # API rate limiting detection
        if "cooldown" in log_line.lower() or "rate limit" in log_line.lower():
            rate_limit_det = self.detect_api_rate_limiting(log_line)
            if rate_limit_det:
                detections.append(rate_limit_det)
        
        # Server connection tracking
        if "DNS64" in log_line or "connected to" in log_line.lower() or "connecting to" in log_line.lower():
            server_det = self.track_server_connection(log_line)
            if server_det:
                detections.append(server_det)

        return detections


__all__ = ["VPNIntegrityMonitor", "ThreatDetection", "ServerConnection"]
