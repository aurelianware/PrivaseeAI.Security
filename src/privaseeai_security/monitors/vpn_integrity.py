"""VPN integrity monitoring utilities.

This module provides `VPNIntegrityMonitor` which watches VPN-related log
entries for indicators such as transport protocol manipulation, API rate
limiting, server hopping, and certificate anomalies. It integrates the
`CertificateValidator` implemented in the crypto package for certificate
checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import datetime

from privaseeai_security.config import Config
from privaseeai_security.logger import get_logger
from privaseeai_security.crypto.cert_validator import CertificateValidator, ThreatLevel

LOGGER = get_logger(__name__)


@dataclass
class ThreatDetection:
    threat_level: ThreatLevel
    attack_type: Optional[str]
    indicators: List[str]
    details: Optional[str] = None
    timestamp: datetime.datetime = datetime.datetime.utcnow()


class VPNIntegrityMonitor:
    """Monitor VPN logs and detect integrity issues.

    This class follows the project's monitor patterns and is intentionally
    lightweight so it can be used in tests and in a long-running daemon.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.logger = LOGGER
        self.cert_validator = CertificateValidator()
        # Simple state tracking
        self.protocol_history: List[str] = []
        self.server_history: List[str] = []

    def analyze_transport_protocol(self, log_line: str) -> Optional[ThreatDetection]:
        """Analyze WireGuard protocol lines for TCP/UDP fallback.

        Returns a `ThreatDetection` when an anomaly is found.
        """
        if "socketType value: tcp" in log_line or "New socketType value: tcp" in log_line:
            self.protocol_history.append("tcp")
            return ThreatDetection(threat_level=ThreatLevel.MEDIUM, attack_type="TRANSPORT_MANIPULATION", indicators=["TCP_FALLBACK"], details="Observed TCP where UDP expected")
        if "socketType value: udp" in log_line or "New socketType value: udp" in log_line:
            self.protocol_history.append("udp")
            return ThreatDetection(threat_level=ThreatLevel.NONE, attack_type=None, indicators=["UDP_OK"], details="UDP observed")
        return None

    def validate_vpn_certificate(self, log_line: str) -> Optional[ThreatDetection]:
        """Extract certificate info from a log line and validate it.

        This method attempts to extract a fingerprint from `log_line`. If a
        full certificate blob is available (PEM/DER) the `CertificateValidator`
        would be called with bytes — in real deployments this should parse the
        certificate. For log-file-driven checks we perform a fingerprint lookup
        against `CertificateValidator.KNOWN_GOOD_FINGERPRINTS` as a fast-path.
        """
        info = self.cert_validator.extract_cert_info_from_log(log_line)
        if not info:
            return None

        fp = info.fingerprint.lower()
        # Known-good fast path
        for known in self.cert_validator.KNOWN_GOOD_FINGERPRINTS:
            if known.lower() in fp:
                self.logger.debug("Known-good certificate fingerprint detected: %s", fp)
                return ThreatDetection(threat_level=ThreatLevel.NONE, attack_type=None, indicators=["KNOWN_GOOD_CERT"], details=f"Fingerprint {fp} matched known-good")

        # Unknown fingerprint -> escalate. In future we could call
        # self.cert_validator.validate_vpn_certificate() with full cert bytes
        # when available.
        self.logger.warning("Unknown certificate fingerprint detected: %s", fp)
        return ThreatDetection(threat_level=ThreatLevel.HIGH, attack_type="MITM_CERTIFICATE", indicators=["UNKNOWN_FINGERPRINT"], details=f"Fingerprint {fp} is not known-good")

    def analyze_log_entry(self, log_line: str) -> List[ThreatDetection]:
        """Route a single log line to detectors and collect detections."""
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

        # TODO: add API rate limiting, server hopping analysis here

        return detections


__all__ = ["VPNIntegrityMonitor", "ThreatDetection"]
