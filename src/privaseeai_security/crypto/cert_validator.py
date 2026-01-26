"""VPN certificate validation helpers.

This module provides a CertificateValidator class that integrates with the
cryptography library to validate VPN certificates and detect common MITM
indicators. The implementation follows the style used in the project's
`crypto.py` utility: small, well-documented helpers that can be extended.

MITM detection logic (high-level):
- Self-signed certificates: Certificates where subject == issuer are strong
  indicators of interception when observed in a VPN context. These are
  classified as CRITICAL by default.
- Weak signature/hash algorithms (MD5, SHA1): These indicate legacy or
  maliciously-constructed certs and increase threat severity.
- Short validity periods: Very short lifetimes (e.g. minutes/hours/days)
  for leaf certificates may indicate ephemeral MITM certificates generated
  on the fly by an interceptor.
- Incomplete or inconsistent chains: Missing intermediates or mismatched
  issuer/subject relationships in a presented chain can indicate tampering.

All public methods include type hints and comprehensive docstrings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple
import datetime
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

LOGGER = logging.getLogger(__name__)


class ThreatLevel(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ValidationResult:
    """Result of validating a VPN certificate.

    Attributes:
        threat_level: Overall assessed threat level.
        indicators: Short list of strings describing suspicious signals.
        fingerprint: Hex fingerprint of the evaluated certificate.
        message: Optional human-readable summary.
    """
    threat_level: ThreatLevel
    indicators: List[str]
    fingerprint: str
    message: Optional[str] = None


@dataclass
class CertificateInfo:
    """Structured information extracted from an X.509 certificate."""
    fingerprint: str
    subject: str
    issuer: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime


class CertificateValidator:
    """Validator for VPN certificates with basic MITM detection.

    The validator focuses on practical, defensive checks that can be run
    lightweight in a monitoring agent:

    - Compare certificate fingerprints against a known-good database
      (class-level `KNOWN_GOOD_FINGERPRINTS`).
    - Inspect certificate properties for common MITM indicators
      (self-signed, weak hash algorithms, short validity windows, incomplete
      chains).

    Notes on fingerprints:
    - Fingerprints are normalized to lower-case hex with no separators when
      comparing. Known-good entries may be full or partial hex strings; the
      validator checks containment to support truncated fingerprints from
      logs.
    """

    # Example known-good ProtonVPN fingerprint (lowercase substring match).
    KNOWN_GOOD_FINGERPRINTS = {"6a1e93785520dade"}

    def __init__(self) -> None:
        self.logger = LOGGER

    def _load_certificate(self, data: bytes) -> x509.Certificate:
        """Load a certificate from PEM or DER bytes.

        Raises ValueError if the data cannot be parsed.
        """
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            return x509.load_der_x509_certificate(data, default_backend())

    def _compute_fingerprint(self, cert: x509.Certificate, algo=hashes.SHA256()) -> str:
        """Compute hex fingerprint of the certificate using the given hash.

        Returns the lower-case hex string representation.
        """
        fp = cert.fingerprint(algo)
        return fp.hex()

    def detect_mitm_indicators(self, cert: x509.Certificate, chain: Optional[List[x509.Certificate]] = None) -> List[str]:
        """Analyze the provided certificate (and optional chain) for MITM indicators.

        Detection heuristics implemented:
        - Self-signed leaf certificate (subject == issuer) => strong indicator.
        - Weak signature/hash algorithm (md5, sha1) => raises suspicion.
        - Very short validity period (configurable thresholds here) => suspicious.
        - Incomplete chain (chain is None or chain length < 2) => potential tampering.

        The method returns a list of textual indicators which higher-level code
        can map to `ThreatLevel` values.
        """
        indicators: List[str] = []

        try:
            # Self-signed check (very strong signal in VPN contexts)
            if cert.issuer.rfc4514_string() == cert.subject.rfc4514_string():
                indicators.append("SELF_SIGNED")

            # Weak hash algorithm check
            try:
                hash_name = cert.signature_hash_algorithm.name.lower()
                if hash_name in {"md5", "sha1"}:
                    indicators.append("WEAK_HASH_ALGORITHM")
            except Exception:
                # Some certificate implementations may not expose algorithm info
                indicators.append("UNKNOWN_SIGNATURE_ALGORITHM")

            # Validity window analysis
            validity = cert.not_valid_after - cert.not_valid_before
            if validity <= datetime.timedelta(days=7):
                indicators.append("SHORT_VALIDITY")
            elif validity <= datetime.timedelta(days=30):
                indicators.append("UNUSUAL_VALIDITY_PERIOD")

            # Chain inspection: incomplete or too-short chains may indicate
            # interception or missing intermediates.
            if not chain or len(chain) < 2:
                indicators.append("INCOMPLETE_CHAIN")
            else:
                # Basic consistency checks: each cert issuer should match next cert subject
                for i in range(len(chain) - 1):
                    if chain[i].issuer.rfc4514_string() != chain[i + 1].subject.rfc4514_string():
                        indicators.append("CHAIN_MISMATCH")
                        break

        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug("Error during MITM indicator detection: %s", exc)
            indicators.append("DETECTION_ERROR")

        return indicators

    def _check_self_signed(self, cert: x509.Certificate) -> bool:
        """Return True if certificate appears self-signed (subject == issuer)."""
        try:
            return cert.issuer.rfc4514_string() == cert.subject.rfc4514_string()
        except Exception:
            return False

    def _check_expiry(self, cert: x509.Certificate) -> Optional[str]:
        """Check certificate validity window and return an indicator or None.

        Returns:
            'SHORT_VALIDITY' if validity <= 1 day,
            'UNUSUAL_VALIDITY_PERIOD' if <= 30 days,
            None otherwise.
        """
        try:
            validity = cert.not_valid_after - cert.not_valid_before
            if validity <= datetime.timedelta(days=1):
                return "SHORT_VALIDITY"
            if validity <= datetime.timedelta(days=30):
                return "UNUSUAL_VALIDITY_PERIOD"
        except Exception:
            return None
        return None

    def extract_cert_info_from_log(self, log_line: str) -> Optional[CertificateInfo]:
        """Extract certificate fingerprint and validity times from a log line.

        Supports simple text logs and JSON-like fragments that include
        'certificateFingerprint', 'validUntil' and 'refreshTime'. Returns
        a `CertificateInfo` or None when parsing fails.
        """
        import re
        import json

        # Try JSON parse first
        try:
            payload = json.loads(log_line)
            fp = payload.get("certificateFingerprint") or payload.get("fingerprint")
            valid_until = payload.get("validUntil") or payload.get("valid_until")
            if fp:
                # best-effort parse date
                try:
                    valid_dt = datetime.datetime.fromisoformat(valid_until.replace(" +0000", "+00:00")) if valid_until else datetime.datetime.max
                except Exception:
                    valid_dt = datetime.datetime.max
                return CertificateInfo(fingerprint=fp.strip("'\""), subject="", issuer="", not_valid_before=datetime.datetime.min, not_valid_after=valid_dt)
        except Exception:
            pass

        # Fallback to regex for text logs
        # Example: certificateFingerprint: '6a1e93785520dade', validUntil: '2026-01-27 04:27:11 +0000'
        try:
            fp_match = re.search(r"certificateFingerprint:\s*'?(?P<fp>[0-9a-fA-F]+)'?", log_line)
            valid_match = re.search(r"validUntil:\s*'?(?P<valid>[^']+)'?", log_line)
            if fp_match:
                fp = fp_match.group("fp")
                valid_str = valid_match.group("valid") if valid_match else None
                if valid_str:
                    try:
                        valid_dt = datetime.datetime.strptime(valid_str, "%Y-%m-%d %H:%M:%S %z")
                    except Exception:
                        try:
                            valid_dt = datetime.datetime.strptime(valid_str, "%Y-%m-%d %H:%M:%S")
                        except Exception:
                            valid_dt = datetime.datetime.max
                else:
                    valid_dt = datetime.datetime.max
                return CertificateInfo(fingerprint=fp, subject="", issuer="", not_valid_before=datetime.datetime.min, not_valid_after=valid_dt)
        except Exception:
            return None

        return None

    def validate_vpn_certificate(self, cert_bytes: bytes, chain_bytes: Optional[List[bytes]] = None) -> ValidationResult:
        """Validate a VPN certificate and return a `ValidationResult`.

        Args:
            cert_bytes: DER or PEM encoded certificate bytes (leaf certificate).
            chain_bytes: Optional list of DER/PEM encoded certificates representing
                the chain presented by the peer (leaf-first is acceptable).

        Returns:
            `ValidationResult` with `threat_level`, `indicators`, and `fingerprint`.
        """
        try:
            cert = self._load_certificate(cert_bytes)
        except Exception as exc:
            msg = f"Unable to parse certificate: {exc}"
            self.logger.debug(msg)
            return ValidationResult(threat_level=ThreatLevel.HIGH, indicators=["PARSE_ERROR"], fingerprint="", message=msg)

        fingerprint = self._compute_fingerprint(cert)
        fp_lower = fingerprint.lower()

        # Normalize known-good entries and support partial-match lookups
        for known in self.KNOWN_GOOD_FINGERPRINTS:
            if known.lower() in fp_lower:
                return ValidationResult(threat_level=ThreatLevel.NONE, indicators=["KNOWN_GOOD"], fingerprint=fingerprint, message="Fingerprint matched known-good database")

        # Load chain if provided
        chain: Optional[List[x509.Certificate]] = None
        if chain_bytes:
            parsed_chain: List[x509.Certificate] = []
            for b in chain_bytes:
                try:
                    parsed_chain.append(self._load_certificate(b))
                except Exception:
                    # skip unparsable entries but note incomplete chain
                    self.logger.debug("Skipping unparsable chain certificate")
            chain = parsed_chain

        indicators = self.detect_mitm_indicators(cert, chain)

        # Map indicators to threat level conservatively
        if "SELF_SIGNED" in indicators:
            level = ThreatLevel.CRITICAL
        elif "WEAK_HASH_ALGORITHM" in indicators or "CHAIN_MISMATCH" in indicators:
            level = ThreatLevel.HIGH
        elif "SHORT_VALIDITY" in indicators or "INCOMPLETE_CHAIN" in indicators:
            level = ThreatLevel.MEDIUM
        else:
            # Unknown fingerprint but no strong MITM indicators: treat as HIGH
            level = ThreatLevel.HIGH

        return ValidationResult(threat_level=level, indicators=indicators, fingerprint=fingerprint)


__all__ = ["CertificateValidator", "ValidationResult", "CertificateInfo", "ThreatLevel"]
