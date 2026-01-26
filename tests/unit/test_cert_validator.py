"""Unit tests for the CertificateValidator module."""

from pathlib import Path
import datetime
import types
import json

import pytest

from privaseeai_security.crypto.cert_validator import (
    CertificateValidator,
    ValidationResult,
    ThreatLevel,
    CertificateInfo,
)


@pytest.fixture
def attack_logs_dir() -> Path:
    return Path(__file__).parent.parent.parent / "test_fixtures" / "attack_logs"


def make_mock_cert(fingerprint_hex: str = "aa11bb22cc33dd44", subject: str = "CN=leaf", issuer: str = "CN=CA",
                   hash_name: str = "sha256", days_valid: int = 365):
    """Create a lightweight mock x509.Certificate-like object for testing."""
    subj = types.SimpleNamespace(rfc4514_string=lambda: subject)
    iss = types.SimpleNamespace(rfc4514_string=lambda: issuer)
    sig = types.SimpleNamespace(name=hash_name)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = types.SimpleNamespace(
        subject=subj,
        issuer=iss,
        signature_hash_algorithm=sig,
        not_valid_before=now,
        not_valid_after=now + datetime.timedelta(days=days_valid),
        fingerprint=lambda algo=None: bytes.fromhex(fingerprint_hex),
    )
    return cert


def test_validate_known_good_protonvpn_certificate(monkeypatch):
    validator = CertificateValidator()

    # Mock loading to return a cert whose fingerprint contains known-good substring
    mock_cert = make_mock_cert(fingerprint_hex="6a1e93785520dade")

    monkeypatch.setattr(CertificateValidator, "_load_certificate", lambda self, data: mock_cert)

    res = validator.validate_vpn_certificate(b"dummy")
    assert isinstance(res, ValidationResult)
    assert res.threat_level == ThreatLevel.NONE
    assert "KNOWN_GOOD" in res.indicators


def test_reject_unknown_certificate_fingerprint(monkeypatch):
    validator = CertificateValidator()

    # Create leaf and issuer certs for a valid-looking chain
    leaf = make_mock_cert(fingerprint_hex="deadbeef00", subject="CN=leaf", issuer="CN=intermediate", days_valid=365)
    issuer = make_mock_cert(fingerprint_hex="cafebabe00", subject="CN=intermediate", issuer="CN=root", days_valid=365)

    def fake_load(self, data):
        if data == b"leaf":
            return leaf
        return issuer

    monkeypatch.setattr(CertificateValidator, "_load_certificate", fake_load)

    # Provide chain bytes so detect_mitm_indicators sees a complete chain
    res = validator.validate_vpn_certificate(b"leaf", chain_bytes=[b"issuer", b"root"])
    assert isinstance(res, ValidationResult)
    # Unknown fingerprint but complete chain -> our conservative mapping returns HIGH
    assert res.threat_level == ThreatLevel.HIGH


def test_detect_self_signed_certificate(monkeypatch):
    validator = CertificateValidator()

    # self-signed -> subject == issuer
    self_signed = make_mock_cert(fingerprint_hex="cafecafe", subject="CN=self", issuer="CN=self", days_valid=365)
    monkeypatch.setattr(CertificateValidator, "_load_certificate", lambda self, data: self_signed)

    res = validator.validate_vpn_certificate(b"dummy")
    assert res.threat_level == ThreatLevel.CRITICAL
    assert "SELF_SIGNED" in res.indicators


def test_extract_cert_from_wireguard_log(attack_logs_dir):
    validator = CertificateValidator()
    log_file = attack_logs_dir / "certificate_refresh.log"
    assert log_file.exists()

    content = log_file.read_text()
    # Find the line that contains the certificate
    cert_line = next((l for l in content.splitlines() if "Certificate with features saved" in l), None)
    assert cert_line is not None

    info = validator.extract_cert_info_from_log(cert_line)
    assert isinstance(info, CertificateInfo)
    assert info.fingerprint == "6a1e93785520dade"
    # validUntil in fixture is 2026-01-27 04:27:11 +0000
    assert info.not_valid_after.year == 2026


def test_extract_cert_from_protonvpn_json():
    validator = CertificateValidator()
    payload = json.dumps({
        "certificateFingerprint": "6a1e93785520dade",
        "validUntil": "2026-01-27 04:27:11 +0000",
    })

    info = validator.extract_cert_info_from_log(payload)
    assert isinstance(info, CertificateInfo)
    assert info.fingerprint == "6a1e93785520dade"


def test_validate_certificate_expiry_dates(monkeypatch):
    validator = CertificateValidator()

    # Very short validity (<1 day) should be flagged as SHORT_VALIDITY -> MEDIUM
    short_cert = make_mock_cert(fingerprint_hex="00112233", days_valid=0)
    monkeypatch.setattr(CertificateValidator, "_load_certificate", lambda self, data: short_cert)

    res = validator.validate_vpn_certificate(b"dummy")
    assert res.threat_level == ThreatLevel.MEDIUM
    assert "SHORT_VALIDITY" in res.indicators


def test_certificate_chain_validation(monkeypatch):
    validator = CertificateValidator()

    # Create a consistent chain where issuer of leaf matches subject of next cert
    leaf = make_mock_cert(fingerprint_hex="a1b2c3", subject="CN=leaf", issuer="CN=intermediate", days_valid=365)
    inter = make_mock_cert(fingerprint_hex="d4e5f6", subject="CN=intermediate", issuer="CN=root", days_valid=365)
    root = make_mock_cert(fingerprint_hex="010203", subject="CN=root", issuer="CN=root", days_valid=365)

    def fake_load(self, data):
        if data == b"leaf":
            return leaf
        if data == b"inter":
            return inter
        return root

    monkeypatch.setattr(CertificateValidator, "_load_certificate", fake_load)

    res = validator.validate_vpn_certificate(b"leaf", chain_bytes=[b"inter", b"root"])
    # detect_mitm_indicators should not report INCOMPLETE_CHAIN or CHAIN_MISMATCH
    assert "INCOMPLETE_CHAIN" not in res.indicators
    assert "CHAIN_MISMATCH" not in res.indicators


def test_parse_malformed_log_entries():
    validator = CertificateValidator()
    bad_line = "This is not a valid certificate log entry"
    info = validator.extract_cert_info_from_log(bad_line)
    assert info is None
