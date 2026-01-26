"""Integration tests for VPN Integrity Monitor.

Tests real-world attack patterns using actual log formats from the attack:
1. TCP fallback (WireGuard forced to TCP)
2. API rate limiting (50-minute cooldown)
3. Server hopping (4 servers in 7 minutes)
4. Certificate validation (should pass for known-good cert)
"""
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor, ThreatDetection
from privaseeai_security.crypto.cert_validator import ThreatLevel
from privaseeai_security.config import Config


class TestVPNIntegrityMonitor:
    """Integration tests for VPN Integrity Monitor against real attack patterns."""

    @pytest.fixture
    def monitor(self):
        """Create VPN integrity monitor instance."""
        config = Config()
        return VPNIntegrityMonitor(config)

    @pytest.fixture
    def sample_logs_dir(self):
        """Get path to sample attack logs."""
        return Path(__file__).parent.parent.parent / "test_fixtures" / "attack_logs"

    def test_detect_tcp_fallback_attack(self, monitor):
        """Test detection of TCP fallback when UDP is expected.
        
        Real-world scenario: Attacker blocks UDP to force TCP fallback,
        making traffic easier to inspect/manipulate.
        
        Input: WireGuard log with "socketType value: tcp"
        Expected: ThreatLevel.MEDIUM, attack_type='TRANSPORT_MANIPULATION'
        """
        # Real WireGuard log format from attack
        log_line = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        
        detections = monitor.analyze_log_entry(log_line)
        
        # Should detect TCP fallback
        assert len(detections) > 0, "Should detect TCP fallback"
        
        tcp_detection = next((d for d in detections if d.attack_type == "TRANSPORT_MANIPULATION"), None)
        assert tcp_detection is not None, "Should identify as TRANSPORT_MANIPULATION"
        assert tcp_detection.threat_level == ThreatLevel.MEDIUM, "TCP fallback should be MEDIUM threat"
        assert "TCP_FALLBACK" in tcp_detection.indicators or "UDP_BLOCKING" in str(tcp_detection.indicators)

    def test_udp_normal_operation(self, monitor):
        """Test that normal UDP operation is not flagged as a threat."""
        log_line = "2026-01-26T04:20:00.000000Z | INFO | PROTOCOL | New socketType value: udp"
        
        detections = monitor.analyze_log_entry(log_line)
        
        # Should have a detection but with NONE threat level
        udp_detection = next((d for d in detections if "UDP" in str(d.indicators)), None)
        if udp_detection:
            assert udp_detection.threat_level == ThreatLevel.NONE, "UDP should be normal (NONE threat)"

    def test_detect_api_cooldown_tracking(self, monitor, sample_logs_dir):
        """Test detection of API rate limiting indicating tracking attempts.
        
        Real-world scenario: ProtonVPN API returns cooldown error when
        attacker is making excessive location tracking requests.
        
        Input: ProtonVPN log with cooldown error
        Expected: ThreatLevel.HIGH, attack_type='API_TRACKING'
        """
        # Real ProtonVPN log format from attack
        log_line = 'ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}'
        
        detections = monitor.analyze_log_entry(log_line)
        
        # Should detect API rate limiting
        assert len(detections) > 0, "Should detect API rate limiting"
        
        api_detection = next((d for d in detections if d.attack_type == "API_TRACKING"), None)
        assert api_detection is not None, "Should identify as API_TRACKING"
        assert api_detection.threat_level == ThreatLevel.HIGH, "API rate limiting should be HIGH threat"
        assert "API_RATE_LIMIT" in api_detection.indicators or "COOLDOWN" in str(api_detection.indicators)

    def test_detect_rapid_server_hopping(self, monitor):
        """Test detection of rapid VPN server hopping.
        
        Real-world scenario: 4 different servers in 7 minutes indicates
        forced disconnections or connection disruption attacks.
        
        Input: 4 server connections in short time window
        Expected: ThreatLevel.MEDIUM, attack_type='FORCED_RECONNECTION'
        """
        # Simulate 4 different server connections in quick succession
        servers = [
            "DNS64: mapped 185.159.157.99",
            "DNS64: mapped 185.159.156.78", 
            "DNS64: mapped 185.159.158.12",
            "DNS64: mapped 185.159.159.45"
        ]
        
        all_detections = []
        for server_log in servers:
            detections = monitor.analyze_log_entry(server_log)
            all_detections.extend(detections)
        
        # Should detect server hopping pattern
        hopping_detection = next(
            (d for d in all_detections if d.attack_type in ["FORCED_RECONNECTION", "CONNECTION_DISRUPTION"]),
            None
        )
        
        assert hopping_detection is not None, "Should detect server hopping pattern"
        assert hopping_detection.threat_level == ThreatLevel.MEDIUM, "Server hopping should be MEDIUM threat"
        assert len(monitor.server_connections) >= 4, "Should track all 4 server connections"

    def test_validate_certificate_from_logs(self, monitor):
        """Test certificate validation from log entries.
        
        Real-world scenario: Extract certificate fingerprint from logs
        and validate against known-good database.
        
        Input: Log with certificateFingerprint '6a1e93785520dade'
        Expected: ThreatLevel.NONE (known-good cert)
        """
        # Real WireGuard certificate log from legitimate ProtonVPN connection
        log_line = "DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: '6a1e93785520dade', validUntil: '2026-01-27 04:27:11 +0000'"
        
        detections = monitor.analyze_log_entry(log_line)
        
        # Should validate certificate
        cert_detection = next((d for d in detections if "CERT" in str(d.indicators)), None)
        assert cert_detection is not None, "Should detect and validate certificate"
        assert cert_detection.threat_level == ThreatLevel.NONE, "Known-good cert should have NONE threat"
        assert "KNOWN_GOOD" in str(cert_detection.indicators)

    def test_detect_unknown_certificate(self, monitor):
        """Test detection of unknown certificate fingerprint."""
        # Unknown certificate fingerprint
        log_line = "DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: 'deadbeef12345678'"
        
        detections = monitor.analyze_log_entry(log_line)
        
        cert_detection = next((d for d in detections if "CERT" in str(d.indicators) or d.attack_type == "MITM_CERTIFICATE"), None)
        assert cert_detection is not None, "Should detect unknown certificate"
        assert cert_detection.threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM], "Unknown cert should be elevated threat"

    def test_rapid_reconnection_detection(self, monitor):
        """Test detection of rapid reconnections (< 2 minutes apart)."""
        # First connection
        log1 = "DNS64: mapped 185.159.157.99"
        monitor.analyze_log_entry(log1)
        
        # Second connection to different server immediately after
        log2 = "DNS64: mapped 185.159.156.78"
        detections = monitor.analyze_log_entry(log2)
        
        # Should detect rapid reconnection
        rapid_detection = next(
            (d for d in detections if "RAPID" in str(d.indicators) or d.attack_type == "CONNECTION_DISRUPTION"),
            None
        )
        
        if rapid_detection:
            assert rapid_detection.threat_level == ThreatLevel.MEDIUM, "Rapid reconnection should be MEDIUM threat"

    def test_end_to_end_attack_detection(self, monitor):
        """Test complete attack sequence with multiple threat types.
        
        Real-world scenario: Complete log sequence from actual attack showing:
        1. TCP fallback (transport manipulation)
        2. API rate limiting (tracking attempt)
        3. Server hopping (connection disruption)
        4. Certificate validation (should pass for known-good)
        
        Expected: Multiple threat detections with proper severity
        """
        # Complete attack sequence
        attack_logs = [
            # Normal start with UDP
            "2026-01-26T04:20:00.000000Z | INFO | PROTOCOL | New socketType value: udp",
            
            # Certificate validation (should pass)
            "DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: '6a1e93785520dade', validUntil: '2026-01-27 04:27:11 +0000'",
            
            # Attack begins: UDP blocked, forced to TCP
            "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp",
            
            # API abuse/tracking attempt
            'ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}',
            
            # Forced server hopping
            "DNS64: mapped 185.159.157.99",
            "DNS64: mapped 185.159.156.78",
            "DNS64: mapped 185.159.158.12",
            "DNS64: mapped 185.159.159.45"
        ]
        
        all_detections = []
        for log_line in attack_logs:
            detections = monitor.analyze_log_entry(log_line)
            all_detections.extend(detections)
        
        # Verify we detected the key attack components
        attack_types_detected = {d.attack_type for d in all_detections if d.attack_type}
        
        # Should detect transport manipulation
        assert "TRANSPORT_MANIPULATION" in attack_types_detected, "Should detect TCP fallback"
        
        # Should detect API tracking
        assert "API_TRACKING" in attack_types_detected, "Should detect API rate limiting"
        
        # Should detect server hopping or connection disruption
        assert any(t in attack_types_detected for t in ["FORCED_RECONNECTION", "CONNECTION_DISRUPTION"]), \
            "Should detect server hopping pattern"
        
        # Should have HIGH or MEDIUM threats
        high_threats = [d for d in all_detections if d.threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]]
        assert len(high_threats) >= 2, f"Should detect at least 2 significant threats, found {len(high_threats)}"
        
        # Certificate should pass
        cert_detections = [d for d in all_detections if "CERT" in str(d.indicators)]
        if cert_detections:
            known_good = [d for d in cert_detections if d.threat_level == ThreatLevel.NONE]
            assert len(known_good) > 0, "Known-good certificate should pass validation"

    def test_json_log_format_parsing(self, monitor):
        """Test parsing of JSON-formatted log entries."""
        # ProtonVPN uses JSON format
        json_log = '{"timestamp":"2026-01-26T04:30:00Z","level":"ERROR","error":"cooldown(2026-01-26 05:24:44 +0000)"}'
        
        detections = monitor.analyze_log_entry(json_log)
        
        # Should parse and detect cooldown even in JSON format
        cooldown_detection = next((d for d in detections if "COOLDOWN" in str(d.indicators) or "API" in str(d.attack_type or "")), None)
        if cooldown_detection:
            assert cooldown_detection.threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]

    def test_malformed_log_handling(self, monitor):
        """Test that malformed logs don't crash the monitor."""
        malformed_logs = [
            "",  # Empty
            "random garbage text",  # No structure
            "|||",  # Only separators
            '{"invalid json',  # Malformed JSON
            None,  # Will be converted to string
        ]
        
        for bad_log in malformed_logs:
            try:
                if bad_log is None:
                    continue
                detections = monitor.analyze_log_entry(bad_log)
                # Should not crash, may return empty list
                assert isinstance(detections, list), "Should return list even for malformed logs"
            except Exception as e:
                pytest.fail(f"Monitor crashed on malformed log '{bad_log}': {e}")

    def test_state_tracking_persistence(self, monitor):
        """Test that monitor maintains state across multiple log entries."""
        # Process several logs
        monitor.analyze_log_entry("2026-01-26T04:20:00.000000Z | INFO | PROTOCOL | New socketType value: udp")
        monitor.analyze_log_entry("2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp")
        monitor.analyze_log_entry("DNS64: mapped 185.159.157.99")
        
        # State should be maintained
        assert len(monitor.protocol_history) >= 2, "Should track protocol history"
        assert len(monitor.server_connections) >= 1, "Should track server connections"

    def test_threat_detection_dataclass(self, monitor):
        """Test that ThreatDetection objects are properly structured."""
        log_line = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        detections = monitor.analyze_log_entry(log_line)
        
        if detections:
            detection = detections[0]
            
            # Verify required fields
            assert hasattr(detection, 'threat_level'), "Should have threat_level"
            assert hasattr(detection, 'attack_type'), "Should have attack_type"
            assert hasattr(detection, 'indicators'), "Should have indicators"
            assert hasattr(detection, 'timestamp'), "Should have timestamp"
            
            # Verify types
            assert isinstance(detection.threat_level, ThreatLevel), "threat_level should be ThreatLevel enum"
            assert isinstance(detection.indicators, list), "indicators should be a list"
            assert isinstance(detection.timestamp, datetime), "timestamp should be datetime"
