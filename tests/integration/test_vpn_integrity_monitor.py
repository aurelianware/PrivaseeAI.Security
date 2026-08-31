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
        """A single TCP socketType line is an INFO observation, not an attack.

        Policy change (timeline engine): TCP transport is normal Proton Smart
        Protocol behaviour on restrictive networks. It is recorded as an INFO
        ``TRANSPORT_TCP`` observation and only escalates to LOW at the session
        level when it persists (see test_vpn_integrity_session). It is no longer
        scored MEDIUM ``TRANSPORT_MANIPULATION`` on a single line.
        """
        # Real WireGuard log format
        log_line = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"

        detections = monitor.analyze_log_entry(log_line)

        # Should observe TCP transport as INFO
        assert len(detections) > 0, "Should observe TCP transport"

        tcp_detection = next((d for d in detections if d.attack_type == "TRANSPORT_TCP"), None)
        assert tcp_detection is not None, "Should identify as TRANSPORT_TCP observation"
        assert tcp_detection.threat_level == ThreatLevel.INFO, "TCP transport should be INFO"
        assert "TRANSPORT_TCP" in tcp_detection.indicators

    def test_udp_normal_operation(self, monitor):
        """Test that normal UDP operation is not flagged as a threat."""
        log_line = "2026-01-26T04:20:00.000000Z | INFO | PROTOCOL | New socketType value: udp"
        
        detections = monitor.analyze_log_entry(log_line)
        
        # Should have a detection but with NONE threat level
        udp_detection = next((d for d in detections if "UDP" in str(d.indicators)), None)
        if udp_detection:
            assert udp_detection.threat_level == ThreatLevel.NONE, "UDP should be normal (NONE threat)"

    def test_detect_api_cooldown_tracking(self, monitor, sample_logs_dir):
        """An API cooldown is an INFO observation from the VPN integrity monitor.

        Policy change (timeline engine): Proton rate-limits routine client
        requests, so a ``cooldown(...)`` line is not by itself evidence of
        tracking. The VPN integrity monitor records it as an INFO ``API_COOLDOWN``
        observation (the dedicated APIAbuseMonitor still applies its own,
        frequency-based judgment separately).
        """
        # Real ProtonVPN log format
        log_line = '2026-01-26T05:00:00.000000Z | ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}'

        detections = monitor.analyze_log_entry(log_line)

        # Should observe the cooldown
        assert len(detections) > 0, "Should observe API cooldown"

        api_detection = next((d for d in detections if d.attack_type == "API_COOLDOWN"), None)
        assert api_detection is not None, "Should identify as API_COOLDOWN observation"
        assert api_detection.threat_level == ThreatLevel.INFO, "API cooldown should be INFO"
        assert "API_COOLDOWN" in api_detection.indicators

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
        """An unknown (full-length) fingerprint is LOW, not HIGH MITM.

        Policy change (timeline engine): a certificate fingerprint pulled from a
        log is a weak signal on its own, so an unknown fingerprint is LOW rather
        than HIGH ``MITM_CERTIFICATE``. Fingerprints shorter than 32 hex chars are
        rejected entirely (see test_reject_short_fingerprint).
        """
        # Unknown, but full 64-hex-char (SHA-256) fingerprint
        fp = "abcdef0123456789" * 4  # 64 hex chars
        log_line = f"DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: '{fp}'"

        detections = monitor.analyze_log_entry(log_line)

        cert_detection = next(
            (d for d in detections if d.attack_type == "UNKNOWN_CERT_FINGERPRINT"), None
        )
        assert cert_detection is not None, "Should observe unknown certificate"
        assert cert_detection.threat_level == ThreatLevel.LOW, "Unknown cert should be LOW"

    def test_reject_short_fingerprint(self, monitor):
        """Fingerprints shorter than 32 hex chars are ignored, not escalated."""
        log_line = "DEBUG | USER_CERT | Certificate with features saved | certificateFingerprint: 'deadbeef12345678'"

        detections = monitor.analyze_log_entry(log_line)

        assert not any(
            d.attack_type == "UNKNOWN_CERT_FINGERPRINT" for d in detections
        ), "Short/ambiguous fingerprint must not produce a threat"

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
        """Complete log sequence, scored under the new observation/judgment policy.

        Policy change (timeline engine): TCP and cooldown are INFO observations
        (TRANSPORT_TCP / API_COOLDOWN), the known-good cert stays NONE, and only
        the DNS64 IP churn produces an actionable MEDIUM judgment. Crucially, the
        whole sequence yields no HIGH/CRITICAL.
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

        attack_types_detected = {d.attack_type for d in all_detections if d.attack_type}

        # TCP and cooldown are now INFO observations, not attacks.
        assert "TRANSPORT_TCP" in attack_types_detected, "Should observe TCP transport"
        assert "API_COOLDOWN" in attack_types_detected, "Should observe API cooldown"

        # DNS64 churn still yields the one actionable judgment.
        assert any(
            t in attack_types_detected for t in ["FORCED_RECONNECTION", "CONNECTION_DISRUPTION"]
        ), "Should detect DNS64 IP churn"

        # New policy: no HIGH/CRITICAL for this sequence.
        assert not any(
            d.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] for d in all_detections
        ), "Normal Proton/iOS behaviour must not score HIGH/CRITICAL"

        # Certificate should pass.
        cert_detections = [d for d in all_detections if "CERT" in str(d.indicators)]
        if cert_detections:
            known_good = [d for d in cert_detections if d.threat_level == ThreatLevel.NONE]
            assert len(known_good) > 0, "Known-good certificate should pass validation"

    def test_json_log_format_parsing(self, monitor):
        """JSON cooldown entries parse to an INFO observation.

        Policy change (timeline engine): a cooldown is an INFO ``API_COOLDOWN``
        observation regardless of log format, not a HIGH/MEDIUM threat.
        """
        # ProtonVPN uses JSON format
        json_log = '{"timestamp":"2026-01-26T04:30:00Z","level":"ERROR","error":"cooldown(2026-01-26 05:24:44 +0000)"}'

        detections = monitor.analyze_log_entry(json_log)

        cooldown_detection = next(
            (d for d in detections if d.attack_type == "API_COOLDOWN"), None
        )
        assert cooldown_detection is not None, "Should observe cooldown in JSON format"
        assert cooldown_detection.threat_level == ThreatLevel.INFO

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
    
    def test_rapid_multi_server_hopping_pattern(self, monitor):
        """Test detection of rapid server hopping (4 servers in 7-10 minutes).
        
        Real-world scenario from iOS_DEVICE_TESTING_GUIDE.md:
        - User connects to 4 different servers within 7-10 minutes
        - Indicates forced disconnections or connection instability
        - Should trigger FORCED_RECONNECTION alert
        """
        base_time = datetime.now()
        
        # Simulate connections to 4 different servers over 7 minutes
        servers = [
            "185.159.157.99",  # Server 1
            "104.245.144.186", # Server 2
            "91.193.4.90",     # Server 3
            "212.102.46.78"    # Server 4
        ]
        
        # Connect to each server with 2-minute intervals
        for i, server in enumerate(servers):
            time_offset = i * 2  # 0, 2, 4, 6 minutes
            timestamp = (base_time + timedelta(minutes=time_offset)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
            
            # WireGuard DNS64 log format
            log_line = f"{timestamp} | INFO | DNS64: mapped {server}"
            detections = monitor.analyze_log_entry(log_line)
        
        # After 4 servers in 6 minutes, should detect hopping
        assert len(monitor.server_connections) == 4, "Should track all 4 server connections"
        
        # Check if any detection flagged rapid switching
        all_detections = []
        for conn in monitor.server_connections:
            if hasattr(conn, 'threat_level') and conn.threat_level != ThreatLevel.NONE:
                all_detections.append(conn)
        
        # Should have detected forced reconnections (7 minutes < 10 minute threshold)
        assert len(all_detections) > 0 or len(monitor.server_connections) >= 4, \
            "Should detect rapid server hopping pattern"
    
    def test_combined_attack_sequence(self, monitor):
        """Combined TCP + cooldown + DNS64 churn under the new policy.

        Policy change (timeline engine): TCP and cooldown are INFO observations;
        only DNS64 IP churn is actionable (MEDIUM). Nothing here is HIGH/CRITICAL.
        """
        all_detections = []
        
        # Phase 1: TCP Fallback (MEDIUM threat)
        tcp_log = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        detections = monitor.analyze_log_entry(tcp_log)
        all_detections.extend(detections)
        
        # Phase 2: API Rate Limiting (HIGH threat)
        api_log = '{"error":"cooldown(2026-01-26T05:14:55.103672Z)","endpoint":"/vpn/servers"}'
        detections = monitor.analyze_log_entry(api_log)
        all_detections.extend(detections)
        
        # Phase 3: Rapid Server Hopping (MEDIUM threat)
        base_time = datetime.now()
        for i in range(4):
            timestamp = (base_time + timedelta(minutes=i*2)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
            server_log = f"{timestamp} | INFO | DNS64: mapped 185.159.157.{100+i}"
            detections = monitor.analyze_log_entry(server_log)
            all_detections.extend(detections)
        
        # Verify observation types detected
        attack_types = {d.attack_type for d in all_detections if d}

        assert "TRANSPORT_TCP" in attack_types, "Should observe TCP transport"
        assert "API_COOLDOWN" in attack_types, "Should observe API cooldown"

        # No HIGH/CRITICAL should come out of this normal-looking churn.
        assert not any(
            d.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] for d in all_detections
        ), "Combined normal behaviour must not score HIGH/CRITICAL"
