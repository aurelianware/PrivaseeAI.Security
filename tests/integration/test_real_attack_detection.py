"""End-to-end integration tests for real attack detection.

This test suite validates the complete monitoring system against actual attack logs
from the ProtonVPN and WireGuard incident.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path

from src.privaseeai_security.config import Config
from src.privaseeai_security.crypto.cert_validator import ThreatLevel
from src.privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor, ThreatDetection
from src.privaseeai_security.monitors.api_abuse import APIAbuseMonitor
from src.privaseeai_security.alerting.telegram import TelegramAlerter


@pytest.fixture
def config():
    """Create test configuration."""
    return Config()


@pytest.fixture
def vpn_monitor(config):
    """Create VPN integrity monitor."""
    return VPNIntegrityMonitor(config)


@pytest.fixture
def api_monitor(config):
    """Create API abuse monitor."""
    return APIAbuseMonitor(config)


@pytest.fixture
def alerter():
    """Create Telegram alerter in dry-run mode."""
    return TelegramAlerter(dry_run=True, throttle_minutes=1)


@pytest.fixture
def real_attack_logs():
    """Real attack log sequence from January 26, 2026 incident."""
    return [
        # Initial VPN connection - UDP normal
        "2026-01-26T04:20:11.123456Z | INFO | PROTOCOL | New socketType value: udp",
        
        # Certificate validation - known-good ProtonVPN cert
        "Certificate with features saved | certificateFingerprint: '6a1e93785520dade', "
        "validUntil: '2026-01-27 04:27:11 +0000', refreshTime: '2026-01-26 22:27:11 +0000'",
        
        # TCP fallback attack begins - UDP blocked
        "2026-01-26T04:24:44.103672Z | INFO | PROTOCOL | New socketType value: tcp",
        
        # API rate limiting - location tracking
        '2026-01-26T04:24:55.234567Z | ERROR | API | User location request failed | '
        '{"error":"cooldown(2026-01-26 05:24:44 +0000)"}',
        
        # Server hopping pattern - 4 servers in 7 minutes
        "2026-01-26T04:25:00.000000Z | INFO | VPN | DNS64: mapped 185.159.157.22 to fd12::1",
        "2026-01-26T04:27:30.000000Z | INFO | VPN | DNS64: mapped 185.107.56.122 to fd12::2",
        "2026-01-26T04:29:15.000000Z | INFO | VPN | DNS64: mapped 91.90.44.6 to fd12::3",
        "2026-01-26T04:31:45.000000Z | INFO | VPN | DNS64: mapped 146.70.80.134 to fd12::4",
        
        # Continued TCP operation
        "2026-01-26T04:35:00.000000Z | INFO | PROTOCOL | socketType value: tcp",
    ]


class TestRealAttackDetection:
    """Test detection of actual attack patterns from real logs."""
    
    def test_detect_tcp_fallback_from_real_logs(self, vpn_monitor, real_attack_logs):
        """TCP transport is recorded as an INFO observation, not a MEDIUM attack.

        Policy change (timeline engine): a single TCP socketType line is normal
        Proton Smart Protocol behaviour. It surfaces as INFO ``TRANSPORT_TCP``; it
        is no longer scored MEDIUM ``TRANSPORT_MANIPULATION``.
        """
        # Process UDP log first
        udp_log = real_attack_logs[0]
        threats = vpn_monitor.analyze_log_entry(udp_log)
        # UDP is normal (NONE level).
        actionable_threats = [
            t for t in threats if t.threat_level.value not in ("NONE", "INFO")
        ]
        assert len(actionable_threats) == 0

        # Process TCP log
        tcp_log = real_attack_logs[2]
        threats = vpn_monitor.analyze_log_entry(tcp_log)

        tcp_obs = next((t for t in threats if t.attack_type == "TRANSPORT_TCP"), None)
        assert tcp_obs is not None, "Should observe TCP transport"
        assert tcp_obs.threat_level.value == "INFO"
        # And no MEDIUM+ threat from a single TCP line.
        assert not any(
            t.threat_level.value in ("MEDIUM", "HIGH", "CRITICAL") for t in threats
        )
    
    def test_detect_api_rate_limiting_from_real_logs(self, api_monitor, real_attack_logs):
        """Test API rate limiting detection from actual ProtonVPN logs."""
        rate_limit_log = real_attack_logs[3]
        
        threat = api_monitor.check_rate_limit_responses("com.protonvpn.app", rate_limit_log)
        
        assert threat is not None
        assert threat.threat_level == ThreatLevel.HIGH
        assert threat.attack_type == "API_TRACKING"
        assert "2026-01-26 05:24:44" in str(threat.indicators)
    
    def test_detect_server_hopping_from_real_logs(self, vpn_monitor, real_attack_logs):
        """Test server hopping detection from actual attack logs."""
        # Process server connection logs
        server_logs = real_attack_logs[4:8]  # 4 server connections
        
        all_threats = []
        for log in server_logs:
            threats = vpn_monitor.analyze_log_entry(log)
            all_threats.extend(threats)
        
        # Should detect rapid server hopping (4 servers in ~7 minutes)
        hopping_threats = [
            t for t in all_threats
            if t.attack_type in ["FORCED_RECONNECTION", "RAPID_RECONNECTION", "CONNECTION_DISRUPTION"]
        ]
        
        assert len(hopping_threats) > 0
        # Check actual threat level values
        threat_levels = [t.threat_level for t in hopping_threats]
        assert any(level.value == "MEDIUM" for level in threat_levels)
    
    def test_certificate_validation_from_real_logs(self, vpn_monitor, real_attack_logs):
        """Test certificate validation with known-good ProtonVPN cert."""
        cert_log = real_attack_logs[1]
        
        threats = vpn_monitor.analyze_log_entry(cert_log)
        
        # Should validate successfully with known-good fingerprint
        cert_threats = [t for t in threats if t.attack_type and "CERTIFICATE" in t.attack_type]
        
        # Known-good cert should not trigger threats (or returns empty if cert validation not in this log)
        if cert_threats:
            assert all(t.threat_level == ThreatLevel.NONE for t in cert_threats)
    
    def test_complete_attack_sequence(self, vpn_monitor, api_monitor, real_attack_logs):
        """Test detection of complete attack sequence."""
        vpn_threats = []
        api_threats = []
        
        # Process all logs through appropriate monitors
        for log in real_attack_logs:
            if "PROTOCOL" in log or "DNS64" in log or "Certificate" in log:
                threats = vpn_monitor.analyze_log_entry(log)
                vpn_threats.extend(threats)
            
            if "API" in log:
                threat = api_monitor.check_rate_limit_responses("com.protonvpn.app", log)
                if threat:
                    api_threats.append(threat)
        
        # Should detect multiple attack vectors
        all_threats = vpn_threats + api_threats
        
        # Filter out NONE level threats (successful validations)
        actionable_threats = [t for t in all_threats if t.threat_level != ThreatLevel.NONE]

        # Policy change (timeline engine): TCP is now an INFO observation
        # (TRANSPORT_TCP), while the dedicated APIAbuseMonitor still raises HIGH
        # API_TRACKING and DNS64 churn still yields a MEDIUM judgment.
        attack_types = {t.attack_type for t in actionable_threats}
        assert "TRANSPORT_TCP" in attack_types  # TCP observation
        assert "API_TRACKING" in attack_types  # from APIAbuseMonitor
        assert any(
            t in attack_types for t in ["FORCED_RECONNECTION", "CONNECTION_DISRUPTION"]
        )  # DNS64 churn
        # The VPN integrity monitor itself contributes nothing HIGH/CRITICAL.
        vpn_high = [
            t for t in vpn_threats
            if t.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
        ]
        assert len(vpn_high) == 0


class TestAlertingIntegration:
    """Test alerting system integration."""
    
    def test_send_alert_for_critical_threat(self, alerter):
        """Test sending alert for critical threat."""
        threat = ThreatDetection(
            threat_level=ThreatLevel.CRITICAL,
            attack_type="MITM_CERTIFICATE",
            indicators=[
                "Unknown certificate fingerprint detected",
                "Expected: 6a1e93785520dade",
                "Found: abc123def456"
            ],
            timestamp=datetime.now(),
            details="Self-signed certificate detected in VPN connection"
        )
        
        success = alerter.send_threat_alert(threat)
        assert success is True
    
    def test_send_alert_for_high_threat(self, alerter):
        """Test sending alert for high-severity threat."""
        threat = ThreatDetection(
            threat_level=ThreatLevel.HIGH,
            attack_type="API_TRACKING",
            indicators=[
                "Rate limit cooldown: 50 minutes",
                "Location API repeatedly blocked"
            ],
            timestamp=datetime.now(),
            details="API rate limiting detected - possible location tracking attempt"
        )
        
        success = alerter.send_threat_alert(threat)
        assert success is True
    
    def test_alert_throttling(self, alerter):
        """Test that similar alerts are throttled."""
        threat = ThreatDetection(
            threat_level=ThreatLevel.MEDIUM,
            attack_type="TRANSPORT_MANIPULATION",
            indicators=["TCP fallback detected"],
            timestamp=datetime.now(),
            details=None
        )
        
        # First alert should send
        first_send = alerter.send_threat_alert(threat)
        assert first_send is True
        
        # Immediate duplicate should be throttled
        second_send = alerter.send_threat_alert(threat)
        assert second_send is False
        
        # Force should bypass throttling
        force_send = alerter.send_threat_alert(threat, force=True)
        assert force_send is True
    
    def test_alert_severity_filtering(self, alerter):
        """Test that only high-severity threats trigger alerts."""
        # Low severity should not alert by default
        assert alerter.should_alert(ThreatLevel.LOW) is False
        assert alerter.should_alert(ThreatLevel.MEDIUM) is False
        
        # High and critical should alert
        assert alerter.should_alert(ThreatLevel.HIGH) is True
        assert alerter.should_alert(ThreatLevel.CRITICAL) is True
    
    def test_custom_alert_formatting(self, alerter):
        """Test custom alert message formatting."""
        success = alerter.send_custom_alert(
            title="Test Alert",
            message="This is a test of the alerting system",
            severity=ThreatLevel.MEDIUM
        )
        assert success is True


class TestEndToEndMonitoring:
    """Test complete monitoring workflow."""
    
    def test_process_logs_and_alert_workflow(
        self,
        vpn_monitor,
        api_monitor,
        alerter,
        real_attack_logs
    ):
        """Test complete workflow: logs → detection → alerting."""
        alerts_sent = []
        
        # Process all logs
        for log in real_attack_logs:
            threats = []
            
            # Route to appropriate monitor
            if "PROTOCOL" in log or "DNS64" in log or "Certificate" in log:
                threats.extend(vpn_monitor.analyze_log_entry(log))
            
            if "API" in log:
                api_threat = api_monitor.check_rate_limit_responses("com.protonvpn.app", log)
                if api_threat:
                    threats.append(api_threat)
            
            # Send alerts for high-severity threats
            for threat in threats:
                if alerter.should_alert(threat.threat_level):
                    success = alerter.send_threat_alert(threat)
                    if success:
                        alerts_sent.append(threat)
        
        # Verify alerts were sent for critical issues
        assert len(alerts_sent) >= 1  # At least one high/critical threat
        
        # Verify alert types
        alert_types = {alert.attack_type for alert in alerts_sent}
        assert "API_TRACKING" in alert_types  # Rate limiting is HIGH
    
    def test_graceful_handling_of_malformed_logs(
        self,
        vpn_monitor,
        api_monitor,
        alerter
    ):
        """Test that malformed logs don't crash the system."""
        malformed_logs = [
            "",  # Empty log
            "Random text without structure",
            '{"incomplete": "json"',  # Malformed JSON
            None,  # Would need string handling
        ]
        
        for log in malformed_logs:
            if log is None:
                continue
            
            try:
                # Should not raise exceptions
                vpn_monitor.analyze_log_entry(log)
                api_monitor.check_rate_limit_responses("test.app", log)
            except Exception as e:
                pytest.fail(f"Malformed log caused exception: {e}")
    
    def test_state_persistence_across_log_entries(self, vpn_monitor):
        """Monitor state persists across entries; TCP is observed as INFO.

        Policy change (timeline engine): the TCP line is recorded as an INFO
        ``TRANSPORT_TCP`` observation rather than a MEDIUM
        ``TRANSPORT_MANIPULATION`` threat. Protocol history is still tracked.
        """
        # Send UDP log
        udp_log = "2026-01-26T04:20:11.123456Z | INFO | PROTOCOL | New socketType value: udp"
        vpn_monitor.analyze_log_entry(udp_log)

        # Verify protocol history is tracked
        assert len(vpn_monitor.protocol_history) > 0

        # Send TCP log
        tcp_log = "2026-01-26T04:24:44.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        threats = vpn_monitor.analyze_log_entry(tcp_log)

        # Should observe TCP transport and record two protocol-history entries.
        assert len(vpn_monitor.protocol_history) >= 2
        assert any(t.attack_type == "TRANSPORT_TCP" for t in threats)


class TestThreatDetectionAccuracy:
    """Test accuracy of threat detection - minimize false positives."""
    
    def test_no_false_positives_for_normal_operation(self, vpn_monitor, api_monitor):
        """Test that normal logs don't trigger false alarms."""
        normal_logs = [
            "2026-01-26T10:00:00.000000Z | INFO | PROTOCOL | New socketType value: udp",
            "Certificate with features saved | certificateFingerprint: '6a1e93785520dade', "
            "validUntil: '2026-01-27 04:27:11 +0000'",
            "2026-01-26T10:05:00.000000Z | INFO | API | Location request successful | status: 200",
        ]
        
        all_threats = []
        for log in normal_logs:
            threats = vpn_monitor.analyze_log_entry(log)
            all_threats.extend(threats)
            
            api_threat = api_monitor.check_rate_limit_responses("com.protonvpn.app", log)
            if api_threat:
                all_threats.append(api_threat)
        
        # Filter out NONE-level (successful validations)
        actionable_threats = [t for t in all_threats if t.threat_level.value != "NONE"]
        
        # Normal operation should not trigger actionable threats
        assert len(actionable_threats) == 0
    
    def test_threat_level_accuracy(self, vpn_monitor, api_monitor):
        """Threat levels match the new policy: TCP INFO, cooldown (APIAbuse) HIGH.

        Policy change (timeline engine): a single TCP line is INFO
        ``TRANSPORT_TCP`` in the VPN integrity monitor. The dedicated
        APIAbuseMonitor still scores an active cooldown as HIGH.
        """
        # TCP transport should be an INFO observation
        tcp_log = "2026-01-26T04:24:44.103672Z | INFO | PROTOCOL | New socketType value: tcp"
        vpn_monitor.analyze_log_entry(
            "2026-01-26T04:20:00.000000Z | INFO | PROTOCOL | New socketType value: udp"
        )  # Establish UDP first
        threats = vpn_monitor.analyze_log_entry(tcp_log)
        tcp_threats = [t for t in threats if t.attack_type and "TRANSPORT" in t.attack_type]
        if tcp_threats:
            assert tcp_threats[0].threat_level.value == ThreatLevel.INFO.value

        # API rate limiting should be HIGH (active tracking attempt)
        api_log = '{"error":"cooldown(2026-01-26 05:24:44 +0000)"}'
        threat = api_monitor.check_rate_limit_responses("com.protonvpn.app", api_log)
        assert threat is not None
        assert threat.threat_level.value == ThreatLevel.HIGH.value
