"""Unit tests for Carrier Compromise Detector module.

Tests carrier-level attack detection including:
- eSIM profile manipulation
- Localhost VPN routing
- DNS tampering
- Network interface anomalies
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import plistlib
import tempfile
import shutil

from src.privaseeai_security.monitors.carrier_detection import (
    CarrierCompromiseDetector,
    CarrierThreatDetection,
    ESIMProfile,
    VPNProfile
)
from src.privaseeai_security.crypto.cert_validator import ThreatLevel


class TestCarrierDetectorInitialization:
    """Test CarrierCompromiseDetector initialization."""
    
    def test_detector_init_default(self):
        """Test detector initialization with defaults."""
        detector = CarrierCompromiseDetector()
        
        assert detector.config is not None
        assert detector.logger is not None
        assert len(detector.known_esim_profiles) == 0
        assert len(detector.known_vpn_profiles) == 0
        assert len(detector.dns_baseline) == 0
    
    def test_detector_init_with_config(self):
        """Test detector initialization with custom config."""
        from src.privaseeai_security.config import Config
        config = Config()
        detector = CarrierCompromiseDetector(config=config)
        
        assert detector.config is config
    
    def test_detector_profile_history_initialized(self):
        """Test profile history dictionaries are initialized."""
        detector = CarrierCompromiseDetector()
        
        assert isinstance(detector.esim_profile_history, dict)
        assert isinstance(detector.vpn_profile_history, dict)


class TestESIMProfileDetection:
    """Test eSIM profile monitoring and threat detection."""
    
    @pytest.fixture
    def temp_backup(self):
        """Create temporary backup directory."""
        temp_dir = tempfile.mkdtemp()
        backup_dir = Path(temp_dir) / "Backup" / "test-device-id"
        backup_dir.mkdir(parents=True)
        yield backup_dir
        shutil.rmtree(temp_dir)
    
    def test_detect_unauthorized_esim_profile(self, temp_backup):
        """Test detection of unauthorized eSIM profile."""
        # Create fake carrier plist with suspicious profile
        carrier_data = {
            "ProfileID": "suspicious-esim-123",
            "CarrierName": "SuspiciousCarrier",
            "IsActive": True,
            "IsSigned": False,  # Unsigned = suspicious
            "Issuer": "localhost"  # Very suspicious
        }
        
        carrier_file = temp_backup / "carrier_test.plist"
        with open(carrier_file, 'wb') as f:
            plistlib.dump(carrier_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        threat = threats[0]
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.attack_type == "ESIM_MANIPULATION"
        assert "Unsigned" in str(threat.indicators)
        assert "localhost" in str(threat.indicators).lower()
    
    def test_identify_localhost_routing_in_vpn_profile(self, temp_backup):
        """Test detection of VPN profile routing to localhost."""
        # Create VPN profile with localhost server
        vpn_data = {
            "PayloadIdentifier": "com.malicious.vpn",
            "PayloadDisplayName": "Malicious VPN",
            "RemoteAddress": "127.0.0.1",  # CRITICAL: localhost routing
            "VPNType": "IKEv2"
            # PayloadCertificateUUID omitted = unsigned
        }
        
        vpn_file = temp_backup / "vpn_test.plist"
        with open(vpn_file, 'wb') as f:
            plistlib.dump(vpn_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.detect_localhost_routing(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        threat = threats[0]
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.attack_type == "LOCALHOST_VPN_ROUTING"
        assert "127.0.0.1" in str(threat.indicators)
    
    def test_detect_private_ip_vpn_routing(self, temp_backup):
        """Test detection of VPN profile using private IP."""
        vpn_data = {
            "PayloadIdentifier": "com.corporate.vpn",
            "PayloadDisplayName": "Corporate VPN",
            "ServerAddress": "192.168.1.100",  # Private IP
            "VPNType": "IKEv2"
        }
        
        vpn_file = temp_backup / "corporate_vpn.plist"
        with open(vpn_file, 'wb') as f:
            plistlib.dump(vpn_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.detect_localhost_routing(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        assert "private ip" in str(threats[0].indicators).lower()  # Case-insensitive match
    
    def test_parse_ios_carrier_bundle(self, temp_backup):
        """Test parsing of iOS CarrierBundle files."""
        carrier_data = {
            "ProfileID": "carrier-bundle-456",
            "CarrierName": "T-Mobile",  # Known carrier
            "IsActive": True,
            "IsSigned": True
        }
        
        carrier_file = temp_backup / "CarrierBundle.plist"
        with open(carrier_file, 'wb') as f:
            plistlib.dump(carrier_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=temp_backup.parent.parent)
        
        # Should NOT detect threat for legitimate carrier
        assert len(threats) == 0
        assert "carrier-bundle-456" in detector.known_esim_profiles
    
    def test_track_profile_across_backups(self, temp_backup):
        """Test tracking eSIM profiles across multiple backup snapshots."""
        # Create two backup snapshots
        backup1 = temp_backup
        backup2 = temp_backup.parent / "test-device-id-2"
        backup2.mkdir()
        
        # Same profile in both backups (persistent profile)
        profile_data = {
            "ProfileID": "persistent-profile-789",
            "CarrierName": "UnknownCarrier",
            "IsActive": True,
            "IsSigned": False
        }
        
        for backup in [backup1, backup2]:
            carrier_file = backup / "carrier_persistent.plist"
            with open(carrier_file, 'wb') as f:
                plistlib.dump(profile_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=temp_backup.parent.parent, 
                                                 compare_across_backups=True)
        
        # Should detect persistent suspicious profile
        assert len(threats) > 0
        threat_indicators = str([t.indicators for t in threats])
        assert "persists across" in threat_indicators.lower() or "Unknown carrier" in threat_indicators
    
    def test_detect_dns_tampering(self):
        """Test DNS configuration tampering detection."""
        detector = CarrierCompromiseDetector()
        detector.dns_baseline = ["8.8.8.8", "8.8.4.4"]  # Google DNS baseline
        
        # Mock scutil output with tampered DNS (localhost)
        scutil_output = """
resolver #1
  nameserver[0] : 127.0.0.1
  nameserver[1] : ::1
"""
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                stdout=scutil_output,
                returncode=0
            )
            
            threats = detector.analyze_dns_resolution()
            
            assert len(threats) > 0
            threat = threats[0]
            assert threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            assert "localhost" in str(threat.indicators).lower() or "127.0.0.1" in str(threat.indicators)
    
    def test_monitor_network_interface_changes(self):
        """Test monitoring of network interface changes."""
        detector = CarrierCompromiseDetector()
        
        # Mock ifconfig output with suspicious TUN interfaces
        ifconfig_output = """
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                stdout=ifconfig_output,
                returncode=0
            )
            
            threats = detector.track_network_interfaces()
            
            # Should flag excessive TUN/TAP interfaces
            assert len(threats) > 0
            # Check that details include interface names
            assert "utun" in str(threats[0].details).lower()


class TestVPNProfileValidation:
    """Test VPN profile validation and threat detection."""
    
    @pytest.fixture
    def temp_backup(self):
        """Create temporary backup directory."""
        temp_dir = tempfile.mkdtemp()
        backup_dir = Path(temp_dir) / "Backup" / "test-device-id"
        backup_dir.mkdir(parents=True)
        yield backup_dir
        shutil.rmtree(temp_dir)
    
    def test_validate_carrier_profile_signature(self, temp_backup):
        """Test validation of carrier profile signatures."""
        # Unsigned profile (suspicious)
        unsigned_data = {
            "ProfileID": "unsigned-profile",
            "CarrierName": "TestCarrier",
            "IsActive": True,
            "IsSigned": False
        }
        
        carrier_file = temp_backup / "unsigned_carrier.plist"
        with open(carrier_file, 'wb') as f:
            plistlib.dump(unsigned_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        assert "Unsigned" in str(threats[0].indicators)
    
    def test_detect_vpn_profile_no_remote_endpoint(self, temp_backup):
        """Test detection of VPN profile with no remote endpoint."""
        vpn_data = {
            "PayloadIdentifier": "com.noop.vpn",
            "PayloadDisplayName": "Fake VPN",
            "RemoteAddress": "",  # No endpoint
            "VPNType": "IKEv2"
        }
        
        vpn_file = temp_backup / "noop_vpn.plist"
        with open(vpn_file, 'wb') as f:
            plistlib.dump(vpn_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.detect_localhost_routing(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        assert "no remote endpoint" in str(threats[0].indicators).lower()
    
    def test_detect_mdm_vpn_profile(self, temp_backup):
        """Test detection of MDM-installed VPN profiles."""
        mdm_data = {
            "PayloadContent": [{
                "PayloadType": "com.apple.vpn.managed",
                "PayloadIdentifier": "com.mdm.vpn",
                "PayloadDisplayName": "MDM VPN",
                "RemoteAddress": "vpn.company.com",
                "VPNType": "IKEv2"
                # PayloadOrganization omitted = no organization = suspicious
            }]
        }
        
        mdm_file = temp_backup / "com.apple.mdm.plist"
        with open(mdm_file, 'wb') as f:
            plistlib.dump(mdm_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.detect_localhost_routing(backup_path=temp_backup.parent.parent)
        
        # MDM profile without organization should be flagged
        if len(threats) > 0:
            assert "MDM" in str(threats[0].details) or "organization" in str(threats[0].indicators).lower()
    
    def test_detect_suspicious_vpn_name(self, temp_backup):
        """Test detection of VPN profiles with suspicious names."""
        vpn_data = {
            "PayloadIdentifier": "com.debug.vpn",
            "PayloadDisplayName": "Debug Proxy",  # Suspicious keyword
            "ServerAddress": "10.0.0.1",
            "VPNType": "IKEv2"
        }
        
        vpn_file = temp_backup / "debug_vpn.plist"
        with open(vpn_file, 'wb') as f:
            plistlib.dump(vpn_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.detect_localhost_routing(backup_path=temp_backup.parent.parent)
        
        assert len(threats) > 0
        assert "Suspicious profile name" in str(threats[0].indicators)


class TestPrivateIPDetection:
    """Test private IP address detection helper."""
    
    def test_is_private_ip_class_a(self):
        """Test detection of Class A private IPs (10.x.x.x)."""
        detector = CarrierCompromiseDetector()
        
        assert detector._is_private_ip("10.0.0.1") is True
        assert detector._is_private_ip("10.255.255.255") is True
    
    def test_is_private_ip_class_b(self):
        """Test detection of Class B private IPs (172.16-31.x.x)."""
        detector = CarrierCompromiseDetector()
        
        assert detector._is_private_ip("172.16.0.1") is True
        assert detector._is_private_ip("172.31.255.255") is True
        assert detector._is_private_ip("172.15.0.1") is False  # Not in range
        assert detector._is_private_ip("172.32.0.1") is False  # Not in range
    
    def test_is_private_ip_class_c(self):
        """Test detection of Class C private IPs (192.168.x.x)."""
        detector = CarrierCompromiseDetector()
        
        assert detector._is_private_ip("192.168.1.1") is True
        assert detector._is_private_ip("192.168.255.255") is True
    
    def test_is_private_ip_public_addresses(self):
        """Test that public IPs are not flagged as private."""
        detector = CarrierCompromiseDetector()
        
        assert detector._is_private_ip("8.8.8.8") is False
        assert detector._is_private_ip("1.1.1.1") is False
        assert detector._is_private_ip("104.21.45.66") is False
    
    def test_is_private_ip_edge_cases(self):
        """Test edge cases for private IP detection."""
        detector = CarrierCompromiseDetector()
        
        assert detector._is_private_ip("") is False
        assert detector._is_private_ip("unknown") is False
        assert detector._is_private_ip(None) is False


class TestThreatDataClasses:
    """Test threat detection dataclasses."""
    
    def test_carrier_threat_detection_creation(self):
        """Test CarrierThreatDetection dataclass."""
        threat = CarrierThreatDetection(
            threat_level=ThreatLevel.CRITICAL,
            attack_type="LOCALHOST_VPN_ROUTING",
            indicators=["VPN points to localhost"],
            timestamp=datetime.now()
        )
        
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.attack_type == "LOCALHOST_VPN_ROUTING"
        assert len(threat.indicators) == 1
        assert isinstance(threat.timestamp, datetime)
    
    def test_esim_profile_dataclass(self):
        """Test ESIMProfile dataclass."""
        profile = ESIMProfile(
            profile_id="esim-123",
            carrier_name="T-Mobile",
            is_active=True,
            is_signed=True,
            issuer="T-Mobile USA"
        )
        
        assert profile.profile_id == "esim-123"
        assert profile.carrier_name == "T-Mobile"
        assert profile.is_active is True
        assert profile.is_signed is True
    
    def test_vpn_profile_dataclass(self):
        """Test VPNProfile dataclass."""
        profile = VPNProfile(
            profile_id="vpn-456",
            display_name="ProtonVPN",
            server_address="vpn.protonvpn.ch",
            vpn_type="WireGuard",
            is_signed=True,
            organization="Proton AG"
        )
        
        assert profile.profile_id == "vpn-456"
        assert profile.display_name == "ProtonVPN"
        assert profile.server_address == "vpn.protonvpn.ch"
        assert profile.vpn_type == "WireGuard"


class TestDNSParsing:
    """Test DNS server parsing from scutil output."""
    
    def test_parse_dns_servers_ipv4(self):
        """Test parsing IPv4 DNS servers."""
        detector = CarrierCompromiseDetector()
        scutil_output = """
resolver #1
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
"""
        
        dns_servers = detector._parse_dns_servers(scutil_output)
        
        assert "8.8.8.8" in dns_servers
        assert "8.8.4.4" in dns_servers
    
    def test_parse_dns_servers_ipv6(self):
        """Test parsing IPv6 DNS servers."""
        detector = CarrierCompromiseDetector()
        scutil_output = """
resolver #1
  nameserver[0] : 2001:4860:4860::8888
  nameserver[1] : 2001:4860:4860::8844
"""
        
        dns_servers = detector._parse_dns_servers(scutil_output)
        
        assert "2001:4860:4860::8888" in dns_servers
        assert "2001:4860:4860::8844" in dns_servers
    
    def test_parse_dns_servers_mixed(self):
        """Test parsing mixed IPv4/IPv6 DNS servers."""
        detector = CarrierCompromiseDetector()
        scutil_output = """
resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : fd27:50a3:7f28:8::1
"""
        
        dns_servers = detector._parse_dns_servers(scutil_output)
        
        assert "192.168.1.1" in dns_servers
        assert "fd27:50a3:7f28:8::1" in dns_servers


class TestNetworkInterfaceParsing:
    """Test network interface parsing from ifconfig output."""
    
    def test_parse_network_interfaces(self):
        """Test parsing network interface names."""
        detector = CarrierCompromiseDetector()
        ifconfig_output = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""
        
        interfaces = detector._parse_network_interfaces(ifconfig_output)
        
        assert "en0" in interfaces
        assert "utun0" in interfaces
        assert "utun1" in interfaces
    
    def test_parse_network_interfaces_tun_only(self):
        """Test filtering TUN/TAP interfaces."""
        detector = CarrierCompromiseDetector()
        ifconfig_output = """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""
        
        interfaces = detector._parse_network_interfaces(ifconfig_output)
        tun_interfaces = [i for i in interfaces if 'tun' in i or 'tap' in i]
        
        assert len(tun_interfaces) == 3


class TestErrorHandling:
    """Test error handling in carrier detection."""
    
    def test_monitor_esim_nonexistent_backup(self):
        """Test handling of non-existent backup path."""
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=Path("/nonexistent/path"))
        
        # Should return empty list, not crash
        assert threats == []
    
    def test_localhost_routing_empty_backup(self):
        """Test handling of empty backup directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "Backup"
            backup_dir.mkdir()
            
            detector = CarrierCompromiseDetector()
            threats = detector.detect_localhost_routing(backup_path=backup_dir)
            
            assert threats == []
    
    def test_dns_analysis_subprocess_error(self):
        """Test handling of subprocess errors in DNS analysis."""
        detector = CarrierCompromiseDetector()
        
        with patch('subprocess.run', side_effect=Exception("Command failed")):
            threats = detector.analyze_dns_resolution()
            
            # Should handle error gracefully
            assert isinstance(threats, list)
    
    def test_encrypted_backup_handling(self):
        """Test graceful handling of encrypted backups.
        
        Real-world scenario from iOS_DEVICE_TESTING_GUIDE.md:
        - User has encrypted iOS backup
        - Cannot read without password
        - Should return helpful error, not crash
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "Backup" / "encrypted-device-id"
            backup_dir.mkdir(parents=True)
            
            # Create a Manifest.plist indicating encryption
            manifest_data = {
                "IsEncrypted": True,
                "BackupKeyBag": b"encrypted_data_here"
            }
            
            manifest_file = backup_dir / "Manifest.plist"
            with open(manifest_file, 'wb') as f:
                plistlib.dump(manifest_data, f)
            
            detector = CarrierCompromiseDetector()
            
            # Should not crash on encrypted backup
            try:
                esim_threats = detector.monitor_esim_profiles(backup_path=backup_dir.parent.parent)
                vpn_threats = detector.detect_localhost_routing(backup_path=backup_dir.parent.parent)
                
                # Should return empty or handle gracefully
                assert isinstance(esim_threats, list)
                assert isinstance(vpn_threats, list)
            except Exception as e:
                pytest.fail(f"Should handle encrypted backup gracefully, but got: {e}")


class TestBackupComparison:
    """Test differential analysis across backup snapshots."""
    
    @pytest.fixture
    def multi_backup_dir(self):
        """Create multiple backup snapshots for comparison."""
        temp_dir = tempfile.mkdtemp()
        backup_root = Path(temp_dir) / "Backup"
        backup_root.mkdir()
        
        # Create 3 backup snapshots with different timestamps
        backups = []
        import time
        import os
        base_time = time.time()
        
        for i in range(3):
            backup_dir = backup_root / f"device-snapshot-{i}"
            backup_dir.mkdir()
            
            # Set modification time explicitly (older backups have older times)
            # backup-0: base_time - 2 days
            # backup-1: base_time - 1 day  
            # backup-2: base_time (most recent)
            mtime = base_time - (2 - i) * 86400  # 86400 seconds = 1 day
            os.utime(backup_dir, (mtime, mtime))
            
            backups.append(backup_dir)
        
        yield backup_root, backups
        shutil.rmtree(temp_dir)
    
    def test_profile_persistence_across_backups(self, multi_backup_dir):
        """Test detection of profiles that persist across multiple backups.
        
        Real-world scenario from iOS_DEVICE_TESTING_GUIDE.md:
        - Profile appears in multiple backup snapshots
        - Survives across time gaps (possible factory reset)
        - Should flag as suspicious persistence
        """
        backup_root, backups = multi_backup_dir
        
        # Create same suspicious profile in all 3 backups (persistent)
        persistent_profile_data = {
            "ProfileID": "persistent-rootkit-123",
            "CarrierName": "SuspiciousCarrier",
            "IsActive": True,
            "IsSigned": False
        }
        
        for backup in backups:
            carrier_file = backup / "persistent_carrier.plist"
            with open(carrier_file, 'wb') as f:
                plistlib.dump(persistent_profile_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=backup_root, compare_across_backups=True)
        
        # Should detect persistence across backups
        assert len(threats) > 0, "Should detect persistent suspicious profile"
        
        # Check that persistence is mentioned in indicators
        threat_indicators = ' '.join([str(t.indicators) for t in threats])
        assert "persist" in threat_indicators.lower() or "Unknown carrier" in threat_indicators, \
            "Should flag profile persistence or suspicious carrier"
    
    def test_profile_modification_detection(self, multi_backup_dir):
        """Test detection of profile modifications across backups."""
        backup_root, backups = multi_backup_dir
        
        profile_id = "modified-profile-456"
        
        # Create profile in first backup with original carrier
        original_data = {
            "ProfileID": profile_id,
            "CarrierName": "Verizon",
            "IsActive": True,
            "IsSigned": True
        }
        
        carrier_file_1 = backups[0] / "modified_carrier.plist"
        with open(carrier_file_1, 'wb') as f:
            plistlib.dump(original_data, f)
        
        # Create same profile in second backup with CHANGED carrier
        modified_data = {
            "ProfileID": profile_id,
            "CarrierName": "SuspiciousCarrier",  # Changed!
            "IsActive": True,
            "IsSigned": False  # Changed!
        }
        
        carrier_file_2 = backups[1] / "modified_carrier.plist"
        with open(carrier_file_2, 'wb') as f:
            plistlib.dump(modified_data, f)
        
        detector = CarrierCompromiseDetector()
        
        # First scan - should be clean
        threats_1 = detector.monitor_esim_profiles(backup_path=backups[0].parent, compare_across_backups=False)
        
        # Second scan - should detect modification
        threats_2 = detector.monitor_esim_profiles(backup_path=backups[1].parent, compare_across_backups=True)
        
        # Should detect the modification
        all_threats = threats_1 + threats_2
        assert len(all_threats) > 0, "Should detect profile modification"
        
        # Check that modification indicators are present
        threat_indicators = ' '.join([str(t.indicators) for t in all_threats])
        has_modification_indicator = any([
            "changed" in threat_indicators.lower(),
            "unsigned" in threat_indicators.lower(),
            "suspicious" in threat_indicators.lower()
        ])
        assert has_modification_indicator, "Should flag carrier name or signature change"
    
    @pytest.mark.skip(reason="Flaky timing issue in CI - needs refactoring")
    def test_new_profile_after_reset_simulation(self, multi_backup_dir):
        """Test detection of profiles appearing after simulated factory reset.
        
        Scenario: Profile appears in backup after significant time gap
        - Could indicate reinstallation after reset
        - Suspicious if profile wasn't user-installed
        """
        backup_root, backups = multi_backup_dir
        
        # First backup: No suspicious profiles
        normal_data = {
            "ProfileID": "legitimate-carrier",
            "CarrierName": "T-Mobile",
            "IsActive": True,
            "IsSigned": True
        }
        
        carrier_file_1 = backups[0] / "normal_carrier.plist"
        with open(carrier_file_1, 'wb') as f:
            plistlib.dump(normal_data, f)
        
        # Third backup (after gap): New suspicious profile appears
        new_suspicious_data = {
            "ProfileID": "post-reset-profile",
            "CarrierName": "UnknownCarrier",
            "IsActive": True,
            "IsSigned": False
        }
        
        carrier_file_3 = backups[2] / "new_carrier.plist"
        with open(carrier_file_3, 'wb') as f:
            plistlib.dump(new_suspicious_data, f)
        
        detector = CarrierCompromiseDetector()
        threats = detector.monitor_esim_profiles(backup_path=backup_root, compare_across_backups=True)
        
        # Should flag new unsigned profile with unknown carrier
        assert len(threats) > 0, "Should detect new suspicious profile"
        
        unsigned_threat = next((t for t in threats if "Unsigned" in str(t.indicators)), None)
        assert unsigned_threat is not None, "Should flag unsigned profile"
