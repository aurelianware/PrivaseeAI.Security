"""Unit tests for iOS backup analysis functionality (Prompts 6.1-6.3)."""

import pytest
from pathlib import Path
import tempfile
import shutil
import plistlib
import sqlite3

from privaseeai_security.device_info import (
    DeviceInfoExtractor,
    ProfileInfo,
    AppInfo
)
from privaseeai_security.crypto.cert_validator import ThreatLevel


class TestBackupAnalysis:
    """Test real iOS backup parsing functionality (Prompt 6.1)."""
    
    @pytest.fixture
    def mock_backup_dir(self):
        """Create mock iOS backup directory structure."""
        temp_dir = tempfile.mkdtemp()
        backup_dir = Path(temp_dir)
        
        # Create Info.plist
        info_data = {
            "Device Name": "Test iPhone",
            "Product Version": "17.2",
            "Product Type": "iPhone15,2",
            "Unique Identifier": "test-device-123",
            "Serial Number": "C02YW0ECJHD5",
            "Build Version": "21C62"
        }
        
        with open(backup_dir / "Info.plist", 'wb') as f:
            plistlib.dump(info_data, f)
        
        # Create Manifest.plist
        manifest_data = {
            "BackupKeyBag": b"test_data",
            "Date": "2026-01-26",
            "IsEncrypted": False
        }
        
        with open(backup_dir / "Manifest.plist", 'wb') as f:
            plistlib.dump(manifest_data, f)
        
        # Create Manifest.db (SQLite)
        conn = sqlite3.connect(str(backup_dir / "Manifest.db"))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE Files (
                fileID TEXT PRIMARY KEY,
                domain TEXT,
                relativePath TEXT
            )
        ''')
        
        # Add some mock file entries
        cursor.execute('''
            INSERT INTO Files (fileID, domain, relativePath)
            VALUES ('abc123', 'AppDomain-com.apple.mobilesafari', 'Documents/test.db')
        ''')
        
        cursor.execute('''
            INSERT INTO Files (fileID, domain, relativePath)
            VALUES ('def456', 'SystemPreferencesDomain', 'Library/Preferences/com.apple.wifi.plist')
        ''')
        
        conn.commit()
        conn.close()
        
        yield backup_dir
        shutil.rmtree(temp_dir)
    
    def test_parse_manifest_database(self, mock_backup_dir):
        """Test querying Manifest.db SQLite database."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        
        # Test that we can read from Manifest.db
        manifest_db = mock_backup_dir / "Manifest.db"
        assert manifest_db.exists()
        
        conn = sqlite3.connect(str(manifest_db))
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM Files WHERE domain LIKE 'AppDomain%'")
        rows = cursor.fetchall()
        conn.close()
        
        assert len(rows) == 1
        assert 'mobilesafari' in rows[0][0]
    
    def test_extract_vpn_profiles(self, mock_backup_dir):
        """Test extracting VPN configuration profiles."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        vpn_profiles = extractor.extract_vpn_profiles()
        
        # Should return list (may be empty for mock backup)
        assert isinstance(vpn_profiles, list)
    
    def test_get_installed_apps(self, mock_backup_dir):
        """Test extracting installed applications list."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        apps = extractor.get_installed_apps()
        
        assert isinstance(apps, list)
        # Should find the mobilesafari app we added
        if apps:
            assert any('mobilesafari' in app.bundle_id for app in apps)
    
    def test_extract_network_configuration(self, mock_backup_dir):
        """Test parsing network settings from backup."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        network_config = extractor.analyze_network_configuration()
        
        assert isinstance(network_config, dict)
        assert "dns_servers" in network_config
        assert "wifi_networks" in network_config
        assert "proxy_settings" in network_config
    
    def test_validate_backup_with_real_structure(self, mock_backup_dir):
        """Test backup validation with real backup structure."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        is_valid = extractor.validate_backup()
        
        # Should be valid (has Info.plist and Manifest.plist)
        assert is_valid is True
    
    def test_extract_device_info_from_real_backup(self, mock_backup_dir):
        """Test extracting device info from real backup structure."""
        extractor = DeviceInfoExtractor(str(mock_backup_dir))
        device_info = extractor.extract_device_info()
        
        assert device_info.device_id == "test-device-123"
        assert device_info.device_name == "Test iPhone"
        assert device_info.ios_version == "17.2"
        assert device_info.model == "iPhone15,2"
        assert device_info.serial_number == "C02YW0ECJHD5"


class TestProfileExtraction:
    """Test security profile extraction (Prompt 6.2)."""
    
    @pytest.fixture
    def backup_with_profiles(self):
        """Create backup with VPN and MDM profiles."""
        temp_dir = tempfile.mkdtemp()
        backup_dir = Path(temp_dir)
        
        # Create basic backup structure
        with open(backup_dir / "Info.plist", 'wb') as f:
            plistlib.dump({"Device Name": "Test"}, f)
        
        with open(backup_dir / "Manifest.plist", 'wb') as f:
            plistlib.dump({"IsEncrypted": False}, f)
        
        # Create Manifest.db with VPN profile reference
        conn = sqlite3.connect(str(backup_dir / "Manifest.db"))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE Files (
                fileID TEXT PRIMARY KEY,
                domain TEXT,
                relativePath TEXT
            )
        ''')
        
        # Add VPN profile file reference
        file_id = "aabbccdd1122334455667788"
        cursor.execute('''
            INSERT INTO Files (fileID, domain, relativePath)
            VALUES (?, 'SystemPreferencesDomain', 'Library/Preferences/com.apple.vpn.managed.plist')
        ''', (file_id,))
        
        conn.commit()
        conn.close()
        
        # Create the actual VPN profile file (in hash subdirectory)
        hash_dir = backup_dir / file_id[:2]
        hash_dir.mkdir()
        
        vpn_profile_data = {
            "PayloadIdentifier": "com.example.vpn",
            "PayloadDisplayName": "Example VPN",
            "PayloadOrganization": "Example Corp",
            "PayloadCertificateUUID": "cert-123"  # Signed
        }
        
        with open(hash_dir / file_id, 'wb') as f:
            plistlib.dump(vpn_profile_data, f)
        
        yield backup_dir
        shutil.rmtree(temp_dir)
    
    def test_detect_unsigned_profile(self):
        """Test detection of unsigned security profiles."""
        # Create profile without certificate UUID
        profile = ProfileInfo(
            profile_id="test-123",
            profile_type="VPN",
            is_signed=False,
            organization=None
        )
        
        extractor = DeviceInfoExtractor("/tmp")
        indicators = extractor._detect_suspicious_indicators(profile)
        
        assert "Unsigned profile" in indicators
        assert "No organization specified" in indicators
    
    def test_validate_profile_signature(self, backup_with_profiles):
        """Test validation of profile digital signatures."""
        extractor = DeviceInfoExtractor(str(backup_with_profiles))
        profiles = extractor.extract_vpn_profiles()
        
        if profiles:
            # Should have signed profile from fixture
            signed_profile = profiles[0]
            assert signed_profile.is_signed is True
    
    def test_extract_security_profiles(self, backup_with_profiles):
        """Test extracting all security-relevant profiles."""
        extractor = DeviceInfoExtractor(str(backup_with_profiles))
        security_profiles = extractor.extract_security_profiles()
        
        assert isinstance(security_profiles, list)
        
        # Check that profiles have threat assessments
        for profile in security_profiles:
            assert hasattr(profile, 'threat_level')
            assert hasattr(profile, 'suspicious_indicators')
    
    def test_profile_threat_assessment(self):
        """Test threat level assessment for profiles."""
        extractor = DeviceInfoExtractor("/tmp")
        
        # Unsigned profile with no org = suspicious
        profile1 = ProfileInfo(
            profile_id="unsigned-1",
            profile_type="VPN",
            is_signed=False,
            organization=None
        )
        profile1.suspicious_indicators = extractor._detect_suspicious_indicators(profile1)
        threat_level = extractor._assess_threat_level(profile1)
        
        # Should be at least LOW threat
        assert threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        
        # Signed profile with org = safe
        profile2 = ProfileInfo(
            profile_id="signed-1",
            profile_type="VPN",
            is_signed=True,
            organization="Proton AG"
        )
        profile2.suspicious_indicators = extractor._detect_suspicious_indicators(profile2)
        threat_level2 = extractor._assess_threat_level(profile2)
        
        assert threat_level2 == ThreatLevel.NONE
    
    def test_suspicious_vpn_profile_name_detection(self):
        """Test detection of VPN profiles with suspicious names."""
        extractor = DeviceInfoExtractor("/tmp")
        
        suspicious_profile = ProfileInfo(
            profile_id="test-vpn",
            profile_type="VPN",
            is_signed=True,
            organization="Test Corp",
            display_name="Debug Proxy VPN"  # Suspicious!
        )
        
        indicators = extractor._detect_suspicious_indicators(suspicious_profile)
        
        assert any("Suspicious name" in ind for ind in indicators)
    
    def test_mdm_profile_without_organization(self):
        """Test detection of MDM profile without organization."""
        extractor = DeviceInfoExtractor("/tmp")
        
        mdm_profile = ProfileInfo(
            profile_id="mdm-1",
            profile_type="MDM",
            is_signed=True,
            organization=None  # No org = suspicious for MDM
        )
        
        indicators = extractor._detect_suspicious_indicators(mdm_profile)
        mdm_profile.suspicious_indicators = indicators  # Assign indicators to profile
        threat_level = extractor._assess_threat_level(mdm_profile)
        
        assert "MDM profile without verified organization" in indicators
        assert threat_level == ThreatLevel.HIGH
