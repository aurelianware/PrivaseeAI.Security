"""Device information extraction for iOS devices."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from pathlib import Path
import plistlib
import sqlite3
import logging
import tempfile
import shutil

try:
    from iOSbackup import iOSbackup
    HAS_IOSBACKUP = True
except ImportError:
    HAS_IOSBACKUP = False

from .crypto.cert_validator import ThreatLevel


class DeviceInfoError(Exception):
    """Device information error exception."""
    pass


@dataclass
class DeviceInfo:
    """iOS device information."""
    
    device_id: str
    device_name: str
    ios_version: str
    model: str
    serial_number: Optional[str] = None
    capacity: Optional[int] = None
    build_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert device info to dictionary.
        
        Returns:
            Dictionary representation of device info
        """
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "ios_version": self.ios_version,
            "model": self.model,
            "serial_number": self.serial_number,
            "capacity": self.capacity,
            "build_version": self.build_version,
        }


@dataclass
class ProfileInfo:
    """Security profile information from iOS backup.
    
    Represents VPN, MDM, Certificate, or Configuration profiles.
    """
    profile_id: str
    profile_type: str  # 'VPN' | 'MDM' | 'Certificate' | 'Configuration'
    is_signed: bool
    organization: Optional[str] = None
    display_name: Optional[str] = None
    install_date: Optional[str] = None
    suspicious_indicators: Optional[List[str]] = None
    threat_level: ThreatLevel = ThreatLevel.NONE
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile info to dictionary."""
        return {
            "profile_id": self.profile_id,
            "profile_type": self.profile_type,
            "is_signed": self.is_signed,
            "organization": self.organization,
            "display_name": self.display_name,
            "install_date": self.install_date,
            "suspicious_indicators": self.suspicious_indicators or [],
            "threat_level": self.threat_level.value
        }


@dataclass
class AppInfo:
    """Installed application information."""
    bundle_id: str
    app_name: str
    version: Optional[str] = None
    install_date: Optional[str] = None


class DeviceInfoExtractor:
    """Extract device information from iOS backups.
    
    Supports parsing Info.plist, Status.plist, Manifest.db (SQLite),
    and extracting security profiles, installed apps, and network configurations.
    """
    
    # Apple system paths that should not trigger alerts
    APPLE_SYSTEM_PATHS = {
        'Library/ConfigurationProfiles/',
        'Library/UserConfigurationProfiles/',
        'Library/Managed Preferences/',
        'SystemConfiguration/',
    }
    
    # Known legitimate organizations (can be expanded)
    # Note: Carriers (Verizon, AT&T, T-Mobile) intentionally NOT whitelisted
    # due to potential insider threat concerns
    KNOWN_LEGITIMATE_ORGS = {
        'Apple Inc.',
        'Apple',
        'NextDNS Inc',
        'NextDNS',
    }
    
    # Legitimate service identifiers (even if unsigned/no org)
    # Note: VPN profiles (networkextension) intentionally NOT whitelisted
    # to ensure all VPN configurations are reviewed
    KNOWN_LEGITIMATE_SERVICES = {
        'io.nextdns',  # NextDNS DNS privacy service
        'com.apple.managedconfiguration',  # Apple system config
    }
    
    # Suspicious VPN server patterns
    SUSPICIOUS_VPN_SERVERS = {
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
    }

    def __init__(self, backup_path: str, password: Optional[str] = None):
        """Initialize device info extractor.
        
        Args:
            backup_path: Path to iOS backup directory
            password: Optional password for encrypted backups
        """
        self.backup_path = Path(backup_path)
        self.password = password
        self.logger = logging.getLogger(__name__)
        self._decrypted_manifest_path = None
        
    def extract_device_info(self) -> DeviceInfo:
        """Extract device information from backup.
        
        Parses Info.plist from iOS backup directory.
        
        Returns:
            DeviceInfo object
            
        Raises:
            DeviceInfoError: If device info cannot be extracted
        """
        try:
            info_plist_path = self.backup_path / "Info.plist"
            
            if not info_plist_path.exists():
                self.logger.warning(f"Info.plist not found at {info_plist_path}")
                # Return stub data for testing
                return DeviceInfo(
                    device_id="unknown",
                    device_name="Unknown Device",
                    ios_version="unknown",
                    model="Unknown"
                )
            
            with open(info_plist_path, 'rb') as f:
                info_data = plistlib.load(f)
            
            return DeviceInfo(
                device_id=info_data.get("Unique Identifier", info_data.get("Device Name", "unknown")),
                device_name=info_data.get("Device Name", "Unknown"),
                ios_version=info_data.get("Product Version", "unknown"),
                model=info_data.get("Product Type", "Unknown"),
                serial_number=info_data.get("Serial Number"),
                build_version=info_data.get("Build Version"),
            )
            
        except Exception as e:
            self.logger.error(f"Failed to extract device info: {e}")
            raise DeviceInfoError(f"Failed to extract device info: {str(e)}") from e

    def get_device_id(self) -> str:
        """Get device ID from backup.
        
        Returns:
            Device ID string
            
        Raises:
            DeviceInfoError: If device ID cannot be found
        """
        try:
            device_info = self.extract_device_info()
            return device_info.device_id
        except Exception as e:
            raise DeviceInfoError(f"Failed to get device ID: {str(e)}") from e

    def validate_backup(self) -> bool:
        """Validate iOS backup structure.
        
        Checks for required files: Info.plist, Manifest.plist/Manifest.db
        
        Returns:
            True if backup is valid, False otherwise
        """
        try:
            # Check for Info.plist
            if not (self.backup_path / "Info.plist").exists():
                return False
            
            # Check for Manifest (either .plist or .db)
            has_manifest = (
                (self.backup_path / "Manifest.plist").exists() or
                (self.backup_path / "Manifest.db").exists()
            )
            
            return has_manifest
            
        except Exception:
            return False
    
    def get_installed_apps(self) -> List[AppInfo]:
        """List all installed applications from backup.
        
        Queries Manifest.db SQLite database for app domains.
        
        Returns:
            List of AppInfo objects for installed applications
        """
        apps = []
        
        try:
            manifest_db = self._get_manifest_db_path()
            
            if not manifest_db or not manifest_db.exists():
                self.logger.warning(f"Manifest.db not accessible")
                return apps
            
            conn = sqlite3.connect(str(manifest_db))
            cursor = conn.cursor()
            
            # Query for app domains
            query = """
                SELECT DISTINCT domain 
                FROM Files 
                WHERE domain LIKE 'AppDomain%' OR domain LIKE '%Container%'
                LIMIT 100
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                domain = row[0]
                # Extract bundle ID from domain (e.g., "AppDomain-com.apple.mobilesafari")
                if '-' in domain:
                    bundle_id = domain.split('-', 1)[1]
                    app_name = bundle_id.split('.')[-1].title()
                    
                    apps.append(AppInfo(
                        bundle_id=bundle_id,
                        app_name=app_name
                    ))
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to get installed apps: {e}")
        
        return apps
    
    def extract_vpn_profiles(self) -> List[ProfileInfo]:
        """Extract VPN configuration profiles from backup.
        
        Searches for VPN-related plist files in SystemPreferencesDomain.
        
        Returns:
            List of ProfileInfo objects for VPN profiles
        """
        profiles = []
        
        try:
            # Query Manifest.db for VPN-related files
            manifest_db = self._get_manifest_db_path()
            
            if not manifest_db or not manifest_db.exists():
                self.logger.warning(f"Manifest.db not accessible")
                return profiles
            
            conn = sqlite3.connect(str(manifest_db))
            cursor = conn.cursor()
            
            # Look for VPN configuration files
            query = """
                SELECT fileID, relativePath 
                FROM Files 
                WHERE (domain = 'SystemPreferencesDomain' OR domain LIKE '%Preferences%')
                  AND (relativePath LIKE '%vpn%' OR relativePath LIKE '%VPN%' 
                       OR relativePath LIKE '%NetworkExtension%')
                LIMIT 50
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for file_id, rel_path in rows:
                # Construct file path (iOS backup uses 2-char hash directories)
                file_path = self.backup_path / file_id[:2] / file_id
                
                if file_path.exists():
                    try:
                        with open(file_path, 'rb') as f:
                            vpn_data = plistlib.load(f)
                        
                        # Extract VPN profile info
                        profile = self._parse_vpn_profile(vpn_data, rel_path)
                        if profile:
                            profiles.append(profile)
                            
                    except Exception as e:
                        self.logger.debug(f"Could not parse VPN file {rel_path}: {e}")
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to extract VPN profiles: {e}")
        
        return profiles
    
    def get_mdm_profiles(self) -> List[ProfileInfo]:
        """Extract MDM (Mobile Device Management) profiles from backup.
        
        Returns:
            List of ProfileInfo objects for MDM profiles
        """
        profiles = []
        
        try:
            manifest_db = self._get_manifest_db_path()
            
            if not manifest_db or not manifest_db.exists():
                return profiles
            
            conn = sqlite3.connect(str(manifest_db))
            cursor = conn.cursor()
            
            # Look for MDM/management configuration files
            query = """
                SELECT fileID, relativePath 
                FROM Files 
                WHERE relativePath LIKE '%mdm%' 
                   OR relativePath LIKE '%MDM%'
                   OR relativePath LIKE '%ManagedPreferences%'
                   OR relativePath LIKE '%Configuration%Profile%'
                LIMIT 50
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for file_id, rel_path in rows:
                file_path = self.backup_path / file_id[:2] / file_id
                
                if file_path.exists():
                    try:
                        with open(file_path, 'rb') as f:
                            mdm_data = plistlib.load(f)
                        
                        profile = self._parse_mdm_profile(mdm_data, rel_path)
                        if profile:
                            profiles.append(profile)
                            
                    except Exception as e:
                        self.logger.debug(f"Could not parse MDM file {rel_path}: {e}")
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to extract MDM profiles: {e}")
        
        return profiles
    
    def analyze_network_configuration(self) -> Dict[str, Any]:
        """Parse network settings from backup.
        
        Extracts DNS, proxy, WiFi, and cellular configurations.
        
        Returns:
            Dictionary containing network configuration details
        """
        network_config = {
            "dns_servers": [],
            "wifi_networks": [],
            "proxy_settings": {},
            "cellular_settings": {}
        }
        
        try:
            manifest_db = self._get_manifest_db_path()
            
            if not manifest_db or not manifest_db.exists():
                return network_config
            
            conn = sqlite3.connect(str(manifest_db))
            cursor = conn.cursor()
            
            # Look for network preference files
            query = """
                SELECT fileID, relativePath 
                FROM Files 
                WHERE domain = 'SystemPreferencesDomain'
                  AND (relativePath LIKE '%com.apple.wifi%' 
                       OR relativePath LIKE '%com.apple.network%'
                       OR relativePath LIKE '%com.apple.commcenter%')
                LIMIT 20
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for file_id, rel_path in rows:
                file_path = self.backup_path / file_id[:2] / file_id
                
                if file_path.exists():
                    try:
                        with open(file_path, 'rb') as f:
                            net_data = plistlib.load(f)
                        
                        # Extract relevant network settings
                        if 'wifi' in rel_path.lower():
                            networks = self._extract_wifi_networks(net_data)
                            network_config["wifi_networks"].extend(networks)
                        
                        if 'network' in rel_path.lower():
                            dns = self._extract_dns_settings(net_data)
                            if dns:
                                network_config["dns_servers"].extend(dns)
                            
                    except Exception as e:
                        self.logger.debug(f"Could not parse network file {rel_path}: {e}")
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to analyze network configuration: {e}")
        
        return network_config
    
    def extract_security_profiles(self) -> List[ProfileInfo]:
        """Extract and analyze all security-relevant profiles.
        
        Combines VPN, MDM, Certificate, and Configuration profiles with
        threat analysis and suspicious indicator detection.
        
        Returns:
            List of ProfileInfo objects with threat assessments
        """
        all_profiles = []
        
        # Get VPN profiles
        vpn_profiles = self.extract_vpn_profiles()
        all_profiles.extend(vpn_profiles)
        
        # Get MDM profiles
        mdm_profiles = self.get_mdm_profiles()
        all_profiles.extend(mdm_profiles)
        
        # Analyze each profile for suspicious indicators
        for profile in all_profiles:
            profile.suspicious_indicators = self._detect_suspicious_indicators(profile)
            profile.threat_level = self._assess_threat_level(profile)
        
        return all_profiles
    
    def _parse_vpn_profile(self, vpn_data: Dict, rel_path: str) -> Optional[ProfileInfo]:
        """Parse VPN profile from plist data."""
        try:
            profile_id = vpn_data.get("PayloadIdentifier", rel_path)
            display_name = vpn_data.get("PayloadDisplayName", vpn_data.get("UserDefinedName", "VPN Profile"))
            organization = vpn_data.get("PayloadOrganization")
            is_signed = bool(vpn_data.get("PayloadCertificateUUID"))
            
            return ProfileInfo(
                profile_id=str(profile_id),
                profile_type="VPN",
                is_signed=is_signed,
                organization=organization,
                display_name=display_name
            )
        except Exception:
            return None
    
    def _parse_mdm_profile(self, mdm_data: Dict, rel_path: str) -> Optional[ProfileInfo]:
        """Parse MDM profile from plist data."""
        try:
            profile_id = mdm_data.get("PayloadIdentifier", rel_path)
            display_name = mdm_data.get("PayloadDisplayName", "MDM Profile")
            organization = mdm_data.get("PayloadOrganization")
            is_signed = bool(mdm_data.get("PayloadCertificateUUID"))
            
            return ProfileInfo(
                profile_id=str(profile_id),
                profile_type="MDM",
                is_signed=is_signed,
                organization=organization,
                display_name=display_name
            )
        except Exception:
            return None
    
    def _extract_wifi_networks(self, wifi_data: Dict) -> List[str]:
        """Extract WiFi network SSIDs from preferences."""
        networks = []
        try:
            if isinstance(wifi_data, dict):
                # Look for known WiFi keys in the plist
                known_networks = wifi_data.get("KnownNetworks", {})
                if isinstance(known_networks, dict):
                    networks.extend(known_networks.keys())
        except Exception:
            pass
        return networks
    
    def _extract_dns_settings(self, network_data: Dict) -> List[str]:
        """Extract DNS server addresses from network configuration."""
        dns_servers = []
        try:
            if isinstance(network_data, dict):
                # Look for DNS configuration
                dns_config = network_data.get("DNS", {})
                if isinstance(dns_config, dict):
                    servers = dns_config.get("ServerAddresses", [])
                    if isinstance(servers, list):
                        dns_servers.extend([str(s) for s in servers])
        except Exception:
            pass
        return dns_servers
    
    def _detect_suspicious_indicators(self, profile: ProfileInfo) -> List[str]:
        """Detect suspicious attributes in a profile.
        
        Uses whitelisting to reduce false positives from Apple system files.
        """
        indicators = []
        
        # Check if this is an Apple system file (whitelist)
        if self._is_apple_system_file(profile.profile_id):
            # System files are expected, not suspicious
            return []
        
        # Check if this is a known legitimate service
        if self._is_known_service(profile.profile_id):
            return []
        
        # Check if from known legitimate organization
        is_known_org = profile.organization in self.KNOWN_LEGITIMATE_ORGS if profile.organization else False
        
        # VPN-specific checks
        if profile.profile_type == "VPN":
            # Check for localhost/suspicious servers (CRITICAL)
            if self._has_localhost_server(profile):
                indicators.append("VPN server points to localhost (CRITICAL)")
            
            # Check for suspicious names
            if profile.display_name and any(kw in profile.display_name.lower() 
                                           for kw in ["test", "debug", "local", "proxy"]):
                indicators.append(f"Suspicious VPN name: {profile.display_name}")
            
            # Unsigned VPN from unknown org is concerning
            if not profile.is_signed and not is_known_org:
                indicators.append("Unsigned VPN profile from unknown organization")
            elif not profile.organization:
                indicators.append("VPN profile with no organization")
        
        # MDM-specific checks
        elif profile.profile_type == "MDM":
            # MDM without organization is more suspicious if also unsigned
            if not profile.is_signed and not profile.organization:
                indicators.append("Unsigned MDM profile with no organization")
            elif not profile.organization and not is_known_org:
                # MDM from unknown org is less critical if signed
                if profile.is_signed:
                    indicators.append("MDM profile from unknown organization (signed)")
        
        return indicators
    
    def _assess_threat_level(self, profile: ProfileInfo) -> ThreatLevel:
        """Assess threat level based on suspicious indicators.
        
        Uses confidence-based scoring:
        - CRITICAL: Localhost VPN servers, multiple high-risk indicators
        - HIGH: Unsigned VPN from unknown org, suspicious names
        - MEDIUM: Single concerning indicator (unsigned, no org)
        - LOW: Minor concerns (signed but unknown org)
        - NONE: Clean or whitelisted
        """
        if not profile.suspicious_indicators:
            return ThreatLevel.NONE
        
        indicators_str = str(profile.suspicious_indicators)
        
        # CRITICAL: Localhost VPN server (definite attack)
        if "localhost (CRITICAL)" in indicators_str:
            return ThreatLevel.CRITICAL
        
        # CRITICAL: Multiple high-risk indicators
        if "Unsigned VPN profile from unknown" in indicators_str:
            return ThreatLevel.CRITICAL
        
        if "Unsigned MDM profile with no organization" in indicators_str:
            return ThreatLevel.CRITICAL
        
        # HIGH: Suspicious VPN configuration
        if "Suspicious VPN name" in indicators_str:
            return ThreatLevel.HIGH
        
        # MEDIUM: Single concerning indicator
        if "VPN profile with no organization" in indicators_str:
            return ThreatLevel.MEDIUM
        
        # LOW: Minor concerns (signed but unknown org)
        if "unknown organization (signed)" in indicators_str:
            return ThreatLevel.LOW
        
        # Default to LOW for any other single indicator
        if len(profile.suspicious_indicators) == 1:
            return ThreatLevel.LOW
        
        # Multiple indicators without specific patterns
        return ThreatLevel.MEDIUM
    
    def _is_apple_system_file(self, profile_id: str) -> bool:
        """Check if profile ID matches known Apple system paths.
        
        Args:
            profile_id: Profile identifier or path
            
        Returns:
            True if this is a known Apple system file
        """
        if not profile_id:
            return False
        
        # Check against known Apple system paths
        for system_path in self.APPLE_SYSTEM_PATHS:
            if system_path in profile_id:
                return True
        
        # Check for 
    
    def _is_known_service(self, profile_id: str) -> bool:
        """Check if profile ID is from a known legitimate service.
        
        Args:
            profile_id: Profile identifier or path
            
        Returns:
            True if this is a known legitimate service
        """
        if not profile_id:
            return False
        
        # Check against known legitimate services
        for service in self.KNOWN_LEGITIMATE_SERVICES:
            if service in profile_id:
                return True
        
        return False
    
    def _has_localhost_server(self, profile: ProfileInfo) -> bool:
        """Check if VPN profile uses localhost or suspicious servers.
        
        Args:
            profile: ProfileInfo object to check
            
        Returns:
            True if profile contains localhost or suspicious server references
        """
        if profile.profile_type != "VPN":
            return False
        
        # Check profile ID and display name for localhost patterns
        check_strings = [
            profile.profile_id.lower() if profile.profile_id else "",
            profile.display_name.lower() if profile.display_name else "",
        ]
        
        for check_str in check_strings:
            for suspicious_server in self.SUSPICIOUS_VPN_SERVERS:
                if suspicious_server in check_str:
                    return True
        
        return False
    
    def _get_manifest_db_path(self) -> Optional[Path]:
        """Get path to Manifest.db, decrypting if necessary.
        
        Returns:
            Path to Manifest.db (decrypted if encrypted), or None if not accessible
        """
        manifest_db = self.backup_path / "Manifest.db"
        
        if not manifest_db.exists():
            return None
        
        # Check if backup is encrypted
        if self._is_backup_encrypted():
            if not self.password:
                self.logger.warning("Backup is encrypted but no password provided")
                return None
            
            # Return cached decrypted path or decrypt now
            if self._decrypted_manifest_path and self._decrypted_manifest_path.exists():
                return self._decrypted_manifest_path
            
            return self._decrypt_manifest_db()
        
        return manifest_db
    
    def _is_backup_encrypted(self) -> bool:
        """Check if the backup is encrypted.
        
        Returns:
            True if backup is encrypted
        """
        try:
            manifest_plist = self.backup_path / "Manifest.plist"
            if not manifest_plist.exists():
                return False
            
            with open(manifest_plist, 'rb') as f:
                manifest = plistlib.load(f)
            
            return manifest.get('IsEncrypted', False)
        except Exception:
            return False
    
    def _decrypt_manifest_db(self) -> Optional[Path]:
        """Decrypt Manifest.db using the provided password.
        
        Uses iOSbackup library for proper iOS backup decryption.
        
        Returns:
            Path to decrypted temporary Manifest.db file, or None if decryption fails
        """
        if not self.password:
            self.logger.error("Password required for encrypted backup")
            return None
        
        if not HAS_IOSBACKUP:
            self.logger.error("iOSbackup library not installed. Run: pip install iOSbackup")
            return None
        
        try:
            # Use iOSbackup library to decrypt
            backup = iOSbackup(udid=self.backup_path.name, 
                             cleartextpassword=self.password,
                             backuproot=str(self.backup_path.parent))
            
            # Check if decryption worked by trying to access Manifest.db
            manifest_db_path = self.backup_path / "Manifest.db"
            
            if not manifest_db_path.exists():
                self.logger.error("Manifest.db not found after decryption")
                return None
            
            # The iOSbackup library decrypts in-place, so we can use the original path
            # But we need to test if it's actually readable
            try:
                conn = sqlite3.connect(str(manifest_db_path))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                cursor.fetchone()
                conn.close()
                
                self.logger.info("Successfully decrypted and verified Manifest.db")
                return manifest_db_path
                
            except sqlite3.DatabaseError as e:
                self.logger.error(f"Manifest.db still encrypted or corrupted: {e}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to decrypt backup: {e}")
            return None
    
    def __del__(self):
        """Clean up temporary decrypted files."""
        if self._decrypted_manifest_path and self._decrypted_manifest_path.exists():
            try:
                self._decrypted_manifest_path.unlink()
            except Exception:
                pass
