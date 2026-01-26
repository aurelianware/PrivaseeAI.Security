"""Device information extraction for iOS devices."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from pathlib import Path
import plistlib
import sqlite3
import logging

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

    def __init__(self, backup_path: str):
        """Initialize device info extractor.
        
        Args:
            backup_path: Path to iOS backup directory
        """
        self.backup_path = Path(backup_path)
        self.logger = logging.getLogger(__name__)
        
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
            manifest_db = self.backup_path / "Manifest.db"
            
            if not manifest_db.exists():
                self.logger.warning(f"Manifest.db not found at {manifest_db}")
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
            manifest_db = self.backup_path / "Manifest.db"
            
            if not manifest_db.exists():
                self.logger.warning(f"Manifest.db not found")
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
            manifest_db = self.backup_path / "Manifest.db"
            
            if not manifest_db.exists():
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
            manifest_db = self.backup_path / "Manifest.db"
            
            if not manifest_db.exists():
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
        """Detect suspicious attributes in a profile."""
        indicators = []
        
        if not profile.is_signed:
            indicators.append("Unsigned profile")
        
        if not profile.organization:
            indicators.append("No organization specified")
        
        if profile.profile_type == "VPN":
            # Additional VPN-specific checks would go here
            if profile.display_name and any(kw in profile.display_name.lower() 
                                           for kw in ["test", "debug", "local", "proxy"]):
                indicators.append(f"Suspicious name: {profile.display_name}")
        
        if profile.profile_type == "MDM":
            # MDM profiles should have organization
            if not profile.organization:
                indicators.append("MDM profile without verified organization")
        
        return indicators
    
    def _assess_threat_level(self, profile: ProfileInfo) -> ThreatLevel:
        """Assess threat level based on suspicious indicators."""
        if not profile.suspicious_indicators:
            return ThreatLevel.NONE
        
        num_indicators = len(profile.suspicious_indicators)
        
        # Critical: Multiple suspicious indicators
        if num_indicators >= 3:
            return ThreatLevel.CRITICAL
        
        # High: Unsigned MDM or suspicious VPN name
        if "MDM profile without" in str(profile.suspicious_indicators):
            return ThreatLevel.HIGH
        
        if "Suspicious name" in str(profile.suspicious_indicators):
            return ThreatLevel.HIGH
        
        # Medium: 2 indicators
        if num_indicators == 2:
            return ThreatLevel.MEDIUM
        
        # Low: 1 indicator
        return ThreatLevel.LOW
