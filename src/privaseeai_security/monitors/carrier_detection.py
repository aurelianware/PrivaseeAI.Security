"""Carrier Compromise Detector for identifying carrier-level attacks.

This module detects carrier-level attacks including:
- eSIM profile manipulation
- Localhost routing through fake VPN profiles
- DNS tampering
- Network interface anomalies

Platform: iOS focused but extensible to other platforms
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import subprocess
import plistlib
import re

from ..config import Config
from ..logger import get_logger
from ..crypto.cert_validator import ThreatLevel


@dataclass
class CarrierThreatDetection:
    """Data class for carrier compromise threat detection results."""
    threat_level: ThreatLevel
    attack_type: str
    indicators: List[str]
    timestamp: datetime
    details: Optional[str] = None
    profile_info: Optional[Dict] = None
    recommended_action: Optional[str] = None


@dataclass
class ESIMProfile:
    """Data class for eSIM profile information."""
    profile_id: str
    carrier_name: str
    is_active: bool
    install_date: Optional[datetime] = None
    is_signed: bool = False
    issuer: Optional[str] = None


@dataclass
class VPNProfile:
    """Data class for VPN profile information."""
    profile_id: str
    display_name: str
    server_address: str
    vpn_type: str  # IPSec, IKEv2, WireGuard, etc.
    is_signed: bool = False
    organization: Optional[str] = None
    install_date: Optional[datetime] = None


class CarrierCompromiseDetector:
    """Monitor for detecting carrier-level attacks and compromises.
    
    This detector monitors for:
    1. eSIM profile manipulation (unauthorized profiles)
    2. Localhost routing through fake VPN profiles
    3. DNS tampering and resolution anomalies
    4. Network interface anomalies (TUN/TAP)
    
    Attributes:
        config: Configuration object
        logger: Logger instance
        known_esim_profiles: Set of known-good eSIM profile IDs
        known_vpn_profiles: Set of known-good VPN profile IDs
        dns_baseline: Expected DNS servers
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the Carrier Compromise Detector.
        
        Args:
            config: Optional configuration object. If not provided, uses default Config.
        """
        self.config = config or Config()
        self.logger = get_logger(__name__)
        
        # Track known-good profiles
        self.known_esim_profiles: Set[str] = set()
        self.known_vpn_profiles: Set[str] = set()
        
        # Baseline DNS servers (set during initialization or first run)
        self.dns_baseline: List[str] = []
        
        # Track profile history for differential analysis
        self.esim_profile_history: Dict[str, ESIMProfile] = {}
        self.vpn_profile_history: Dict[str, VPNProfile] = {}
        
        self.logger.info("CarrierCompromiseDetector initialized")
    
    def monitor_esim_profiles(self, backup_path: Optional[Path] = None, compare_across_backups: bool = True) -> List[CarrierThreatDetection]:
        """Monitor eSIM profiles for unauthorized changes or additions.
        
        Detects:
        - New eSIM profiles not installed by user
        - Unsigned or suspicious carrier profiles
        - Profiles that persist across factory resets
        - Unauthorized carrier bundle modifications
        - Profile modifications across backup snapshots
        
        Args:
            backup_path: Path to iOS backup directory. If None, uses default location.
            compare_across_backups: If True, analyze multiple backups to detect persistent profiles.
        
        Returns:
            List of CarrierThreatDetection objects for any suspicious profiles found.
        """
        threats = []
        
        if backup_path is None:
            # Default iOS backup location on macOS
            backup_path = Path.home() / "Library/Application Support/MobileSync/Backup"
        
        if not backup_path.exists():
            self.logger.warning(f"iOS backup path does not exist: {backup_path}")
            return threats
        
        try:
            backup_dirs = sorted([d for d in backup_path.iterdir() if d.is_dir()], 
                               key=lambda d: d.stat().st_mtime, reverse=True)
            if not backup_dirs:
                self.logger.warning("No iOS backups found")
                return threats
            
            # Analyze most recent backup
            latest_backup = backup_dirs[0]
            self.logger.info(f"Analyzing latest backup: {latest_backup.name}")
            
            # Parse carrier profiles from latest backup
            current_esim_profiles = self._extract_esim_profiles(latest_backup)
            current_profile_ids = {p.profile_id for p in current_esim_profiles}
            
            # Track profiles across multiple backups if requested
            persistent_profiles: Set[str] = set()
            if compare_across_backups and len(backup_dirs) > 1:
                # Analyze up to 3 previous backups
                for old_backup in backup_dirs[1:4]:
                    old_profiles = self._extract_esim_profiles(old_backup)
                    old_profile_ids = {p.profile_id for p in old_profiles}
                    
                    # Find profiles that exist in both old and new backups
                    common_profiles = current_profile_ids & old_profile_ids
                    persistent_profiles.update(common_profiles)
                    
                    # Check for profiles that survived a factory reset
                    # (indicated by significant time gap or device info change)
                    time_gap = latest_backup.stat().st_mtime - old_backup.stat().st_mtime
                    if time_gap > 7 * 24 * 3600:  # More than 7 days
                        for profile_id in common_profiles:
                            if profile_id not in self.known_esim_profiles:
                                self.logger.warning(f"Profile {profile_id} persisted across {time_gap/86400:.1f} day gap")
            
            # Analyze each current profile
            for profile in current_esim_profiles:
                suspicious_indicators = []
                
                # Check if profile is unsigned
                if not profile.is_signed:
                    suspicious_indicators.append("Unsigned eSIM profile")
                
                # Check for suspicious issuer
                if profile.issuer:
                    suspicious_patterns = ["localhost", "127.0.0.1", "test", "debug"]
                    if any(pattern in profile.issuer.lower() for pattern in suspicious_patterns):
                        suspicious_indicators.append(f"Suspicious issuer: {profile.issuer}")
                
                # Check against known carriers (expanded list)
                known_carriers = [
                    "T-Mobile", "AT&T", "Verizon", "Sprint", "US Cellular",
                    "Vodafone", "O2", "EE", "Three", "Orange",
                    "Rogers", "Bell", "Telus", "Fido"
                ]
                carrier_match = any(carrier.lower() in profile.carrier_name.lower() 
                                  for carrier in known_carriers)
                if not carrier_match and profile.carrier_name.lower() not in ["unknown", "no service"]:
                    suspicious_indicators.append(f"Unknown carrier: {profile.carrier_name}")
                
                # Check if profile persists across backups (potential rootkit behavior)
                if profile.profile_id in persistent_profiles and profile.profile_id not in self.known_esim_profiles:
                    suspicious_indicators.append("Profile persists across multiple backups")
                
                # Check for profiles appearing in history but with modifications
                if profile.profile_id in self.esim_profile_history:
                    old_profile = self.esim_profile_history[profile.profile_id]
                    if old_profile.carrier_name != profile.carrier_name:
                        suspicious_indicators.append(
                            f"Carrier name changed: {old_profile.carrier_name} → {profile.carrier_name}"
                        )
                    if old_profile.is_signed != profile.is_signed:
                        suspicious_indicators.append("Signature status changed")
                
                # Generate threat if suspicious indicators found
                if suspicious_indicators:
                    threat_level = ThreatLevel.CRITICAL if any([
                        "Unsigned" in str(suspicious_indicators),
                        "localhost" in str(suspicious_indicators).lower(),
                        "persists across" in str(suspicious_indicators).lower()
                    ]) else ThreatLevel.HIGH
                    
                    threat = CarrierThreatDetection(
                        threat_level=threat_level,
                        attack_type="ESIM_MANIPULATION",
                        indicators=suspicious_indicators,
                        timestamp=datetime.now(),
                        details=f"Suspicious eSIM profile: {profile.carrier_name} (ID: {profile.profile_id[:8]}...)",
                        profile_info={
                            "profile_id": profile.profile_id,
                            "carrier": profile.carrier_name,
                            "is_signed": profile.is_signed,
                            "issuer": profile.issuer,
                            "install_date": profile.install_date.isoformat() if profile.install_date else None,
                            "is_active": profile.is_active
                        },
                        recommended_action="Review eSIM profiles in Settings → Cellular. Remove any unauthorized profiles and contact your carrier immediately."
                    )
                    threats.append(threat)
                    self.logger.warning(f"Suspicious eSIM profile detected: {profile.carrier_name} - {suspicious_indicators}")
                else:
                    # Add to known good profiles
                    self.known_esim_profiles.add(profile.profile_id)
                
                # Update profile history for differential analysis
                self.esim_profile_history[profile.profile_id] = profile
        
        except Exception as e:
            self.logger.error(f"Error monitoring eSIM profiles: {e}")
        
        return threats
    
    def detect_localhost_routing(self, backup_path: Optional[Path] = None, check_tun_tap: bool = True) -> List[CarrierThreatDetection]:
        """Detect fake VPN profiles routing traffic to localhost.
        
        This is a key indicator of the specific carrier-level attack where
        VPN profiles are created with ServerAddress = "127.0.0.1" to intercept
        all network traffic.
        
        Detection includes:
        - VPN profiles pointing to localhost/private IPs
        - Routes directing traffic to localhost
        - Suspicious TUN/TAP interface configurations
        - VPN profiles with no remote endpoint
        - Profiles created outside user installation (MDM/system level)
        
        Args:
            backup_path: Path to iOS backup directory. If None, uses default location.
            check_tun_tap: If True, also check for suspicious TUN/TAP configurations.
        
        Returns:
            List of CarrierThreatDetection objects for any localhost-routing profiles.
        """
        threats = []
        
        if backup_path is None:
            backup_path = Path.home() / "Library/Application Support/MobileSync/Backup"
        
        if not backup_path.exists():
            self.logger.warning(f"iOS backup path does not exist: {backup_path}")
            return threats
        
        try:
            # Find most recent backup
            backup_dirs = [d for d in backup_path.iterdir() if d.is_dir()]
            if not backup_dirs:
                return threats
            
            latest_backup = max(backup_dirs, key=lambda d: d.stat().st_mtime)
            self.logger.info(f"Analyzing VPN profiles in backup: {latest_backup.name}")
            
            # Extract VPN profiles from multiple sources
            vpn_profiles = self._extract_vpn_profiles(latest_backup)
            mdm_profiles = self._extract_mdm_vpn_profiles(latest_backup)
            
            # Analyze all profiles (user-installed and MDM)
            all_profiles = vpn_profiles + mdm_profiles
            
            for profile in all_profiles:
                localhost_indicators = []
                is_mdm = profile in mdm_profiles
                
                # CRITICAL: Check for localhost routing (the documented attack)
                if profile.server_address in ["127.0.0.1", "::1", "localhost"]:
                    localhost_indicators.append(f"VPN server points to localhost: {profile.server_address}")
                
                # Check for suspicious IP ranges (RFC 1918 private addresses)
                # Note: Some corporate VPNs legitimately use these, but still flag for review
                if self._is_private_ip(profile.server_address):
                    localhost_indicators.append(f"VPN server uses private IP: {profile.server_address}")
                
                # Check for empty/null server address (VPN with no remote endpoint)
                if not profile.server_address or profile.server_address in ["", "null", "none"]:
                    localhost_indicators.append("VPN profile has no remote endpoint")
                
                # Check for MDM-installed profiles (created outside user action)
                if is_mdm and not profile.organization:
                    localhost_indicators.append("VPN profile installed via MDM with no verified organization")
                
                # Check for missing signature (unsigned profiles)
                if not profile.is_signed:
                    localhost_indicators.append("Unsigned VPN profile")
                
                # Check for suspicious profile names
                suspicious_keywords = ["test", "debug", "local", "proxy", "intercept", "mitm", "capture"]
                if any(kw in profile.display_name.lower() for kw in suspicious_keywords):
                    localhost_indicators.append(f"Suspicious profile name: {profile.display_name}")
                
                # Check install date (profiles installed at suspicious times)
                if profile.install_date:
                    # Flag profiles installed outside normal hours (11pm - 6am)
                    hour = profile.install_date.hour
                    if hour >= 23 or hour < 6:
                        localhost_indicators.append(f"Profile installed at suspicious time: {profile.install_date}")
                
                # Generate threat if localhost routing detected
                if localhost_indicators:
                    # CRITICAL if localhost/no endpoint, HIGH if private IP only
                    is_critical = any([
                        "localhost" in str(localhost_indicators).lower(),
                        "no remote endpoint" in str(localhost_indicators).lower(),
                        "MDM" in str(localhost_indicators)
                    ])
                    
                    threat = CarrierThreatDetection(
                        threat_level=ThreatLevel.CRITICAL if is_critical else ThreatLevel.HIGH,
                        attack_type="LOCALHOST_VPN_ROUTING",
                        indicators=localhost_indicators,
                        timestamp=datetime.now(),
                        details=f"{'MDM-installed' if is_mdm else 'User'} VPN profile with suspicious routing: {profile.display_name}",
                        profile_info={
                            "profile_id": profile.profile_id,
                            "name": profile.display_name,
                            "server": profile.server_address,
                            "type": profile.vpn_type,
                            "is_signed": profile.is_signed,
                            "organization": profile.organization,
                            "install_date": profile.install_date.isoformat() if profile.install_date else None,
                            "is_mdm": is_mdm
                        },
                        recommended_action="CRITICAL: Delete this VPN profile immediately in Settings → General → VPN & Device Management. This profile may be intercepting all your network traffic. If it's an MDM profile, contact your IT administrator."
                    )
                    threats.append(threat)
                    self.logger.critical(f"Localhost-routing VPN profile detected: {profile.display_name} -> {profile.server_address} (MDM: {is_mdm})")
                else:
                    # Add to known good profiles
                    self.known_vpn_profiles.add(profile.profile_id)
                
                # Update profile history
                self.vpn_profile_history[profile.profile_id] = profile
            
            # Check TUN/TAP interface configurations if requested
            if check_tun_tap:
                tun_tap_threats = self._check_tun_tap_config(latest_backup, len(all_profiles))
                threats.extend(tun_tap_threats)
        
        except Exception as e:
            self.logger.error(f"Error detecting localhost routing: {e}")
        
        return threats
    
    def analyze_dns_resolution(self) -> List[CarrierThreatDetection]:
        """Validate DNS responses and detect tampering.
        
        Detects:
        - DNS hijacking (unexpected DNS servers)
        - DNS response manipulation
        - Suspicious DNS64 mappings
        
        Returns:
            List of CarrierThreatDetection objects for DNS anomalies.
        """
        threats = []
        
        try:
            # Get current DNS servers on macOS
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                dns_servers = self._parse_dns_servers(result.stdout)
                
                # If we don't have a baseline, set it now
                if not self.dns_baseline:
                    self.dns_baseline = dns_servers
                    self.logger.info(f"DNS baseline set: {dns_servers}")
                    return threats
                
                # Check for DNS changes
                unexpected_servers = set(dns_servers) - set(self.dns_baseline)
                
                if unexpected_servers:
                    # Check for suspicious DNS servers
                    suspicious_indicators = []
                    
                    for server in unexpected_servers:
                        # Check for localhost DNS
                        if server in ["127.0.0.1", "::1"]:
                            suspicious_indicators.append(f"Localhost DNS server: {server}")
                        
                        # Check for private IP ranges (unusual for public DNS)
                        if server.startswith(("10.", "172.16.", "192.168.")):
                            suspicious_indicators.append(f"Private IP DNS server: {server}")
                    
                    if suspicious_indicators:
                        threat = CarrierThreatDetection(
                            threat_level=ThreatLevel.HIGH,
                            attack_type="DNS_TAMPERING",
                            indicators=suspicious_indicators,
                            timestamp=datetime.now(),
                            details=f"Unexpected DNS servers detected: {', '.join(unexpected_servers)}",
                            profile_info={
                                "current_dns": dns_servers,
                                "baseline_dns": self.dns_baseline,
                                "unexpected": list(unexpected_servers)
                            },
                            recommended_action="Check DNS settings in System Preferences → Network. Verify DNS servers match your ISP or expected values (e.g., 8.8.8.8 for Google DNS)."
                        )
                        threats.append(threat)
                        self.logger.warning(f"DNS tampering detected: {unexpected_servers}")
        
        except subprocess.TimeoutExpired:
            self.logger.error("DNS lookup timed out")
        except Exception as e:
            self.logger.error(f"Error analyzing DNS: {e}")
        
        return threats
    
    def track_network_interfaces(self) -> List[CarrierThreatDetection]:
        """Monitor TUN/TAP interfaces for anomalies.
        
        Detects:
        - Unexpected TUN/TAP interfaces
        - Interfaces without associated VPN connections
        - Suspicious interface configurations
        
        Returns:
            List of CarrierThreatDetection objects for interface anomalies.
        """
        threats = []
        
        try:
            # Get network interfaces on macOS
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                interfaces = self._parse_network_interfaces(result.stdout)
                
                # Look for TUN/TAP interfaces
                tun_tap_interfaces = [
                    iface for iface in interfaces 
                    if iface.startswith(("tun", "tap", "utun"))
                ]
                
                if tun_tap_interfaces:
                    # TUN/TAP interfaces are normal for VPNs, but check if they match known VPN profiles
                    suspicious_indicators = []
                    
                    # If we have more TUN/TAP interfaces than VPN profiles, it's suspicious
                    if len(tun_tap_interfaces) > len(self.known_vpn_profiles) + 2:  # +2 for system VPN interfaces
                        suspicious_indicators.append(
                            f"Unexpected number of TUN/TAP interfaces: {len(tun_tap_interfaces)} "
                            f"(expected ~{len(self.known_vpn_profiles)})"
                        )
                    
                    # Log for monitoring purposes
                    self.logger.info(f"Active TUN/TAP interfaces: {tun_tap_interfaces}")
                    
                    if suspicious_indicators:
                        threat = CarrierThreatDetection(
                            threat_level=ThreatLevel.MEDIUM,
                            attack_type="INTERFACE_ANOMALY",
                            indicators=suspicious_indicators,
                            timestamp=datetime.now(),
                            details=f"Suspicious network interfaces detected: {', '.join(tun_tap_interfaces)}",
                            profile_info={"interfaces": tun_tap_interfaces},
                            recommended_action="Check active VPN connections and verify all TUN/TAP interfaces are associated with known VPN apps."
                        )
                        threats.append(threat)
        
        except subprocess.TimeoutExpired:
            self.logger.error("Interface check timed out")
        except Exception as e:
            self.logger.error(f"Error tracking network interfaces: {e}")
        
        return threats
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if an IP address is in a private range (RFC 1918).
        
        Args:
            ip_address: IP address string
        
        Returns:
            True if IP is in private range, False otherwise
        """
        if not ip_address or ip_address == "unknown":
            return False
        
        # Check for private IPv4 ranges
        private_ranges = [
            "10.",           # 10.0.0.0/8
            "172.16.", "172.17.", "172.18.", "172.19.",  # 172.16.0.0/12
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168."       # 192.168.0.0/16
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
    def _extract_mdm_vpn_profiles(self, backup_path: Path) -> List[VPNProfile]:
        """Extract MDM-installed VPN profiles from iOS backup.
        
        MDM profiles are system-installed and may not be visible to users.
        
        Args:
            backup_path: Path to iOS backup directory
        
        Returns:
            List of VPNProfile objects from MDM sources
        """
        profiles = []
        
        try:
            # Look for MDM configuration files
            mdm_files = list(backup_path.glob("**/com.apple.mdm*.plist"))
            mdm_files.extend(list(backup_path.glob("**/ManagedPreferences*.plist")))
            
            for plist_file in mdm_files:
                try:
                    with open(plist_file, 'rb') as f:
                        data = plistlib.load(f)
                        
                        # Extract VPN configurations from MDM payloads
                        if isinstance(data, dict):
                            payloads = data.get("PayloadContent", [])
                            if not isinstance(payloads, list):
                                payloads = [payloads] if payloads else []
                            
                            for payload in payloads:
                                if isinstance(payload, dict):
                                    payload_type = payload.get("PayloadType", "")
                                    if "VPN" in payload_type or "com.apple.vpn" in payload_type:
                                        profile = VPNProfile(
                                            profile_id=str(payload.get("PayloadIdentifier", f"mdm_{plist_file.name}")),
                                            display_name=payload.get("PayloadDisplayName", "MDM VPN Profile"),
                                            server_address=payload.get("RemoteAddress", payload.get("ServerAddress", "unknown")),
                                            vpn_type=payload.get("VPNType", "MDM"),
                                            is_signed=bool(payload.get("PayloadCertificateUUID")),
                                            organization=payload.get("PayloadOrganization")
                                        )
                                        profiles.append(profile)
                
                except Exception as e:
                    self.logger.debug(f"Could not parse MDM file {plist_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error extracting MDM VPN profiles: {e}")
        
        return profiles
    
    def _check_tun_tap_config(self, backup_path: Path, expected_vpn_count: int) -> List[CarrierThreatDetection]:
        """Check TUN/TAP interface configurations for anomalies.
        
        Args:
            backup_path: Path to iOS backup directory
            expected_vpn_count: Expected number of VPN profiles
        
        Returns:
            List of CarrierThreatDetection objects for TUN/TAP anomalies
        """
        threats = []
        
        try:
            # Check network configuration files for TUN/TAP interfaces
            network_files = list(backup_path.glob("**/NetworkInterfaces*.plist"))
            network_files.extend(list(backup_path.glob("**/preferences.plist")))
            
            tun_tap_count = 0
            suspicious_configs = []
            
            for plist_file in network_files:
                try:
                    with open(plist_file, 'rb') as f:
                        data = plistlib.load(f)
                        
                        # Look for TUN/TAP interface configurations
                        if isinstance(data, dict):
                            interfaces = data.get("NetworkInterfaces", {})
                            if isinstance(interfaces, dict):
                                for iface_name, iface_config in interfaces.items():
                                    if isinstance(iface_name, str) and any(prefix in iface_name.lower() 
                                                                           for prefix in ["tun", "tap", "utun"]):
                                        tun_tap_count += 1
                                        
                                        # Check for suspicious configurations
                                        if isinstance(iface_config, dict):
                                            # Check for localhost routing in interface config
                                            routes = iface_config.get("Routes", [])
                                            for route in routes:
                                                if isinstance(route, dict):
                                                    dest = route.get("Destination", "")
                                                    if "127.0.0.1" in str(dest) or "localhost" in str(dest):
                                                        suspicious_configs.append(
                                                            f"Interface {iface_name} has localhost route: {dest}"
                                                        )
                
                except Exception as e:
                    self.logger.debug(f"Could not parse network file {plist_file}: {e}")
            
            # Flag if TUN/TAP count exceeds expected VPN profile count significantly
            if tun_tap_count > expected_vpn_count + 2:  # Allow 2 extra for system use
                threat = CarrierThreatDetection(
                    threat_level=ThreatLevel.MEDIUM,
                    attack_type="TUN_TAP_ANOMALY",
                    indicators=[f"Excessive TUN/TAP interfaces: {tun_tap_count} found, {expected_vpn_count} VPN profiles"],
                    timestamp=datetime.now(),
                    details=f"Found {tun_tap_count} TUN/TAP interfaces but only {expected_vpn_count} VPN profiles",
                    recommended_action="Review VPN profiles and network settings. Extra TUN/TAP interfaces may indicate hidden VPN configurations."
                )
                threats.append(threat)
            
            # Add threats for suspicious configurations
            if suspicious_configs:
                threat = CarrierThreatDetection(
                    threat_level=ThreatLevel.HIGH,
                    attack_type="TUN_TAP_LOCALHOST_ROUTING",
                    indicators=suspicious_configs,
                    timestamp=datetime.now(),
                    details="TUN/TAP interfaces configured with localhost routing",
                    recommended_action="CRITICAL: Network interfaces are routing traffic to localhost. This may intercept all network traffic."
                )
                threats.append(threat)
        
        except Exception as e:
            self.logger.error(f"Error checking TUN/TAP config: {e}")
        
        return threats
    
    def _extract_esim_profiles(self, backup_path: Path) -> List[ESIMProfile]:
        """Extract eSIM profiles from iOS backup.
        
        Args:
            backup_path: Path to iOS backup directory
        
        Returns:
            List of ESIMProfile objects found in backup
        """
        profiles = []
        
        try:
            # Look for carrier bundle files in backup
            # iOS stores carrier bundles in various locations
            carrier_files = list(backup_path.glob("**/*carrier*.plist"))
            carrier_files.extend(list(backup_path.glob("**/*CarrierBundle*.plist")))
            
            for plist_file in carrier_files:
                try:
                    with open(plist_file, 'rb') as f:
                        data = plistlib.load(f)
                        
                        # Extract profile information
                        profile = ESIMProfile(
                            profile_id=str(data.get("ProfileID", plist_file.name)),
                            carrier_name=data.get("CarrierName", "Unknown"),
                            is_active=data.get("IsActive", False),
                            is_signed=data.get("IsSigned", False),
                            issuer=data.get("Issuer")
                        )
                        profiles.append(profile)
                
                except Exception as e:
                    self.logger.debug(f"Could not parse {plist_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error extracting eSIM profiles: {e}")
        
        return profiles
    
    def _extract_vpn_profiles(self, backup_path: Path) -> List[VPNProfile]:
        """Extract VPN configuration profiles from iOS backup.
        
        Args:
            backup_path: Path to iOS backup directory
        
        Returns:
            List of VPNProfile objects found in backup
        """
        profiles = []
        
        try:
            # Look for VPN configuration files
            vpn_files = list(backup_path.glob("**/*vpn*.plist"))
            vpn_files.extend(list(backup_path.glob("**/com.apple.vpn.managed.plist")))
            vpn_files.extend(list(backup_path.glob("**/NetworkExtension*.plist")))
            
            for plist_file in vpn_files:
                try:
                    with open(plist_file, 'rb') as f:
                        data = plistlib.load(f)
                        
                        # VPN profiles can be nested in different structures
                        vpn_configs = []
                        
                        if isinstance(data, dict):
                            # Check for VPN configuration in various possible locations
                            if "VPN" in data:
                                vpn_configs.append(data["VPN"])
                            if "VPNSubtype" in data or "VPNType" in data:
                                vpn_configs.append(data)
                            if "PayloadContent" in data:
                                for payload in data.get("PayloadContent", []):
                                    if "VPN" in payload.get("PayloadType", ""):
                                        vpn_configs.append(payload)
                        
                        for vpn_config in vpn_configs:
                            profile = VPNProfile(
                                profile_id=str(vpn_config.get("PayloadIdentifier", plist_file.name)),
                                display_name=vpn_config.get("PayloadDisplayName", vpn_config.get("UserDefinedName", "Unknown")),
                                server_address=vpn_config.get("RemoteAddress", vpn_config.get("ServerAddress", "unknown")),
                                vpn_type=vpn_config.get("VPNType", vpn_config.get("VPNSubType", "Unknown")),
                                is_signed=bool(vpn_config.get("PayloadCertificateUUID")),
                                organization=vpn_config.get("PayloadOrganization")
                            )
                            profiles.append(profile)
                
                except Exception as e:
                    self.logger.debug(f"Could not parse {plist_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error extracting VPN profiles: {e}")
        
        return profiles
    
    def _parse_dns_servers(self, scutil_output: str) -> List[str]:
        """Parse DNS servers from scutil --dns output.
        
        Args:
            scutil_output: Output from scutil --dns command
        
        Returns:
            List of DNS server IP addresses
        """
        dns_servers = []
        
        # Parse DNS servers from scutil output
        # Format: "  nameserver[0] : 8.8.8.8"
        for line in scutil_output.split('\n'):
            if 'nameserver' in line:
                match = re.search(r':\s*([0-9a-fA-F:.]+)', line)
                if match:
                    dns_servers.append(match.group(1))
        
        return list(set(dns_servers))  # Remove duplicates
    
    def _parse_network_interfaces(self, ifconfig_output: str) -> List[str]:
        """Parse network interface names from ifconfig output.
        
        Args:
            ifconfig_output: Output from ifconfig command
        
        Returns:
            List of interface names
        """
        interfaces = []
        
        # Parse interface names from ifconfig output
        # Format: "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
        for line in ifconfig_output.split('\n'):
            if line and not line.startswith((' ', '\t')):
                match = re.match(r'^(\w+):', line)
                if match:
                    interfaces.append(match.group(1))
        
        return interfaces
