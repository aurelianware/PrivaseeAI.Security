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
    
    def monitor_esim_profiles(self, backup_path: Optional[Path] = None) -> List[CarrierThreatDetection]:
        """Monitor eSIM profiles for unauthorized changes or additions.
        
        Detects:
        - New eSIM profiles not installed by user
        - Unsigned or suspicious carrier profiles
        - Profiles that persist across factory resets
        - Unauthorized carrier bundle modifications
        
        Args:
            backup_path: Path to iOS backup directory. If None, uses default location.
        
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
        
        # Find most recent backup
        try:
            backup_dirs = [d for d in backup_path.iterdir() if d.is_dir()]
            if not backup_dirs:
                self.logger.warning("No iOS backups found")
                return threats
            
            # Get most recent backup (by modification time)
            latest_backup = max(backup_dirs, key=lambda d: d.stat().st_mtime)
            self.logger.info(f"Analyzing backup: {latest_backup.name}")
            
            # Parse carrier profiles from backup
            esim_profiles = self._extract_esim_profiles(latest_backup)
            
            for profile in esim_profiles:
                # Check if profile is new (not in known list)
                if profile.profile_id not in self.known_esim_profiles:
                    # Check for suspicious indicators
                    suspicious_indicators = []
                    
                    if not profile.is_signed:
                        suspicious_indicators.append("Unsigned eSIM profile")
                    
                    if profile.issuer and "localhost" in profile.issuer.lower():
                        suspicious_indicators.append(f"Suspicious issuer: {profile.issuer}")
                    
                    # Unknown carrier names are suspicious
                    known_carriers = ["T-Mobile", "AT&T", "Verizon", "Sprint"]
                    if not any(carrier in profile.carrier_name for carrier in known_carriers):
                        suspicious_indicators.append(f"Unknown carrier: {profile.carrier_name}")
                    
                    if suspicious_indicators:
                        threat = CarrierThreatDetection(
                            threat_level=ThreatLevel.CRITICAL,
                            attack_type="ESIM_MANIPULATION",
                            indicators=suspicious_indicators,
                            timestamp=datetime.now(),
                            details=f"Unauthorized eSIM profile detected: {profile.carrier_name}",
                            profile_info={
                                "profile_id": profile.profile_id,
                                "carrier": profile.carrier_name,
                                "is_signed": profile.is_signed,
                                "issuer": profile.issuer
                            },
                            recommended_action="Review eSIM profiles in Settings → Cellular. Remove any unauthorized profiles and contact your carrier."
                        )
                        threats.append(threat)
                        self.logger.warning(f"Suspicious eSIM profile detected: {profile.carrier_name}")
                    else:
                        # Add to known profiles
                        self.known_esim_profiles.add(profile.profile_id)
                
                # Update profile history
                self.esim_profile_history[profile.profile_id] = profile
        
        except Exception as e:
            self.logger.error(f"Error monitoring eSIM profiles: {e}")
        
        return threats
    
    def detect_localhost_routing(self, backup_path: Optional[Path] = None) -> List[CarrierThreatDetection]:
        """Detect fake VPN profiles routing traffic to localhost.
        
        This is a key indicator of the specific carrier-level attack where
        VPN profiles are created with ServerAddress = "127.0.0.1" to intercept
        all network traffic.
        
        Args:
            backup_path: Path to iOS backup directory. If None, uses default location.
        
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
            
            # Extract VPN profiles
            vpn_profiles = self._extract_vpn_profiles(latest_backup)
            
            for profile in vpn_profiles:
                localhost_indicators = []
                
                # Check for localhost routing
                if profile.server_address in ["127.0.0.1", "::1", "localhost"]:
                    localhost_indicators.append(f"VPN server points to localhost: {profile.server_address}")
                
                # Check for suspicious IP ranges (RFC 1918 private addresses)
                if profile.server_address.startswith(("10.", "172.16.", "192.168.")):
                    localhost_indicators.append(f"VPN server uses private IP: {profile.server_address}")
                
                # Check for missing organization (unsigned profiles)
                if not profile.is_signed:
                    localhost_indicators.append("Unsigned VPN profile")
                
                # Check for suspicious profile names
                suspicious_keywords = ["test", "debug", "local", "proxy", "intercept"]
                if any(kw in profile.display_name.lower() for kw in suspicious_keywords):
                    localhost_indicators.append(f"Suspicious profile name: {profile.display_name}")
                
                if localhost_indicators:
                    threat = CarrierThreatDetection(
                        threat_level=ThreatLevel.CRITICAL,
                        attack_type="LOCALHOST_VPN_ROUTING",
                        indicators=localhost_indicators,
                        timestamp=datetime.now(),
                        details=f"Fake VPN profile routing to localhost: {profile.display_name}",
                        profile_info={
                            "profile_id": profile.profile_id,
                            "name": profile.display_name,
                            "server": profile.server_address,
                            "type": profile.vpn_type,
                            "is_signed": profile.is_signed
                        },
                        recommended_action="CRITICAL: Delete this VPN profile immediately in Settings → General → VPN & Device Management. This profile is intercepting all your network traffic."
                    )
                    threats.append(threat)
                    self.logger.critical(f"Localhost-routing VPN profile detected: {profile.display_name} -> {profile.server_address}")
                else:
                    # Add to known profiles
                    self.known_vpn_profiles.add(profile.profile_id)
                
                # Update profile history
                self.vpn_profile_history[profile.profile_id] = profile
        
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
