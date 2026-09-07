"""Carrier Compromise Detector for identifying carrier-level attacks.

This module detects carrier-level attacks including:
- eSIM profile manipulation
- Localhost routing through fake VPN profiles
- DNS tampering
- Network interface anomalies

Platform: iOS focused but extensible to other platforms
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple
import subprocess
import plistlib
import re

from .. import allowlists
from ..config import Config
from ..logger import get_logger
from ..crypto.cert_validator import ThreatLevel


@dataclass
class CarrierThreatDetection:
    """A judgment about a carrier/profile signal.

    ``indicators`` stays a list of human-readable strings for backwards
    compatibility with existing callers and alert formatting.
    ``indicator_kinds`` carries the typed equivalent that scoring actually uses,
    so severity is never decided by substring-matching a stringified list.

    Every judgment carries a ``confidence`` and a non-empty ``alternatives``
    list naming the ordinary explanations for the same signal, matching the
    contract in ``monitors.vpn_integrity``.
    """

    threat_level: ThreatLevel
    attack_type: str
    indicators: List[str]
    timestamp: datetime
    details: Optional[str] = None
    profile_info: Optional[Dict] = None
    recommended_action: Optional[str] = None
    confidence: float = 1.0
    alternatives: List[str] = field(default_factory=list)
    indicator_kinds: List["IndicatorKind"] = field(default_factory=list)


@dataclass
class CarrierObservation:
    """A neutral fact read out of a backup. Carries no verdict."""

    kind: str
    summary: str
    severity: ThreatLevel = ThreatLevel.INFO
    profile_info: Optional[Dict] = None


@dataclass
class CarrierReport:
    """Observation/judgment split for a whole backup analysis."""

    observations: List[CarrierObservation] = field(default_factory=list)
    judgments: List[CarrierThreatDetection] = field(default_factory=list)

    def max_severity(self) -> ThreatLevel:
        """Highest judgment severity, or NONE when nothing was concluded."""
        best = ThreatLevel.NONE
        for judgment in self.judgments:
            if _SEVERITY_ORDER[judgment.threat_level] > _SEVERITY_ORDER[best]:
                best = judgment.threat_level
        return best


# ===========================================================================
# Scoring core: typed indicators, a policy table, and a corroboration gate.
#
# This mirrors the observation/judgment split in
# ``privaseeai_security.monitors.vpn_integrity`` (see ASSESSMENT.md §3.1):
#
# * An **observation** is a fact read out of a backup. It carries no verdict.
# * A **judgment** is a conclusion drawn from one or more indicators. Every
#   judgment carries a confidence in [0, 1] and a non-empty list of benign
#   ``alternatives`` -- the ordinary explanations for the same signal.
#
# Severity is derived from the policy table below and then passed through
# :func:`_grade`, never assembled ad hoc. In particular there is no
# ``"MDM" in str(indicators)`` style escalation any more: that matched a
# stringified Python list, so any indicator text containing "MDM" anywhere
# promoted the whole finding to CRITICAL, and it made every MDM-managed
# corporate iPhone permanently critical.
# ===========================================================================


class IndicatorKind(Enum):
    """Machine-readable signal kinds. Severity comes from _INDICATOR_POLICY."""

    # --- VPN profile routing ---
    LOOPBACK_SERVER = "LOOPBACK_SERVER"
    PRIVATE_IP_SERVER = "PRIVATE_IP_SERVER"
    NO_REMOTE_ENDPOINT = "NO_REMOTE_ENDPOINT"
    MDM_WITHOUT_ORGANIZATION = "MDM_WITHOUT_ORGANIZATION"
    UNSIGNED_VPN_PROFILE = "UNSIGNED_VPN_PROFILE"
    NOTEWORTHY_PROFILE_NAME = "NOTEWORTHY_PROFILE_NAME"

    # --- eSIM / carrier profiles ---
    UNSIGNED_ESIM_PROFILE = "UNSIGNED_ESIM_PROFILE"
    LOOPBACK_ISSUER = "LOOPBACK_ISSUER"
    NOTEWORTHY_ISSUER = "NOTEWORTHY_ISSUER"
    CARRIER_NAME_CHANGED = "CARRIER_NAME_CHANGED"
    SIGNATURE_STATUS_CHANGED = "SIGNATURE_STATUS_CHANGED"

    # --- network state ---
    TUNTAP_LOOPBACK_ROUTE = "TUNTAP_LOOPBACK_ROUTE"
    TUNTAP_COUNT_EXCESS = "TUNTAP_COUNT_EXCESS"
    LOOPBACK_DNS_SERVER = "LOOPBACK_DNS_SERVER"
    PRIVATE_DNS_SERVER = "PRIVATE_DNS_SERVER"
    INTERFACE_COUNT_EXCESS = "INTERFACE_COUNT_EXCESS"


@dataclass(frozen=True)
class IndicatorPolicy:
    """How one indicator kind is scored, and what else explains it."""

    severity: ThreatLevel
    confidence: float
    alternatives: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")
        if self.severity is not ThreatLevel.NONE and not self.alternatives:
            raise ValueError("every scored indicator must name benign alternatives")


@dataclass
class Indicator:
    """A single typed signal, with the human-readable text for the alert."""

    kind: IndicatorKind
    summary: str

    @property
    def policy(self) -> "IndicatorPolicy":
        return _INDICATOR_POLICY[self.kind]


#: Severity, confidence and benign explanations per indicator kind.
#:
#: Grades were set by working backwards from the negative-case contract in
#: ASSESSMENT.md §4.3, which is the authority on what must stay quiet. A signal
#: whose designed benign case (a corporate VPN on an RFC1918 gateway, a home
#: router resolver, a local DNS proxy, stock macOS tunnel interfaces, a carrier
#: rebrand, a profile whose name contains "test") has to produce no alert above
#: INFO is graded INFO here. Those signals are still recorded as observations
#: and still corroborate a judgment when something else co-occurs -- they just
#: cannot raise an alert on their own.
#:
#: Grades follow the rule-by-rule table in ASSESSMENT.md §3.2. The dominant
#: change from the pre-port module is that signals which are *routinely* true of
#: ordinary devices -- unsigned profiles, missing PayloadOrganization, RFC1918
#: VPN gateways, loopback DNS -- are INFO or LOW observations rather than HIGH
#: or CRITICAL findings.
_INDICATOR_POLICY: Dict[IndicatorKind, IndicatorPolicy] = {
    # The documented attack: a VPN profile whose server is the device itself.
    # Precisely matched against the address field, and the one rule in this
    # module that stands alone at full severity.
    IndicatorKind.LOOPBACK_SERVER: IndicatorPolicy(
        severity=ThreatLevel.CRITICAL,
        confidence=0.95,
        alternatives=(
            "A developer or QA profile deliberately pointing at the device",
            "A local debugging proxy the device owner installed themselves",
        ),
    ),
    IndicatorKind.PRIVATE_IP_SERVER: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.4,
        alternatives=(
            "A corporate VPN terminating on an RFC1918 gateway (very common)",
            "A home lab or self-hosted VPN on the local network",
            "Split-tunnel configuration reaching an internal subnet",
        ),
    ),
    IndicatorKind.NO_REMOTE_ENDPOINT: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.3,
        alternatives=(
            "A partially-written or truncated plist in the backup",
            "An on-demand profile that resolves its endpoint at connect time",
        ),
    ),
    IndicatorKind.MDM_WITHOUT_ORGANIZATION: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.3,
        alternatives=(
            "PayloadOrganization is optional in Apple's spec and routinely omitted",
            "An MDM profile pushed by an employer that did not set the field",
        ),
    ),
    IndicatorKind.UNSIGNED_VPN_PROFILE: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.3,
        alternatives=(
            "A VPN configuration added by hand (WireGuard, IKEv2) is unsigned",
            "PayloadCertificateUUID is absent from most user-created profiles",
        ),
    ),
    IndicatorKind.NOTEWORTHY_PROFILE_NAME: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.35,
        alternatives=(
            "A development, staging or QA profile named accordingly",
            "A legitimate corporate proxy configuration",
        ),
    ),
    IndicatorKind.UNSIGNED_ESIM_PROFILE: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.25,
        alternatives=(
            "The IsSigned key is absent from the plist entirely, which parses "
            "as False without meaning the profile is unsigned",
            "Carrier bundles do not always record signature state in the backup",
        ),
    ),
    IndicatorKind.LOOPBACK_ISSUER: IndicatorPolicy(
        severity=ThreatLevel.MEDIUM,
        confidence=0.6,
        alternatives=(
            "A lab or staging carrier bundle issued against a local CA",
            "A test profile left on the device after provisioning",
        ),
    ),
    IndicatorKind.NOTEWORTHY_ISSUER: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.35,
        alternatives=(
            "A carrier's own test or staging issuer name",
            "A pre-production bundle shipped by the operator",
        ),
    ),
    IndicatorKind.CARRIER_NAME_CHANGED: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.4,
        alternatives=(
            "A carrier rebrand (for example Sprint becoming T-Mobile)",
            "Roaming onto a partner network changes the displayed name",
            "An MVNO changing its host network",
        ),
    ),
    IndicatorKind.SIGNATURE_STATUS_CHANGED: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.35,
        alternatives=(
            "The IsSigned key being present in one backup and absent in another",
            "A carrier bundle update that records signature state differently",
        ),
    ),
    IndicatorKind.TUNTAP_LOOPBACK_ROUTE: IndicatorPolicy(
        severity=ThreatLevel.HIGH,
        confidence=0.8,
        alternatives=(
            "A local debugging proxy or packet capture tool installed by the user",
        ),
    ),
    IndicatorKind.TUNTAP_COUNT_EXCESS: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.4,
        alternatives=(
            "iCloud Private Relay adds its own tunnel interfaces",
            "AWDL and other Apple services hold utun interfaces open",
            "More than one VPN app installed, only one of them active",
        ),
    ),
    IndicatorKind.LOOPBACK_DNS_SERVER: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.4,
        alternatives=(
            "A local DNS proxy: NextDNS CLI, AdGuard Home, dnscrypt-proxy, Pi-hole",
            "A DNS-over-HTTPS client listening on loopback",
            "This is the standard deployment shape for the privacy tools this "
            "project's own users run",
        ),
    ),
    IndicatorKind.PRIVATE_DNS_SERVER: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.3,
        alternatives=(
            "A home router acting as resolver (192.168.1.1 is the most common "
            "DNS server in the world)",
            "A corporate internal resolver",
            "A captive portal or guest network resolver",
        ),
    ),
    IndicatorKind.INTERFACE_COUNT_EXCESS: IndicatorPolicy(
        severity=ThreatLevel.INFO,
        confidence=0.35,
        alternatives=(
            "Stock macOS keeps utun0-utun3 up at idle for AWDL and Private Relay",
            "The known-VPN-profile baseline is empty on a freshly started process",
        ),
    ),
}

#: Indicators strong enough to carry a finding on their own. Everything else is
#: capped by :func:`_grade` until something corroborates it.
_DECISIVE_KINDS = frozenset(
    {IndicatorKind.LOOPBACK_SERVER, IndicatorKind.TUNTAP_LOOPBACK_ROUTE}
)

_SEVERITY_ORDER: Dict[ThreatLevel, int] = {
    ThreatLevel.NONE: 0,
    ThreatLevel.INFO: 1,
    ThreatLevel.LOW: 2,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.HIGH: 4,
    ThreatLevel.CRITICAL: 5,
}


def _grade(indicators: Sequence[Indicator]) -> Tuple[ThreatLevel, float, List[str]]:
    """Combine indicators into a severity, a confidence and benign alternatives.

    The corroboration gate, which is the substance of this port:

    * A **decisive** indicator (a loopback VPN server, a loopback route on a
      tunnel interface) carries its full severity alone. These are the signals
      that have no routine benign cause.
    * Any other **single** indicator is capped at LOW. Unsigned profiles,
      missing organizations and RFC1918 gateways are ordinary; one of them is
      never a finding by itself.
    * Two or more non-decisive indicators are capped at MEDIUM. Corroboration
      raises confidence, but nothing reaches HIGH or CRITICAL without a
      decisive signal.

    Returns ``(severity, confidence, alternatives)``.
    """
    if not indicators:
        return ThreatLevel.NONE, 0.0, []

    policies = [ind.policy for ind in indicators]
    decisive = [ind for ind in indicators if ind.kind in _DECISIVE_KINDS]

    if decisive:
        severity = max(
            (ind.policy.severity for ind in decisive),
            key=lambda lvl: _SEVERITY_ORDER[lvl],
        )
        confidence = max(ind.policy.confidence for ind in decisive)
    else:
        base = max(
            (p.severity for p in policies), key=lambda lvl: _SEVERITY_ORDER[lvl]
        )
        strong = [
            p
            for p in policies
            if _SEVERITY_ORDER[p.severity] >= _SEVERITY_ORDER[ThreatLevel.MEDIUM]
        ]
        if len(strong) >= 2:
            # Two independent MEDIUM-or-higher signals corroborate each other
            # and may stand without a decisive indicator.
            cap = ThreatLevel.CRITICAL
        elif len(indicators) == 1:
            cap = ThreatLevel.LOW
        else:
            cap = ThreatLevel.MEDIUM
        severity = base if _SEVERITY_ORDER[base] <= _SEVERITY_ORDER[cap] else cap
        # Corroboration adds a little confidence but never manufactures it.
        confidence = min(1.0, max(p.confidence for p in policies) + 0.05 * (len(indicators) - 1))

    alternatives: List[str] = []
    for policy in policies:
        for alt in policy.alternatives:
            if alt not in alternatives:
                alternatives.append(alt)

    return severity, round(confidence, 2), alternatives


#: How many tunnel interfaces the operating system may hold open on its own,
#: before the count itself is worth noting. Stock macOS keeps utun0-utun3 up at
#: idle for AWDL and iCloud Private Relay, so the old allowance of 2 was below
#: the resting state of an untouched machine.
_SYSTEM_TUNNEL_ALLOWANCE = 4


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

        # Neutral facts that did not rise to a judgment. Kept so a caller can
        # see what was looked at without those facts being alerted on.
        self.observations: List[CarrierObservation] = []

        self.logger.info("CarrierCompromiseDetector initialized")

    def _judgment(
        self,
        indicators: Sequence[Indicator],
        attack_type: str,
        details: str,
        profile_info: Optional[Dict] = None,
        recommended_action: Optional[str] = None,
    ) -> Optional[CarrierThreatDetection]:
        """Turn typed indicators into a judgment, or into an observation.

        Returns ``None`` when the indicators do not add up to something worth
        alerting on. Two cases produce ``None``:

        * no indicators at all, and
        * a graded severity below LOW.

        The second is the substance of the re-grade. Signals that are routinely
        true of ordinary devices -- an unsigned hand-added VPN profile, an MDM
        payload with no PayloadOrganization, a carrier plist missing the
        IsSigned key -- are recorded as observations and do not reach the alert
        stream. They still contribute to a judgment when something else
        corroborates them.
        """
        if not indicators:
            return None

        severity, confidence, alternatives = _grade(indicators)

        if _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[ThreatLevel.LOW]:
            for indicator in indicators:
                self.observations.append(
                    CarrierObservation(
                        kind=indicator.kind.value,
                        summary=indicator.summary,
                        severity=ThreatLevel.INFO,
                        profile_info=profile_info,
                    )
                )
            self.logger.debug(
                "Observation only (%s): %s",
                attack_type,
                [ind.summary for ind in indicators],
            )
            return None

        # Contract check, mirroring vpn_integrity: a judgment without benign
        # alternatives is a judgment that has not been thought through.
        if not alternatives:
            raise AssertionError(
                f"judgment {attack_type} produced no benign alternatives"
            )

        return CarrierThreatDetection(
            threat_level=severity,
            attack_type=attack_type,
            indicators=[ind.summary for ind in indicators],
            timestamp=datetime.now(),
            details=details,
            profile_info=profile_info,
            recommended_action=recommended_action,
            confidence=confidence,
            alternatives=alternatives,
            indicator_kinds=[ind.kind for ind in indicators],
        )
    
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
                # Allowlisted profiles are not scored at all.
                if allowlists.is_allowlisted_profile(profile.profile_id):
                    self.known_esim_profiles.add(profile.profile_id)
                    self.esim_profile_history[profile.profile_id] = profile
                    continue

                indicators: List[Indicator] = []

                # Signature state. INFO, not CRITICAL: _extract_esim_profiles
                # reads data.get("IsSigned", False), so a plist that simply
                # lacks the key -- the common shape -- parses as unsigned.
                if not profile.is_signed:
                    indicators.append(
                        Indicator(
                            IndicatorKind.UNSIGNED_ESIM_PROFILE,
                            "eSIM profile is not marked signed",
                        )
                    )

                # Issuer. Loopback in an issuer is a real oddity; "test" or
                # "debug" is a weak hint. Token-matched, so "Latest" is not a
                # hit. Loopback is matched against issuer tokens because an
                # issuer is a name, not an address field.
                if profile.issuer:
                    issuer_tokens = allowlists.tokenize(profile.issuer)
                    if issuer_tokens & {"localhost", "127", "0", "1"} and (
                        "localhost" in issuer_tokens
                        or "127.0.0.1" in profile.issuer
                    ):
                        indicators.append(
                            Indicator(
                                IndicatorKind.LOOPBACK_ISSUER,
                                f"Issuer references loopback: {profile.issuer}",
                            )
                        )
                    elif allowlists.contains_keyword_token(
                        profile.issuer, allowlists.NOTEWORTHY_ISSUER_TOKENS
                    ):
                        indicators.append(
                            Indicator(
                                IndicatorKind.NOTEWORTHY_ISSUER,
                                f"Non-production issuer name: {profile.issuer}",
                            )
                        )

                # Rules deleted in this port (ASSESSMENT.md §3.2):
                #   #20 "unknown carrier" -- the 14-entry carrier list flagged
                #       every MVNO and every non-US/UK/CA operator on earth.
                #   #21 "persists across backups" -- a working SIM appears in
                #       every backup; persistence is the normal state.
                # Cross-backup presence is now recorded as an observation only.

                # Differential signals against previously seen state.
                if profile.profile_id in self.esim_profile_history:
                    old_profile = self.esim_profile_history[profile.profile_id]
                    if old_profile.carrier_name != profile.carrier_name:
                        indicators.append(
                            Indicator(
                                IndicatorKind.CARRIER_NAME_CHANGED,
                                f"Carrier name changed: {old_profile.carrier_name} "
                                f"\u2192 {profile.carrier_name}",
                            )
                        )
                    if old_profile.is_signed != profile.is_signed:
                        indicators.append(
                            Indicator(
                                IndicatorKind.SIGNATURE_STATUS_CHANGED,
                                "Signature status changed between backups",
                            )
                        )

                judgment = self._judgment(
                    indicators,
                    attack_type="ESIM_MANIPULATION",
                    details=(
                        f"eSIM profile: {profile.carrier_name} "
                        f"(ID: {profile.profile_id[:8]}...)"
                    ),
                    profile_info={
                        "profile_id": profile.profile_id,
                        "carrier": profile.carrier_name,
                        "is_signed": profile.is_signed,
                        "issuer": profile.issuer,
                        "install_date": profile.install_date.isoformat()
                        if profile.install_date
                        else None,
                        "is_active": profile.is_active,
                        "seen_in_earlier_backup": profile.profile_id
                        in persistent_profiles,
                    },
                    recommended_action=(
                        "Review eSIM profiles in Settings \u2192 Cellular. Corroborate "
                        "before acting: most of these signals have ordinary causes."
                    ),
                )
                if judgment is not None:
                    threats.append(judgment)
                    self.logger.info(
                        "eSIM judgment %s (%s) for %s",
                        judgment.threat_level.value,
                        judgment.confidence,
                        profile.carrier_name,
                    )
                else:
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
                is_mdm = profile in mdm_profiles

                # Allowlisted profiles are not scored at all.
                if allowlists.is_allowlisted_profile(profile.profile_id):
                    self.known_vpn_profiles.add(profile.profile_id)
                    self.vpn_profile_history[profile.profile_id] = profile
                    continue

                indicators: List[Indicator] = []
                known_org = allowlists.is_known_organization(profile.organization)

                # The documented attack: the tunnel terminates on the device.
                # Matched against the whole address field, so a hostname such as
                # vpn.localhost-example.com is not a hit. This is the one rule
                # here that stands alone at CRITICAL.
                if allowlists.is_loopback_address(profile.server_address):
                    indicators.append(
                        Indicator(
                            IndicatorKind.LOOPBACK_SERVER,
                            f"VPN server points to loopback: {profile.server_address}",
                        )
                    )
                # RFC1918 gateway. LOW: this is what a corporate VPN looks like.
                elif self._is_private_ip(profile.server_address):
                    indicators.append(
                        Indicator(
                            IndicatorKind.PRIVATE_IP_SERVER,
                            f"VPN server uses private IP: {profile.server_address}",
                        )
                    )

                # Missing endpoint. INFO: usually a truncated plist rather than
                # an attack. This must cover the literal "unknown" that
                # _extract_vpn_profiles substitutes when a plist carries no
                # RemoteAddress or ServerAddress key -- the common shape for a
                # profile with no endpoint -- and the unspecified addresses
                # 0.0.0.0 and ::, which are placeholders, not destinations.
                elif allowlists.is_unspecified_address(profile.server_address):
                    indicators.append(
                        Indicator(
                            IndicatorKind.NO_REMOTE_ENDPOINT,
                            "VPN profile records no remote endpoint "
                            f"({profile.server_address or 'absent'})",
                        )
                    )

                # MDM without an organization. INFO: PayloadOrganization is
                # optional in Apple's spec. The old code escalated this to
                # CRITICAL via `"MDM" in str(indicators)`, which made every
                # MDM-managed corporate iPhone permanently critical.
                if is_mdm and not profile.organization and not known_org:
                    indicators.append(
                        Indicator(
                            IndicatorKind.MDM_WITHOUT_ORGANIZATION,
                            "MDM VPN profile with no organization recorded",
                        )
                    )

                # Unsigned. INFO: every hand-added WireGuard or IKEv2 profile
                # lacks PayloadCertificateUUID.
                if not profile.is_signed and not known_org:
                    indicators.append(
                        Indicator(
                            IndicatorKind.UNSIGNED_VPN_PROFILE,
                            "Unsigned VPN profile",
                        )
                    )

                # Name keywords, token-matched. "local" is gone from the set
                # entirely; "Latest" and "Local Office Wi-Fi" no longer hit.
                name_hits = allowlists.contains_keyword_token(
                    profile.display_name or "", allowlists.NOTEWORTHY_NAME_TOKENS
                )
                if name_hits:
                    indicators.append(
                        Indicator(
                            IndicatorKind.NOTEWORTHY_PROFILE_NAME,
                            f"Noteworthy profile name ({', '.join(sorted(name_hits))}): "
                            f"{profile.display_name}",
                        )
                    )

                # Rule deleted in this port (ASSESSMENT.md §3.2 #30): profiles
                # installed between 23:00 and 06:00 were flagged as "installed
                # at suspicious time". That fires on any late-night install, on
                # timezone-shifted timestamps and on travel, and encodes no
                # threat model -- attackers are not constrained to office hours.

                judgment = self._judgment(
                    indicators,
                    attack_type="LOCALHOST_VPN_ROUTING",
                    details=(
                        f"{'MDM-installed' if is_mdm else 'User'} VPN profile: "
                        f"{profile.display_name}"
                    ),
                    profile_info={
                        "profile_id": profile.profile_id,
                        "name": profile.display_name,
                        "server": profile.server_address,
                        "type": profile.vpn_type,
                        "is_signed": profile.is_signed,
                        "organization": profile.organization,
                        "install_date": profile.install_date.isoformat()
                        if profile.install_date
                        else None,
                        "is_mdm": is_mdm,
                    },
                    recommended_action=(
                        "Review this profile in Settings \u2192 General \u2192 VPN & Device "
                        "Management. A loopback server address is worth acting on "
                        "immediately; the other signals here are weak on their own "
                        "and have ordinary explanations."
                    ),
                )
                if judgment is not None:
                    threats.append(judgment)
                    log = (
                        self.logger.critical
                        if judgment.threat_level == ThreatLevel.CRITICAL
                        else self.logger.info
                    )
                    log(
                        "VPN judgment %s (confidence %s): %s -> %s",
                        judgment.threat_level.value,
                        judgment.confidence,
                        profile.display_name,
                        profile.server_address,
                    )
                else:
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
                    indicators: List[Indicator] = []

                    for server in sorted(unexpected_servers):
                        # Loopback resolver. LOW, not HIGH: this is the standard
                        # deployment shape for NextDNS CLI, AdGuard Home,
                        # dnscrypt-proxy, Pi-hole and DoH clients -- the very
                        # privacy tools this project's users run.
                        if allowlists.is_loopback_address(server):
                            indicators.append(
                                Indicator(
                                    IndicatorKind.LOOPBACK_DNS_SERVER,
                                    f"Loopback DNS server: {server}",
                                )
                            )
                        # RFC1918 resolver. LOW: 192.168.1.1 is the most common
                        # DNS server in the world.
                        elif self._is_private_ip(server):
                            indicators.append(
                                Indicator(
                                    IndicatorKind.PRIVATE_DNS_SERVER,
                                    f"Private IP DNS server: {server}",
                                )
                            )

                    judgment = self._judgment(
                        indicators,
                        attack_type="DNS_TAMPERING",
                        details=(
                            "DNS servers changed from baseline: "
                            f"{', '.join(sorted(unexpected_servers))}"
                        ),
                        profile_info={
                            "current_dns": dns_servers,
                            "baseline_dns": self.dns_baseline,
                            "unexpected": sorted(unexpected_servers),
                        },
                        recommended_action=(
                            "Check DNS settings. If you run a local DNS proxy or "
                            "are on a home or corporate network, this is expected."
                        ),
                    )
                    if judgment is not None:
                        threats.append(judgment)
                        self.logger.info(
                            "DNS judgment %s (confidence %s): %s",
                            judgment.threat_level.value,
                            judgment.confidence,
                            sorted(unexpected_servers),
                        )
        
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
                    indicators: List[Indicator] = []

                    # Stock macOS keeps utun0-utun3 up at idle for AWDL and
                    # iCloud Private Relay, and known_vpn_profiles is empty on a
                    # freshly started process -- which made the old threshold an
                    # effective "> 2" that an idle Mac already exceeds. The
                    # allowance is raised and the finding graded LOW.
                    allowance = max(len(self.known_vpn_profiles), 0) + _SYSTEM_TUNNEL_ALLOWANCE
                    if len(tun_tap_interfaces) > allowance:
                        indicators.append(
                            Indicator(
                                IndicatorKind.INTERFACE_COUNT_EXCESS,
                                f"{len(tun_tap_interfaces)} tunnel interfaces present "
                                f"({', '.join(tun_tap_interfaces)}), above the "
                                f"allowance of {allowance}",
                            )
                        )

                    self.logger.debug("Active TUN/TAP interfaces: %s", tun_tap_interfaces)

                    judgment = self._judgment(
                        indicators,
                        attack_type="INTERFACE_ANOMALY",
                        details=(
                            "Tunnel interface count above allowance: "
                            f"{', '.join(tun_tap_interfaces)}"
                        ),
                        profile_info={"interfaces": tun_tap_interfaces},
                        recommended_action=(
                            "Verify each tunnel interface belongs to a VPN app you "
                            "installed. Private Relay and AWDL hold interfaces open."
                        ),
                    )
                    if judgment is not None:
                        threats.append(judgment)
        
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
                                                    dest = str(route.get("Destination", "")).strip()
                                                    # Loopback route: exact address, or
                                                    # anything inside 127.0.0.0/8.
                                                    if allowlists.is_loopback_address(dest) or dest.startswith("127."):
                                                        suspicious_configs.append(
                                                            f"Interface {iface_name} has localhost route: {dest}"
                                                        )
                
                except Exception as e:
                    self.logger.debug(f"Could not parse network file {plist_file}: {e}")
            
            # Tunnel-interface count. LOW, and with a larger allowance: Private
            # Relay and AWDL routinely hold interfaces open beyond the VPN
            # profiles present in a backup.
            if tun_tap_count > expected_vpn_count + _SYSTEM_TUNNEL_ALLOWANCE:
                count_judgment = self._judgment(
                    [
                        Indicator(
                            IndicatorKind.TUNTAP_COUNT_EXCESS,
                            f"{tun_tap_count} tunnel interfaces configured against "
                            f"{expected_vpn_count} VPN profiles",
                        )
                    ],
                    attack_type="TUN_TAP_ANOMALY",
                    details=(
                        f"Found {tun_tap_count} tunnel interfaces and "
                        f"{expected_vpn_count} VPN profiles"
                    ),
                    recommended_action=(
                        "Review VPN profiles and network settings. Private Relay "
                        "and AWDL account for extra interfaces on their own."
                    ),
                )
                if count_judgment is not None:
                    threats.append(count_judgment)

            # A loopback route on a tunnel interface stays a strong signal: it
            # is one of the two decisive indicators in this module.
            if suspicious_configs:
                route_judgment = self._judgment(
                    [
                        Indicator(IndicatorKind.TUNTAP_LOOPBACK_ROUTE, cfg)
                        for cfg in suspicious_configs
                    ],
                    attack_type="TUN_TAP_LOCALHOST_ROUTING",
                    details="Tunnel interfaces configured with a loopback route",
                    recommended_action=(
                        "Network interfaces are routing traffic to the device "
                        "itself. Unless you installed a local debugging proxy, "
                        "treat this as interception."
                    ),
                )
                if route_judgment is not None:
                    threats.append(route_judgment)
        
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
