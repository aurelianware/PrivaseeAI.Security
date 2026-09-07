"""Group B: ordinary iOS backups that must produce no alert above INFO.

These are the cases from ASSESSMENT.md §4.3 group B. Each fixture carries a
BENIGN-BECAUSE note naming the real-world behaviour it stands for, because a
fixture nobody can justify is one that gets "fixed" later by loosening the
assertion rather than by fixing the rule.

B16 is the inverse: it must FIRE. It exists so that quieting the detector
cannot be mistaken for disabling it.
"""

from __future__ import annotations

import pytest

from privaseeai_security.crypto.cert_validator import ThreatLevel
from privaseeai_security.monitors.carrier_detection import CarrierCompromiseDetector

from .conftest import (
    assert_quiet,
    write_carrier_profile,
    write_mdm_vpn_profile,
    write_vpn_profile,
)


@pytest.fixture
def detector():
    return CarrierCompromiseDetector()


class TestBenignCarrierProfiles:
    """eSIM / carrier bundles that are entirely ordinary."""

    def test_b1_signed_major_carrier(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: the baseline. A signed T-Mobile eSIM on a US iPhone.
        write_carrier_profile(
            device_backup,
            "tmobile",
            ProfileID="8901260000000000001",
            CarrierName="T-Mobile",
            IsActive=True,
            IsSigned=True,
            Issuer="T-Mobile USA CA",
        )
        assert_quiet(detector.monitor_esim_profiles(backup_path=backup_root), context="B1")

    @pytest.mark.parametrize(
        "carrier",
        ["Mint Mobile", "Visible", "Cricket Wireless", "Google Fi", "Boost Mobile"],
    )
    def test_b2_mvno_carriers(self, detector, backup_root, device_backup, carrier):
        # BENIGN-BECAUSE: MVNOs are ordinary carriers. The deleted rule #20
        # matched against a 14-entry list, so every one of these was "Unknown
        # carrier" at HIGH.
        write_carrier_profile(
            device_backup,
            "mvno",
            ProfileID="8901260000000000002",
            CarrierName=carrier,
            IsActive=True,
            IsSigned=True,
        )
        assert_quiet(
            detector.monitor_esim_profiles(backup_path=backup_root),
            context=f"B2 {carrier}",
        )

    @pytest.mark.parametrize("carrier", ["Telstra", "SoftBank", "Orange Polska", "Jio"])
    def test_b3_non_us_carriers(self, detector, backup_root, device_backup, carrier):
        # BENIGN-BECAUSE: the deleted carrier list covered US/UK/CA only, so
        # every operator in the rest of the world was flagged.
        write_carrier_profile(
            device_backup,
            "intl",
            ProfileID="8901260000000000003",
            CarrierName=carrier,
            IsActive=True,
            IsSigned=True,
        )
        assert_quiet(
            detector.monitor_esim_profiles(backup_path=backup_root),
            context=f"B3 {carrier}",
        )

    def test_b4_profile_present_in_every_backup(self, detector, backup_root):
        # BENIGN-BECAUSE: a working SIM appears in every backup by definition.
        # Deleted rule #21 called that "rootkit behaviour" at CRITICAL.
        for index in range(4):
            backup = backup_root / f"device-snapshot-{index}"
            backup.mkdir()
            write_carrier_profile(
                backup,
                "persistent",
                ProfileID="8901260000000000004",
                CarrierName="Vodafone",
                IsActive=True,
                IsSigned=True,
            )
        assert_quiet(
            detector.monitor_esim_profiles(backup_path=backup_root, compare_across_backups=True),
            context="B4",
        )

    def test_b5_plist_without_is_signed_key(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: the parser reads data.get("IsSigned", False), so a
        # bundle that simply does not record signature state parses as
        # unsigned. This is the common real shape, not an unsigned profile.
        write_carrier_profile(
            device_backup,
            "nokey",
            ProfileID="8901260000000000005",
            CarrierName="AT&T",
            IsActive=True,
        )
        assert_quiet(detector.monitor_esim_profiles(backup_path=backup_root), context="B5")

    def test_b15_carrier_rebrand_across_backups(self, detector, backup_root):
        # BENIGN-BECAUSE: carriers rebrand (Sprint became T-Mobile) and roaming
        # changes the displayed name. A changed name is not tampering.
        first = backup_root / "snapshot-1"
        first.mkdir()
        write_carrier_profile(
            first,
            "rebrand",
            ProfileID="8901260000000000015",
            CarrierName="Sprint",
            IsActive=True,
            IsSigned=True,
        )
        assert_quiet(detector.monitor_esim_profiles(backup_path=backup_root))

        second = backup_root / "snapshot-2"
        second.mkdir()
        write_carrier_profile(
            second,
            "rebrand",
            ProfileID="8901260000000000015",
            CarrierName="T-Mobile",
            IsActive=True,
            IsSigned=True,
        )
        assert_quiet(detector.monitor_esim_profiles(backup_path=backup_root), context="B15")


class TestBenignVPNProfiles:
    """VPN and MDM payloads that any managed or privacy-conscious device has."""

    def test_b6_corporate_mdm_without_organization(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: PayloadOrganization is optional in Apple's spec and is
        # routinely omitted. The old code escalated this to CRITICAL through
        # `"MDM" in str(indicators)`, making every corporate iPhone critical.
        write_mdm_vpn_profile(
            device_backup,
            "corp",
            PayloadIdentifier="com.contoso.vpn",
            PayloadDisplayName="Contoso VPN",
            RemoteAddress="vpn.contoso.com",
            VPNType="IKEv2",
            PayloadCertificateUUID="B7A1-4C2E",
        )
        assert_quiet(detector.detect_localhost_routing(backup_path=backup_root), context="B6")

    def test_b7_corporate_vpn_on_private_gateway(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: an RFC1918 gateway is what a corporate VPN looks like.
        # The original code's own comment conceded this while still flagging it.
        write_vpn_profile(
            device_backup,
            "corp",
            PayloadIdentifier="com.contoso.vpn.internal",
            PayloadDisplayName="Contoso Internal",
            ServerAddress="10.4.12.9",
            VPNType="IKEv2",
            PayloadCertificateUUID="C3D4-9911",
            PayloadOrganization="Contoso Ltd",
        )
        assert_quiet(detector.detect_localhost_routing(backup_path=backup_root), context="B7")

    @pytest.mark.parametrize(
        "display_name",
        [
            "Contoso Test Network",  # B8  - contains the token "test"
            "Local Office Wi-Fi",  # B9  - "local" is no longer a keyword
            "Corp Proxy Config",  # B10 - contains the token "proxy"
            "Latest Config",  # substring "test" inside "Latest"
            "Contest Network",  # substring "test" inside "Contest"
            "TestFlight Beta VPN",  # substring "test" inside "TestFlight"
            "Localisation Profile",  # substring "local" inside "Localisation"
        ],
    )
    def test_b8_b10_noteworthy_names_alone(
        self, detector, backup_root, device_backup, display_name
    ):
        # BENIGN-BECAUSE: a name is not evidence. Development, staging and
        # corporate profiles legitimately carry these words, and the first four
        # of these were false positives of *substring* matching specifically.
        write_vpn_profile(
            device_backup,
            "named",
            PayloadIdentifier="com.contoso.vpn.named",
            PayloadDisplayName=display_name,
            ServerAddress="vpn.contoso.com",
            VPNType="IKEv2",
            PayloadCertificateUUID="AA11-BB22",
            PayloadOrganization="Contoso Ltd",
        )
        assert_quiet(
            detector.detect_localhost_routing(backup_path=backup_root),
            context=f"B8/B10 {display_name!r}",
        )

    def test_b12_hand_added_wireguard(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: the ordinary case. A VPN config added by hand is
        # unsigned and carries no organization; it is not an attack.
        write_vpn_profile(
            device_backup,
            "wireguard",
            PayloadIdentifier="com.wireguard.ios.tunnel",
            PayloadDisplayName="Home",
            ServerAddress="vpn.example.net",
            VPNType="WireGuard",
        )
        assert_quiet(detector.detect_localhost_routing(backup_path=backup_root), context="B12")

    def test_b13_protonvpn_profile(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: the previous four-entry org allowlist held only Apple
        # and NextDNS, so every real VPN vendor was an "unknown organization".
        write_vpn_profile(
            device_backup,
            "proton",
            PayloadIdentifier="ch.protonvpn.ios",
            PayloadDisplayName="ProtonVPN",
            ServerAddress="node-ch-01.protonvpn.net",
            VPNType="IKEv2",
            PayloadOrganization="Proton AG",
        )
        assert_quiet(detector.detect_localhost_routing(backup_path=backup_root), context="B13")

    def test_b14_apple_system_configuration_profile(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: Apple's own configuration payloads are system files.
        write_vpn_profile(
            device_backup,
            "system",
            PayloadIdentifier="Library/ConfigurationProfiles/com.apple.vpn",
            PayloadDisplayName="System Configuration",
            ServerAddress="",
            VPNType="Unknown",
        )
        assert_quiet(detector.detect_localhost_routing(backup_path=backup_root), context="B14")

    def test_stacked_benign_signals_stay_quiet(self, detector, backup_root, device_backup):
        # BENIGN-BECAUSE: a realistic dev machine trips several weak signals at
        # once -- unsigned, no organization, RFC1918 gateway, a "test" token.
        # Corroboration between individually-innocuous signals must not
        # manufacture a finding.
        write_vpn_profile(
            device_backup,
            "stack",
            PayloadIdentifier="com.example.dev.vpn",
            PayloadDisplayName="Staging Test VPN",
            ServerAddress="192.168.50.4",
            VPNType="IKEv2",
        )
        assert_quiet(
            detector.detect_localhost_routing(backup_path=backup_root),
            context="stacked benign signals",
        )


class TestTheDetectorStillFires:
    """B16 and friends: quieting the detector must not have disabled it."""

    def test_b16_work_vpn_pointing_at_loopback_fires(self, detector, backup_root, device_backup):
        # This is the inverse test. The profile is named innocuously, so a
        # detector keying on the *name* would miss it -- which is exactly the
        # bug still open in device_info._has_localhost_server. carrier_detection
        # keys on the server address, so it must fire at CRITICAL.
        write_vpn_profile(
            device_backup,
            "loopback",
            PayloadIdentifier="com.example.workvpn",
            PayloadDisplayName="Work VPN",
            RemoteAddress="127.0.0.1",
            VPNType="IKEv2",
            PayloadOrganization="Contoso Ltd",
            PayloadCertificateUUID="DEAD-BEEF",
        )
        threats = detector.detect_localhost_routing(backup_path=backup_root)

        assert threats, "a VPN terminating on the device must be detected"
        threat = threats[0]
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.attack_type == "LOCALHOST_VPN_ROUTING"
        assert "127.0.0.1" in str(threat.indicators)

    def test_every_judgment_carries_confidence_and_alternatives(
        self, detector, backup_root, device_backup
    ):
        """The contract the reference standard establishes."""
        write_vpn_profile(
            device_backup,
            "loopback",
            PayloadIdentifier="com.example.workvpn",
            PayloadDisplayName="Work VPN",
            RemoteAddress="127.0.0.1",
            VPNType="IKEv2",
        )
        for threat in detector.detect_localhost_routing(backup_path=backup_root):
            assert 0.0 < threat.confidence <= 1.0
            assert threat.alternatives, "a judgment must name benign explanations"
            assert threat.indicator_kinds
