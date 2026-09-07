"""Group C: ordinary network state that must produce no alert above INFO.

Cases from ASSESSMENT.md §4.3 group C. The theme is that the network shapes
this detector used to flag at HIGH are the shapes produced by the privacy tools
its own users run — a local DNS proxy, iCloud Private Relay, a home router.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from privaseeai_security.monitors.carrier_detection import CarrierCompromiseDetector

from .conftest import assert_quiet, ifconfig_output, scutil_dns_output


@pytest.fixture
def detector():
    """A detector with a public-resolver baseline already established."""
    det = CarrierCompromiseDetector()
    det.dns_baseline = ["8.8.8.8", "8.8.4.4"]
    return det


def _dns_threats(detector, nameservers):
    with patch("subprocess.run") as run:
        run.return_value = Mock(stdout=scutil_dns_output(nameservers), returncode=0)
        return detector.analyze_dns_resolution()


def _interface_threats(detector, interfaces):
    with patch("subprocess.run") as run:
        run.return_value = Mock(stdout=ifconfig_output(interfaces), returncode=0)
        return detector.track_network_interfaces()


class TestBenignDNS:
    def test_c1_home_router_resolver(self, detector):
        # BENIGN-BECAUSE: 192.168.1.1 is the most common DNS server on earth.
        assert_quiet(_dns_threats(detector, ["192.168.1.1"]), context="C1")

    @pytest.mark.parametrize(
        "resolver",
        ["127.0.0.1", "::1"],
    )
    def test_c2_local_dns_proxy(self, detector, resolver):
        # BENIGN-BECAUSE: this is the standard deployment shape for NextDNS
        # CLI, AdGuard Home, dnscrypt-proxy, Pi-hole and DoH clients. Flagging
        # it at HIGH meant flagging the user's own privacy tooling.
        assert_quiet(_dns_threats(detector, [resolver]), context=f"C2 {resolver}")

    def test_c3_dns_changes_on_network_switch(self, detector):
        # BENIGN-BECAUSE: moving home -> office -> cellular changes resolvers
        # several times in a day. Baseline churn is not tampering.
        for resolvers in (
            ["192.168.1.1"],
            ["10.0.0.53"],
            ["8.8.8.8"],
            ["1.1.1.1"],
        ):
            assert_quiet(_dns_threats(detector, resolvers), context="C3")

    def test_c4_corporate_resolver(self, detector):
        # BENIGN-BECAUSE: an internal resolver on RFC1918 is how every managed
        # network resolves names.
        assert_quiet(_dns_threats(detector, ["10.0.0.53"]), context="C4")

    def test_c7_dns64_resolver_on_ipv6_only_carrier(self, detector):
        # BENIGN-BECAUSE: IPv6-only carriers (T-Mobile US among them) run
        # DNS64/NAT64. The well-known prefix is normal carrier infrastructure.
        assert_quiet(
            _dns_threats(detector, ["2001:4860:4860::6464", "64:ff9b::8.8.8.8"]),
            context="C7",
        )

    def test_public_resolvers_are_not_flagged(self, detector):
        # BENIGN-BECAUSE: switching to Cloudflare or Quad9 is a privacy
        # improvement, not an anomaly.
        assert_quiet(_dns_threats(detector, ["1.1.1.1", "9.9.9.9"]))


class TestBenignInterfaces:
    def test_c5_stock_macos_tunnel_interfaces(self, detector):
        # BENIGN-BECAUSE: macOS keeps utun0-utun3 up at idle for AWDL and
        # iCloud Private Relay. known_vpn_profiles is empty on a fresh process,
        # so the old threshold was an effective "> 2" that an untouched machine
        # already exceeds.
        assert_quiet(
            _interface_threats(detector, ["lo0", "en0", "utun0", "utun1", "utun2", "utun3"]),
            context="C5",
        )

    def test_c6_private_relay_plus_one_vpn(self, detector):
        # BENIGN-BECAUSE: iCloud Private Relay adds its own tunnels on top of
        # whatever VPN is running.
        detector.known_vpn_profiles.add("com.wireguard.ios.tunnel")
        assert_quiet(
            _interface_threats(
                detector,
                ["lo0", "en0", "utun0", "utun1", "utun2", "utun3", "utun4"],
            ),
            context="C6",
        )

    def test_no_tunnel_interfaces_at_all(self, detector):
        # BENIGN-BECAUSE: a machine with no VPN running is the simplest case.
        assert_quiet(_interface_threats(detector, ["lo0", "en0"]))
