"""Tests for the shared allowlists and, in particular, token matching.

Substring matching on profile names was a significant false-positive source:
"Latest" matched the keyword "test", "Local Office Wi-Fi" matched "local", and
every corporate proxy config looked like an interception attempt. These tests
pin the token-based replacement.
"""

import pytest

from privaseeai_security import allowlists


class TestTokenize:
    def test_splits_on_non_alphanumerics(self):
        assert allowlists.tokenize("Contoso Test-Network") == {
            "contoso",
            "test",
            "network",
        }

    def test_is_case_insensitive(self):
        assert allowlists.tokenize("MITM Proxy") == {"mitm", "proxy"}

    def test_empty_input(self):
        assert allowlists.tokenize("") == set()


class TestContainsKeywordToken:
    """The cases that made the old substring check unusable."""

    @pytest.mark.parametrize(
        "name",
        [
            "Latest Backup",  # contains "test"
            "Contest Winner",  # contains "test"
            "Local Office Wi-Fi",  # contains "local"
            "Localisation Profile",
            "TestFlight",  # one token, not "test"
        ],
    )
    def test_benign_names_do_not_match(self, name):
        assert allowlists.contains_keyword_token(name, allowlists.NOTEWORTHY_NAME_TOKENS) == set()

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("Contoso Test Network", {"test"}),
            ("MITM Proxy", {"mitm", "proxy"}),
            ("debug-tunnel", {"debug"}),
            ("Traffic Capture VPN", {"capture"}),
        ],
    )
    def test_real_hits_still_match(self, name, expected):
        assert (
            allowlists.contains_keyword_token(name, allowlists.NOTEWORTHY_NAME_TOKENS) == expected
        )

    def test_local_is_not_a_keyword_at_all(self):
        """'local' was dropped: it flags locales and local networks."""
        assert "local" not in allowlists.NOTEWORTHY_NAME_TOKENS


class TestLoopbackMatching:
    @pytest.mark.parametrize("addr", ["127.0.0.1", "::1", "localhost"])
    def test_loopback_addresses_match(self, addr):
        assert allowlists.is_loopback_address(addr) is True

    @pytest.mark.parametrize("addr", ["0.0.0.0", "::"])
    def test_unspecified_addresses_are_not_loopback(self, addr):
        """0.0.0.0 means "bind all interfaces", not "the device itself".

        It reached the loopback set by being moved verbatim out of device_info,
        where it was only substring-matched against profile names. Against a
        real address field it is decisive, so treating it as loopback escalated
        a placeholder endpoint to CRITICAL.
        """
        assert allowlists.is_loopback_address(addr) is False
        assert allowlists.is_unspecified_address(addr) is True

    @pytest.mark.parametrize(
        "addr",
        [
            "vpn.example.com",
            "10.0.0.1",
            "vpn.localhost-example.com",  # substring, not the address
            "127.0.0.1.example.net",
            "",
            None,
        ],
    )
    def test_non_loopback_addresses_do_not_match(self, addr):
        assert allowlists.is_loopback_address(addr) is False

    def test_whitespace_is_tolerated(self):
        assert allowlists.is_loopback_address("  127.0.0.1 ") is True


class TestUnspecifiedAddresses:
    @pytest.mark.parametrize(
        "addr", ["0.0.0.0", "::", "unknown", "null", "none", "", None, "  UNKNOWN "]
    )
    def test_recognised_as_no_endpoint(self, addr):
        assert allowlists.is_unspecified_address(addr) is True

    @pytest.mark.parametrize("addr", ["vpn.example.com", "10.0.0.1", "127.0.0.1"])
    def test_real_addresses_are_specified(self, addr):
        assert allowlists.is_unspecified_address(addr) is False

    def test_unknown_is_the_parsers_own_default(self):
        """_extract_vpn_profiles substitutes "unknown" for a missing key.

        Without this the NO_REMOTE_ENDPOINT observation was silently dropped
        for the commonest shape of an endpointless profile.
        """
        assert "unknown" in allowlists.UNSPECIFIED_SERVER_ADDRESSES


class TestOrganizationAllowlist:
    @pytest.mark.parametrize("org", ["Apple Inc.", "Proton AG", "Mullvad VPN AB", "Tailscale Inc."])
    def test_known_orgs(self, org):
        assert allowlists.is_known_organization(org) is True

    def test_unknown_org(self):
        assert allowlists.is_known_organization("Some Unknown Corp") is False

    def test_missing_org(self):
        assert allowlists.is_known_organization(None) is False

    def test_common_vpn_vendors_are_present(self):
        """The old four-entry list made every real VPN an 'unknown org'."""
        for vendor in ("Proton AG", "Mullvad", "Tailscale", "Cloudflare"):
            assert allowlists.is_known_organization(vendor), vendor


class TestProfileAllowlisting:
    def test_apple_system_path(self):
        assert allowlists.is_apple_system_path("Library/ConfigurationProfiles/foo.plist")

    def test_known_service(self):
        assert allowlists.is_known_service("io.nextdns.profile")

    def test_unrelated_profile_is_not_allowlisted(self):
        assert allowlists.is_allowlisted_profile("com.example.vpn") is False

    def test_empty_profile_id(self):
        assert allowlists.is_allowlisted_profile("") is False
