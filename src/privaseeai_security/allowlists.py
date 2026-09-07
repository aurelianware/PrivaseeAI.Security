"""Shared allowlists and matching helpers for profile analysis.

Both :mod:`privaseeai_security.device_info` and
:mod:`privaseeai_security.monitors.carrier_detection` parse VPN, MDM and carrier
profiles out of the same iOS backups. They used to carry separate (and unequal)
notions of "this is fine": ``device_info`` had allowlists and an early return,
``carrier_detection`` had none, which is a large part of why the latter graded
ordinary corporate and MVNO profiles as CRITICAL.

This module holds the single shared definition so the two agree.

Matching policy
---------------
Keyword matching here is **token-based, not substring**. Substring matching on
profile display names is what made ``Latest`` match "test", ``Local Office
Wi-Fi`` match "local", and every corporate ``Proxy`` config look like an
interception attempt. :func:`contains_keyword_token` splits on non-alphanumerics
and compares whole tokens instead.
"""

from __future__ import annotations

import re
from typing import Iterable, Set

# ---------------------------------------------------------------------------
# Path / identifier allowlists
# ---------------------------------------------------------------------------

#: Backup-relative paths Apple itself owns. Profiles under these are system
#: configuration, not user- or attacker-installed payloads.
APPLE_SYSTEM_PATHS: Set[str] = {
    "Library/ConfigurationProfiles/",
    "Library/UserConfigurationProfiles/",
    "Library/Managed Preferences/",
    "SystemConfiguration/",
}

#: Payload identifiers for services that are legitimate even when unsigned or
#: carrying no organization.
KNOWN_LEGITIMATE_SERVICES: Set[str] = {
    "io.nextdns",  # NextDNS DNS privacy service
    "com.apple.managedconfiguration",  # Apple system configuration
}

#: Organizations that are not, by themselves, a reason for suspicion.
#:
#: This list was four entries (Apple and NextDNS), which meant ProtonVPN,
#: Mullvad, Tailscale and every corporate VPN counted as an "unknown
#: organization" -- and, combined with unsigned-by-default, graded CRITICAL.
#: It is still not exhaustive and is not meant to be: absence from this set is
#: an INFO-level observation, never a finding on its own.
KNOWN_LEGITIMATE_ORGS: Set[str] = {
    "Apple Inc.",
    "Apple",
    "NextDNS Inc",
    "NextDNS",
    "Proton AG",
    "ProtonVPN",
    "Proton Technologies AG",
    "Mullvad VPN AB",
    "Mullvad",
    "Tailscale Inc.",
    "Tailscale",
    "Cloudflare, Inc.",
    "Cloudflare",
    "WireGuard",
}

#: Server addresses that mean "this profile terminates on the device itself".
#: Unlike the keyword lists below, these are matched against the *server address
#: field*, and a match here is a genuine finding rather than a hint -- in
#: carrier_detection it is the decisive CRITICAL indicator.
#:
#: 0.0.0.0 is deliberately NOT here. It means "unspecified / bind all
#: interfaces", not "loopback". It reached this set by being moved verbatim out
#: of device_info, where it was only ever substring-matched against profile
#: *names* and so was harmless; against a real address field, in a decisive
#: role, it escalated a placeholder endpoint to CRITICAL. It belongs with the
#: unspecified addresses below.
LOOPBACK_SERVER_ADDRESSES: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
}

#: Addresses that mean "no endpoint was recorded" rather than any destination.
#: "unknown" is included because that is the literal default
#: ``_extract_vpn_profiles`` substitutes when a plist carries no RemoteAddress
#: or ServerAddress key at all.
UNSPECIFIED_SERVER_ADDRESSES: Set[str] = {
    "0.0.0.0",
    "::",
    "unknown",
    "null",
    "none",
    "",
}

# ---------------------------------------------------------------------------
# Keyword sets (token-matched, see contains_keyword_token)
# ---------------------------------------------------------------------------

#: Tokens in a profile *name* that are worth noting. A hit is a weak signal --
#: development, staging and corporate profiles legitimately contain these words
#: -- so carrier_detection grades it INFO: an observation that can corroborate
#: another signal, never a finding on its own. A name is not evidence.
NOTEWORTHY_NAME_TOKENS: Set[str] = {
    "test",
    "debug",
    "proxy",
    "intercept",
    "mitm",
    "capture",
}

#: Tokens in a certificate *issuer* that suggest a non-production issuer.
NOTEWORTHY_ISSUER_TOKENS: Set[str] = {
    "test",
    "debug",
    "staging",
}

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def tokenize(value: str) -> Set[str]:
    """Split *value* into lower-case alphanumeric tokens.

    ``"Contoso Test-Network"`` -> ``{"contoso", "test", "network"}``.
    """
    if not value:
        return set()
    return {tok for tok in _TOKEN_SPLIT_RE.split(value.lower()) if tok}


def contains_keyword_token(value: str, keywords: Iterable[str]) -> Set[str]:
    """Return the keywords that appear as whole tokens in *value*.

    This is the substring-matching fix. ``"Latest Backup"`` does not match
    ``test``; ``"Local Office Wi-Fi"`` does not match ``local``; but
    ``"MITM Proxy"`` still matches both ``mitm`` and ``proxy``.
    """
    tokens = tokenize(value)
    return {kw for kw in keywords if kw.lower() in tokens}


def is_apple_system_path(profile_id: str) -> bool:
    """True if *profile_id* lives under a path Apple owns."""
    if not profile_id:
        return False
    return any(path in profile_id for path in APPLE_SYSTEM_PATHS)


def is_known_service(profile_id: str) -> bool:
    """True if *profile_id* belongs to a known-legitimate service."""
    if not profile_id:
        return False
    return any(service in profile_id for service in KNOWN_LEGITIMATE_SERVICES)


def is_known_organization(organization: str | None) -> bool:
    """True if *organization* is on the known-legitimate list."""
    if not organization:
        return False
    return organization.strip() in KNOWN_LEGITIMATE_ORGS


def is_allowlisted_profile(profile_id: str) -> bool:
    """True if the profile should be skipped entirely before scoring."""
    return is_apple_system_path(profile_id) or is_known_service(profile_id)


def is_loopback_address(address: str | None) -> bool:
    """True if *address* points back at the device.

    Compared against the whole, stripped address -- never a substring of a
    longer string -- so a hostname such as ``vpn.localhost-example.com`` does
    not match. ``0.0.0.0`` is not loopback; see
    :func:`is_unspecified_address`.
    """
    if not address:
        return False
    return address.strip().lower() in LOOPBACK_SERVER_ADDRESSES


def is_unspecified_address(address: str | None) -> bool:
    """True if *address* records no endpoint at all.

    Covers a genuinely absent value, the ``"unknown"`` placeholder the profile
    parser substitutes for a missing key, and the unspecified addresses
    ``0.0.0.0`` and ``::``.
    """
    if address is None:
        return True
    return address.strip().lower() in UNSPECIFIED_SERVER_ADDRESSES


__all__ = [
    "APPLE_SYSTEM_PATHS",
    "KNOWN_LEGITIMATE_ORGS",
    "KNOWN_LEGITIMATE_SERVICES",
    "LOOPBACK_SERVER_ADDRESSES",
    "UNSPECIFIED_SERVER_ADDRESSES",
    "NOTEWORTHY_ISSUER_TOKENS",
    "NOTEWORTHY_NAME_TOKENS",
    "contains_keyword_token",
    "is_allowlisted_profile",
    "is_apple_system_path",
    "is_known_organization",
    "is_known_service",
    "is_loopback_address",
    "is_unspecified_address",
    "tokenize",
]
