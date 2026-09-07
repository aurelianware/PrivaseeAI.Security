"""Shared contract and fixtures for the negative-case suite.

The rest of the suite tests that detection *fires*. This directory tests that
it stays *quiet* — which is the property a detector actually has to earn, since
a rule that cries wolf is worse than no rule at all.

The contract is one assertion, :func:`assert_quiet`. Every case in this
directory feeds the detectors a synthetic-but-realistic *benign* input and
requires that nothing above INFO comes back.

Conventions
-----------
* **Corpus as data.** Backups are built by fixtures rather than hand-rolled in
  each test, so the same shapes are reusable.
* **A justification for every fixture.** Each case carries a
  ``BENIGN-BECAUSE:`` note naming the real-world behaviour it represents. A
  fixture nobody can justify is one that will later be "fixed" by loosening the
  assertion.
* **Frozen clock.** Time-dependent rules must not pass or fail based on when CI
  runs.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Iterable, List, Sequence

import pytest

from privaseeai_security.crypto.cert_validator import ThreatLevel
from privaseeai_security.monitors.carrier_detection import _SEVERITY_ORDER


def assert_quiet(
    detections: Sequence,
    max_severity: ThreatLevel = ThreatLevel.INFO,
    context: str = "",
) -> None:
    """Require that no detection exceeds *max_severity*.

    On failure this names every offending rule, its severity, its confidence
    and its indicators, so a regression identifies the rule that broke rather
    than just reporting a count.
    """
    offenders = [
        d for d in detections if _SEVERITY_ORDER[d.threat_level] > _SEVERITY_ORDER[max_severity]
    ]
    if not offenders:
        return

    lines = [
        f"{len(offenders)} detection(s) above {max_severity.value}"
        + (f" for {context}" if context else ""),
        "",
    ]
    for d in offenders:
        lines.append(f"  {d.threat_level.value:<9} {d.attack_type}")
        lines.append(f"    confidence : {getattr(d, 'confidence', 'n/a')}")
        lines.append(f"    indicators : {d.indicators}")
        lines.append(f"    kinds      : {[k.value for k in getattr(d, 'indicator_kinds', [])]}")
        lines.append(f"    alternatives: {getattr(d, 'alternatives', [])}")
        lines.append("")
    raise AssertionError("\n".join(lines))


# ---------------------------------------------------------------------------
# Corpus builders
# ---------------------------------------------------------------------------


@pytest.fixture
def backup_root(tmp_path: Path) -> Path:
    """An iOS backup root directory containing one device backup."""
    root = tmp_path / "Backup"
    root.mkdir()
    (root / "00008110-000A1B2C3D4E5F60").mkdir()
    return root


@pytest.fixture
def device_backup(backup_root: Path) -> Path:
    """The single device backup inside :func:`backup_root`."""
    return next(d for d in backup_root.iterdir() if d.is_dir())


def write_plist(directory: Path, name: str, payload: dict) -> Path:
    """Write *payload* into *directory* as a binary plist."""
    path = directory / name
    with open(path, "wb") as handle:
        plistlib.dump(payload, handle)
    return path


def write_carrier_profile(directory: Path, name: str, **fields) -> Path:
    """Write a carrier/eSIM bundle plist.

    Field names mirror what ``_extract_esim_profiles`` reads.
    """
    return write_plist(directory, f"carrier_{name}.plist", dict(fields))


def write_vpn_profile(directory: Path, name: str, **fields) -> Path:
    """Write a VPN configuration plist."""
    return write_plist(directory, f"vpn_{name}.plist", dict(fields))


def write_mdm_vpn_profile(directory: Path, name: str, **payload_fields) -> Path:
    """Write an MDM-delivered VPN payload."""
    body = {"PayloadType": "com.apple.vpn.managed", **payload_fields}
    return write_plist(directory, f"com.apple.mdm.{name}.plist", {"PayloadContent": [body]})


def scutil_dns_output(nameservers: Iterable[str]) -> str:
    """Render ``scutil --dns`` output for the given resolvers."""
    lines: List[str] = ["resolver #1"]
    for index, server in enumerate(nameservers):
        lines.append(f"  nameserver[{index}] : {server}")
    return "\n".join(lines) + "\n"


def ifconfig_output(interfaces: Iterable[str]) -> str:
    """Render ``ifconfig`` output listing the given interface names."""
    flags = "flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380"
    return "\n".join(f"{iface}: {flags}" for iface in interfaces) + "\n"
