#!/usr/bin/env python3
"""Scan a WireGuard / Proton VPN log file as a session timeline.

This is the timeline-engine front end. Unlike the old line-by-line scanner it:

* parses event time from each log line (never wall-clock time),
* records neutral observations separately from judgments, and
* does not print "disconnect immediately / network may be compromised" unless a
  HIGH/CRITICAL judgment with confidence >= 0.7 is present.

A log that is only path-bumps + keepalives + a userInitiated server change exits
0 with zero HIGH/CRITICAL judgments.
"""

import sys
from pathlib import Path

# Add src to path so this runs from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.monitors.vpn_session_report import (  # noqa: E402
    analyze_logfile,
    render_report,
)
from privaseeai_security.crypto.cert_validator import ThreatLevel  # noqa: E402

_ORDER = {
    ThreatLevel.NONE: 0,
    ThreatLevel.INFO: 1,
    ThreatLevel.LOW: 2,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.HIGH: 4,
    ThreatLevel.CRITICAL: 5,
}


def scan_log_file(log_file: Path, verbose: bool = False) -> int:
    """Scan a VPN log file and print a session report. Returns an exit code."""
    if not log_file.exists():
        print(f"❌ Log file not found: {log_file}")
        return 1

    print("=" * 70)
    print("VPN LOG SESSION SCAN")
    print("=" * 70)
    print(f"\n📄 Analyzing: {log_file.name}")
    print(f"   Path: {log_file}")
    print(f"   Size: {log_file.stat().st_size:,} bytes")
    print()

    try:
        report = analyze_logfile(str(log_file))
    except Exception as e:  # pragma: no cover - defensive
        print(f"❌ Error reading/parsing log file: {e}")
        return 1

    print(render_report(report, verbose=verbose))

    # Exit non-zero only on an actionable (MEDIUM+) judgment.
    if _ORDER[report.max_severity()] >= _ORDER[ThreatLevel.MEDIUM]:
        return 1
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:]]
    verbose = False
    if "--verbose" in args:
        verbose = True
        args = [a for a in args if a != "--verbose"]

    if not args:
        print("Usage: python3 scan_vpn_logs.py <logfile> [--verbose]")
        print("\nExample:")
        print('  python3 scan_vpn_logs.py "WireGuard Logs (1).log"')
        print("  python3 scan_vpn_logs.py proton_vpn.log --verbose")
        return 1

    return scan_log_file(Path(args[0]), verbose=verbose)


if __name__ == "__main__":
    sys.exit(main())
