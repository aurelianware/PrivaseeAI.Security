"""Rendering helpers for VPN :class:`SessionReport` objects.

Shared by ``scan_vpn_logs.py`` and the ``privasee analyze`` CLI command so both
produce the same timeline / metrics / judgments output. Kept UI-free (plain text
and dict/JSON) so it has no dependency on rich/click.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import datetime
import json

from privaseeai_security.collectors.vpn_log_parser import parse_vpn_log_lines
from privaseeai_security.monitors.vpn_integrity import (
    SessionReport,
    VPNIntegrityMonitor,
)
from privaseeai_security.crypto.cert_validator import ThreatLevel

_SEV_ORDER = {
    ThreatLevel.NONE: 0,
    ThreatLevel.INFO: 1,
    ThreatLevel.LOW: 2,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.HIGH: 4,
    ThreatLevel.CRITICAL: 5,
}


def analyze_logfile(path: str) -> SessionReport:
    """Parse ``path`` and return a :class:`SessionReport` for the whole session."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()
    events = parse_vpn_log_lines(lines)
    monitor = VPNIntegrityMonitor()
    return monitor.analyze_session(events)


def _fmt_time(ts: Optional[datetime.datetime]) -> str:
    if ts is None:
        return "??:??:??"
    return ts.strftime("%H:%M:%S")


def _collapse_path_storm(report: SessionReport) -> Optional[str]:
    """Return a collapsed one-line summary for the PATH_MONITOR_STORM, if any."""
    storm = next(
        (j for j in report.judgments if j["kind"] == "PATH_MONITOR_STORM"), None
    )
    if not storm:
        return None
    start = _fmt_time(report.start_ts)
    end = _fmt_time(report.end_ts)
    n = report.metrics.get("bump_count", 0)
    rate = report.metrics.get("bumps_per_hour", 0)
    return f"{start}–{end} PATH_MONITOR_STORM n={n} bumps/hr={rate}"


def render_timeline(report: SessionReport) -> List[str]:
    """Render chronological observations, collapsing PATH bumps into one line."""
    lines: List[str] = ["Timeline"]
    storm_line = _collapse_path_storm(report)
    if storm_line:
        lines.append(f"  {storm_line}")

    # Show non-bump observations chronologically (bumps are collapsed above).
    shown = 0
    for obs in report.observations:
        if obs["kind"] == "PATH_BUMP" and storm_line:
            continue
        lines.append(
            f"  {_fmt_time(obs['ts'])} {obs['kind']}: {obs['summary']}"
        )
        shown += 1
    if shown == 0 and not storm_line:
        lines.append("  (no notable observations)")
    return lines


def render_metrics(report: SessionReport) -> List[str]:
    """Render the metrics table as aligned text rows."""
    lines = ["Metrics"]
    for key, value in report.metrics.items():
        lines.append(f"  {key:<28} {value}")
    return lines


def render_judgments(report: SessionReport, verbose: bool = False) -> List[str]:
    """Render judgments. By default only MEDIUM+ are shown; verbose adds INFO/LOW."""
    lines = ["Judgments"]
    threshold = _SEV_ORDER[ThreatLevel.MEDIUM]
    shown = 0
    for j in sorted(
        report.judgments, key=lambda x: _SEV_ORDER[x["severity"]], reverse=True
    ):
        if not verbose and _SEV_ORDER[j["severity"]] < threshold:
            continue
        conf = j.get("confidence", 0.0)
        lines.append(
            f"  [{j['severity'].value}] {j['kind']} (confidence={conf:.2f})"
        )
        lines.append(f"      {j['summary']}")
        alts = j.get("alternatives") or []
        if alts:
            lines.append("      benign alternatives: " + "; ".join(alts))
        shown += 1
    if shown == 0:
        lines.append(
            "  (no MEDIUM+ judgments)"
            if not verbose
            else "  (no judgments)"
        )
    return lines


def should_warn_disconnect(report: SessionReport) -> bool:
    """True only if there is a HIGH/CRITICAL judgment with confidence >= 0.7.

    Gate for the alarming "disconnect immediately / network may be compromised"
    guidance so it never fires on normal Proton/iOS behaviour.
    """
    for j in report.judgments:
        if (
            _SEV_ORDER[j["severity"]] >= _SEV_ORDER[ThreatLevel.HIGH]
            and j.get("confidence", 0.0) >= 0.7
        ):
            return True
    return False


def render_report(report: SessionReport, verbose: bool = False) -> str:
    """Render the full human-readable report."""
    out: List[str] = []
    out += render_timeline(report)
    out.append("")
    out += render_metrics(report)
    out.append("")
    out += render_judgments(report, verbose=verbose)

    if should_warn_disconnect(report):
        out.append("")
        out.append(
            "⚠️  Disconnect immediately — a high-confidence high-severity "
            "signal was found; your network may be compromised."
        )
    return "\n".join(out)


def _severity_name(sev: ThreatLevel) -> str:
    return sev.value


def report_to_dict(report: SessionReport) -> Dict[str, Any]:
    """Serialize a :class:`SessionReport` to a JSON-friendly dict."""

    def obs_to_dict(o: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": o["ts"].isoformat() if isinstance(o["ts"], datetime.datetime) else o["ts"],
            "kind": o["kind"],
            "severity": _severity_name(o["severity"]),
            "summary": o["summary"],
            "line_no": o["line_no"],
            "evidence": o["evidence"],
        }

    def judg_to_dict(j: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "kind": j["kind"],
            "severity": _severity_name(j["severity"]),
            "confidence": j.get("confidence"),
            "alternatives": j.get("alternatives", []),
            "summary": j["summary"],
        }

    return {
        "start_ts": report.start_ts.isoformat() if report.start_ts else None,
        "end_ts": report.end_ts.isoformat() if report.end_ts else None,
        "metrics": report.metrics,
        "observations": [obs_to_dict(o) for o in report.observations],
        "judgments": [judg_to_dict(j) for j in report.judgments],
        "max_severity": _severity_name(report.max_severity()),
    }


def render_json(report: SessionReport) -> str:
    """Render the report as indented JSON."""
    return json.dumps(report_to_dict(report), indent=2)


def render_baseline_delta(
    report: SessionReport, baseline: SessionReport
) -> List[str]:
    """Render metric deltas between ``report`` and a ``baseline`` session."""
    keys = ["bumps_per_hour", "unique_peers", "unique_dns64_ips"]
    # retries/hr derived from handshake retry counts and duration.
    lines = ["Baseline comparison (this - baseline)"]

    def retries_per_hour(r: SessionReport) -> float:
        dur = r.metrics.get("duration_seconds", 0) or 0
        retries = r.metrics.get("handshake_retry_15s_count", 0) + r.metrics.get(
            "handshake_timeout_5s_count", 0
        )
        return round(retries / dur * 3600.0, 1) if dur > 0 else 0.0

    for key in keys:
        a = report.metrics.get(key, 0)
        b = baseline.metrics.get(key, 0)
        lines.append(f"  {key:<20} {a}  (baseline {b}, Δ {round(a - b, 2)})")

    a_r = retries_per_hour(report)
    b_r = retries_per_hour(baseline)
    lines.append(
        f"  {'retries_per_hour':<20} {a_r}  (baseline {b_r}, Δ {round(a_r - b_r, 2)})"
    )
    return lines


__all__ = [
    "analyze_logfile",
    "render_report",
    "render_json",
    "render_timeline",
    "render_metrics",
    "render_judgments",
    "render_baseline_delta",
    "report_to_dict",
    "should_warn_disconnect",
]
