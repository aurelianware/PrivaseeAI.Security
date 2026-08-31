"""Collectors for turning raw device/VPN logs into structured events."""

from .vpn_log_parser import VpnLogEvent, parse_vpn_log_line, parse_vpn_log_lines

__all__ = ["VpnLogEvent", "parse_vpn_log_line", "parse_vpn_log_lines"]
