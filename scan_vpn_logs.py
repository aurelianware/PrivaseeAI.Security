#!/usr/bin/env python3
"""Scan WireGuard/ProtonVPN log files for security threats."""

import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor

def scan_log_file(log_file: Path):
    """Scan a VPN log file for threats."""
    
    if not log_file.exists():
        print(f"❌ Log file not found: {log_file}")
        return 1
    
    print("=" * 70)
    print("VPN LOG SECURITY SCAN")
    print("=" * 70)
    print(f"\n📄 Analyzing: {log_file.name}")
    print(f"   Path: {log_file}")
    print(f"   Size: {log_file.stat().st_size:,} bytes")
    
    # Read log file
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            log_lines = f.readlines()
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return 1
    
    print(f"   Lines: {len(log_lines):,}")
    
    # Initialize monitor
    vpn_monitor = VPNIntegrityMonitor()
    
    print("\n🔍 Scanning for threats...")
    print()
    
    # Process each log line
    threats_found = []
    
    for i, line in enumerate(log_lines, 1):
        # VPN integrity check returns list of threats
        vpn_threats = vpn_monitor.analyze_log_entry(line)
        if vpn_threats:
            for threat in vpn_threats:
                # Only include actual threats (not NONE level)
                if threat.threat_level.value != 'NONE':
                    threats_found.append({
                        'line': i,
                        'type': 'VPN',
                        'threat': threat,
                        'content': line.strip()
                    })
    
    # Display results
    print("=" * 70)
    print("THREAT ANALYSIS RESULTS")
    print("=" * 70)
    
    if not threats_found:
        print("\n✅ No threats detected in log file!")
        print("\n   Your VPN logs appear clean.")
        return 0
    
    # Group by threat level
    critical = [t for t in threats_found if t['threat'].threat_level.value == 'CRITICAL']
    high = [t for t in threats_found if t['threat'].threat_level.value == 'HIGH']
    medium = [t for t in threats_found if t['threat'].threat_level.value == 'MEDIUM']
    low = [t for t in threats_found if t['threat'].threat_level.value == 'LOW']
    
    print(f"\n📊 Found {len(threats_found)} threat(s):")
    print(f"   🔴 CRITICAL: {len(critical)}")
    print(f"   🟠 HIGH: {len(high)}")
    print(f"   🟡 MEDIUM: {len(medium)}")
    print(f"   🔵 LOW: {len(low)}")
    
    # Show critical threats
    if critical:
        print("\n" + "=" * 70)
        print("🔴 CRITICAL THREATS")
        print("=" * 70)
        for t in critical:
            print(f"\n[Line {t['line']}] {t['threat'].attack_type}")
            print(f"   Description: {t['threat'].details}")
            print(f"   Indicators:")
            for ind in t['threat'].indicators:
                print(f"      • {ind}")
            if len(t['content']) < 200:
                print(f"   Log: {t['content']}")
    
    # Show high threats
    if high:
        print("\n" + "=" * 70)
        print("🟠 HIGH THREATS")
        print("=" * 70)
        for t in high:
            print(f"\n[Line {t['line']}] {t['threat'].attack_type}")
            print(f"   Description: {t['threat'].details}")
            print(f"   Indicators:")
            for ind in t['threat'].indicators:
                print(f"      • {ind}")
    
    # Show medium threats
    if medium:
        print("\n" + "=" * 70)
        print("🟡 MEDIUM THREATS")
        print("=" * 70)
        for t in medium:
            print(f"\n[Line {t['line']}] {t['threat'].attack_type}")
            print(f"   Description: {t['threat'].details}")
    
    # Save detailed report
    report_file = log_file.parent / f"threat_scan_{log_file.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("VPN Log Security Scan Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log File: {log_file}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Total Threats: {len(threats_found)}\n")
        f.write(f"CRITICAL: {len(critical)}\n")
        f.write(f"HIGH: {len(high)}\n")
        f.write(f"MEDIUM: {len(medium)}\n")
        f.write(f"LOW: {len(low)}\n\n")
        
        for t in threats_found:
            f.write(f"\n{'─' * 70}\n")
            f.write(f"[Line {t['line']}] {t['threat'].threat_level.value} - {t['threat'].attack_type}\n")
            f.write(f"{'─' * 70}\n")
            f.write(f"Description: {t['threat'].details}\n")
            f.write(f"Indicators:\n")
            for ind in t['threat'].indicators:
                f.write(f"  • {ind}\n")
            f.write(f"\nLog Entry:\n{t['content']}\n")
    
    print(f"\n📄 Detailed report saved to: {report_file.name}")
    
    # Recommendations
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)
    
    if critical or high:
        print("\n⚠️  ACTION REQUIRED:")
        print("   - Disconnect from current network immediately")
        print("   - Switch VPN servers or providers")
        print("   - Review all CRITICAL and HIGH threats above")
        print("   - Consider your network may be compromised")
    elif medium:
        print("\n⚠️  REVIEW RECOMMENDED:")
        print("   - Monitor for recurring patterns")
        print("   - Consider switching VPN servers")
        print("   - Check if issues persist on different networks")
    
    return 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scan_vpn_logs.py <logfile>")
        print("\nExample:")
        print('  python3 scan_vpn_logs.py "WireGuard Logs (1).log"')
        print('  python3 scan_vpn_logs.py proton_vpn.log')
        return 1
    
    log_file = Path(sys.argv[1])
    return scan_log_file(log_file)

if __name__ == "__main__":
    sys.exit(main())
