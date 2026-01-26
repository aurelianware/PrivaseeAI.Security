#!/usr/bin/env python3
"""Test iPhone VPN security by analyzing live device logs.

Usage:
  1. Connect iPhone via USB
  2. Unlock iPhone and trust computer
  3. Run: python test_iphone.py --live
     OR
     python test_iphone.py --file path/to/logs.txt
"""

import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime

from src.privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor
from src.privaseeai_security.monitors.api_abuse import APIAbuseMonitor
from src.privaseeai_security.alerting.telegram import TelegramAlerter
from src.privaseeai_security.crypto.cert_validator import ThreatLevel


def check_idevice_tools():
    """Check if libimobiledevice tools are installed."""
    try:
        subprocess.run(['which', 'idevicesyslog'], 
                      capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def collect_live_logs(duration_seconds=120):
    """Collect logs from connected iPhone for specified duration.
    
    Args:
        duration_seconds: How long to collect logs (default 2 minutes)
    
    Returns:
        Path to collected log file
    """
    print(f"📱 Collecting iPhone logs for {duration_seconds} seconds...")
    print("   ℹ️  Use your VPN during this time:")
    print("      - Connect/disconnect VPN")
    print("      - Switch servers")
    print("      - Browse websites")
    print("      - Open location-based apps\n")
    
    log_dir = Path.home() / "ios_device_logs"
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"iphone_test_{timestamp}.log"
    
    try:
        # Start log collection
        with open(log_file, 'w') as f:
            process = subprocess.Popen(
                ['idevicesyslog'],
                stdout=f,
                stderr=subprocess.PIPE
            )
            
            # Wait for specified duration
            import time
            for remaining in range(duration_seconds, 0, -10):
                print(f"   ⏱️  {remaining} seconds remaining...")
                time.sleep(10)
            
            # Stop collection
            process.terminate()
            process.wait(timeout=5)
            
        print(f"✅ Logs saved to: {log_file}\n")
        return log_file
        
    except FileNotFoundError:
        print("❌ Error: idevicesyslog not found")
        print("   Install with: brew install libimobiledevice")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error collecting logs: {e}")
        sys.exit(1)


def analyze_logs(log_file, verbose=False):
    """Analyze iPhone logs for security threats.
    
    Args:
        log_file: Path to log file
        verbose: Show all detections including NONE level
    
    Returns:
        List of threats found
    """
    print(f"🔍 Analyzing logs: {log_file}\n")
    
    # Initialize monitors
    vpn_monitor = VPNIntegrityMonitor()
    api_monitor = APIAbuseMonitor()
    alerter = TelegramAlerter(dry_run=True)
    
    threats_found = []
    lines_processed = 0
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            lines_processed += 1
            
            # Analyze with VPN monitor
            if any(keyword in line.lower() for keyword in 
                   ['vpn', 'wireguard', 'protonvpn', 'protocol', 'dns64', 'certificate']):
                vpn_threats = vpn_monitor.analyze_log_entry(line)
                for threat in vpn_threats:
                    if verbose or threat.threat_level.value != "NONE":
                        threats_found.append(('VPN', threat))
            
            # Analyze with API monitor (VPN apps only, not iOS system)
            if any(keyword in line.lower() for keyword in 
                   ['protonvpn', 'vpn']) and any(api_kw in line.lower() for api_kw in 
                   ['api', 'cooldown', 'rate limit', 'error', 'location request']):
                # Extract app identifier if possible
                app_id = "unknown.app"
                if "protonvpn" in line.lower():
                    app_id = "ch.protonvpn.ios"
                
                api_threat = api_monitor.check_rate_limit_responses(app_id, line)
                if api_threat:
                    if verbose or api_threat.threat_level.value != "NONE":
                        threats_found.append(('API', api_threat))
    
    print(f"📊 Processed {lines_processed} log lines\n")
    
    # Report findings
    if not threats_found:
        print("✅ No threats detected!")
        print("   Your iPhone VPN appears to be working normally.\n")
        return []
    
    # Group by severity
    critical = [t for _, t in threats_found if t.threat_level == ThreatLevel.CRITICAL]
    high = [t for _, t in threats_found if t.threat_level == ThreatLevel.HIGH]
    medium = [t for _, t in threats_found if t.threat_level == ThreatLevel.MEDIUM]
    low = [t for _, t in threats_found if t.threat_level == ThreatLevel.LOW]
    none = [t for _, t in threats_found if t.threat_level == ThreatLevel.NONE]
    
    # Display results
    if critical:
        print(f"🚨 CRITICAL THREATS: {len(critical)}")
        for monitor_type, threat in [(m, t) for m, t in threats_found if t.threat_level == ThreatLevel.CRITICAL]:
            print(f"   [{monitor_type}] {threat.attack_type}")
            print(f"   Details: {threat.details}")
            for indicator in threat.indicators:
                print(f"   • {indicator}")
            print()
    
    if high:
        print(f"🔴 HIGH THREATS: {len(high)}")
        for monitor_type, threat in [(m, t) for m, t in threats_found if t.threat_level == ThreatLevel.HIGH]:
            print(f"   [{monitor_type}] {threat.attack_type}")
            print(f"   Details: {threat.details}")
            for indicator in threat.indicators[:3]:  # Show first 3
                print(f"   • {indicator}")
            print()
    
    if medium:
        print(f"🟠 MEDIUM THREATS: {len(medium)}")
        for monitor_type, threat in [(m, t) for m, t in threats_found if t.threat_level == ThreatLevel.MEDIUM]:
            print(f"   [{monitor_type}] {threat.attack_type}")
            if threat.details:
                print(f"   {threat.details[:100]}...")
            print()
    
    if low and verbose:
        print(f"🟡 LOW THREATS: {len(low)}")
    
    if none and verbose:
        print(f"🟢 INFORMATIONAL: {len(none)}")
    
    return threats_found


def main():
    parser = argparse.ArgumentParser(
        description='Test iPhone VPN security with PrivaseeAI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect logs for 2 minutes and analyze
  python test_iphone.py --live
  
  # Collect logs for 5 minutes
  python test_iphone.py --live --duration 300
  
  # Analyze existing log file
  python test_iphone.py --file ~/ios_device_logs/test.log
  
  # Show all detections including informational
  python test_iphone.py --file test.log --verbose
        """
    )
    
    parser.add_argument('--live', action='store_true',
                       help='Collect logs from connected iPhone')
    parser.add_argument('--file', type=Path,
                       help='Analyze existing log file')
    parser.add_argument('--duration', type=int, default=120,
                       help='Collection duration in seconds (default: 120)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show all detections including NONE level')
    
    args = parser.parse_args()
    
    if not args.live and not args.file:
        parser.print_help()
        sys.exit(1)
    
    print("=" * 60)
    print("PrivaseeAI Security - iPhone VPN Testing")
    print("=" * 60)
    print()
    
    # Collect or use existing logs
    if args.live:
        if not check_idevice_tools():
            print("❌ Error: libimobiledevice tools not found")
            print("   Install with: brew install libimobiledevice")
            sys.exit(1)
        
        log_file = collect_live_logs(args.duration)
    else:
        log_file = args.file
        if not log_file.exists():
            print(f"❌ Error: Log file not found: {log_file}")
            sys.exit(1)
    
    # Analyze logs
    threats = analyze_logs(log_file, verbose=args.verbose)
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Log file: {log_file}")
    print(f"Total threats: {len([t for _, t in threats if t.threat_level.value != 'NONE'])}")
    print()
    
    if any(t.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] for _, t in threats):
        print("⚠️  ACTION REQUIRED:")
        print("   - Review threat details above")
        print("   - Consider disconnecting from current network")
        print("   - Switch VPN servers or providers")
    else:
        print("✅ Your iPhone VPN security looks good!")
    print()


if __name__ == '__main__':
    main()
