#!/usr/bin/env python3
"""Scan all iPhone backups in a directory with improved threat detection."""

import sys
import getpass
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.device_info import DeviceInfoExtractor

def scan_backup(backup_dir: Path, password: str = None) -> dict:
    """Scan a single backup and return results."""
    extractor = DeviceInfoExtractor(str(backup_dir), password=password)
    
    # Validate backup
    if not extractor.validate_backup():
        return {"valid": False, "error": "Invalid backup structure"}
    
    # Get device info
    try:
        device_info = extractor.extract_device_info()
    except Exception as e:
        return {"valid": False, "error": f"Could not extract device info: {e}"}
    
    # Extract security profiles
    try:
        profiles = extractor.extract_security_profiles()
    except Exception as e:
        return {"valid": False, "error": f"Could not extract profiles: {e}"}
    
    # Count threats by level
    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    critical_threats = []
    high_threats = []
    
    for profile in profiles:
        level = profile.threat_level.value
        threat_counts[level] += 1
        
        if level == "CRITICAL":
            critical_threats.append(profile)
        elif level == "HIGH":
            high_threats.append(profile)
    
    return {
        "valid": True,
        "device_info": device_info,
        "total_profiles": len(profiles),
        "threat_counts": threat_counts,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
    }

def main():
    backup_root = Path("/Volumes/bakupdisk/iMazing.Backups")
    
    if not backup_root.exists():
        print(f"❌ Backup directory not found: {backup_root}")
        print("\nMake sure the drive is mounted at /Volumes/bakupdisk/")
        return 1
    
    # Find all backup directories
    backups = [d for d in backup_root.iterdir() if d.is_dir() and not d.name.startswith('.')]
    
    if not backups:
        print(f"❌ No backup directories found in {backup_root}")
        return 1
    
    print("=" * 70)
    print("SCANNING ALL iPhone BACKUPS")
    print("=" * 70)
    print(f"\nFound {len(backups)} backup(s) in {backup_root}")
    
    # Ask for encryption password
    print("\n🔐 Some backups may be encrypted.")
    password = getpass.getpass("Enter backup encryption password (or press Enter to skip encrypted backups): ")
    
    if not password:
        password = None
        print("ℹ️  Will skip encrypted backups\n")
    else:
        print("ℹ️  Will attempt to decrypt encrypted backups\n")
    
    results = []
    
    for i, backup_dir in enumerate(backups, 1):
        print(f"\n{'─' * 70}")
        print(f"[{i}/{len(backups)}] Analyzing: {backup_dir.name}")
        print(f"{'─' * 70}")
        
        result = scan_backup(backup_dir, password=password)
        
        if not result["valid"]:
            print(f"⚠️  Skipped: {result['error']}")
            continue
        
        device_info = result["device_info"]
        print(f"\n📱 Device: {device_info.device_name}")
        print(f"   Model: {device_info.model}")
        print(f"   iOS: {device_info.ios_version}")
        if device_info.serial_number:
            print(f"   Serial: {device_info.serial_number}")
        
        print(f"\n📊 Security Profiles: {result['total_profiles']}")
        print(f"   🔴 CRITICAL: {result['threat_counts']['CRITICAL']}")
        print(f"   🟠 HIGH: {result['threat_counts']['HIGH']}")
        print(f"   🟡 MEDIUM: {result['threat_counts']['MEDIUM']}")
        print(f"   🔵 LOW: {result['threat_counts']['LOW']}")
        print(f"   ✅ NONE: {result['threat_counts']['NONE']}")
        
        # Show critical threats
        if result["critical_threats"]:
            print(f"\n🚨 CRITICAL THREATS:")
            for threat in result["critical_threats"]:
                print(f"\n   [{threat.profile_type}] {threat.display_name or 'Unknown'}")
                print(f"   ID: {threat.profile_id[:60]}...")
                if threat.organization:
                    print(f"   Org: {threat.organization}")
                for indicator in threat.suspicious_indicators or []:
                    print(f"      • {indicator}")
        
        # Show high threats
        if result["high_threats"]:
            print(f"\n⚠️  HIGH THREATS:")
            for threat in result["high_threats"]:
                print(f"\n   [{threat.profile_type}] {threat.display_name or 'Unknown'}")
                print(f"   ID: {threat.profile_id[:60]}...")
                if threat.organization:
                    print(f"   Org: {threat.organization}")
        
        results.append({
            "backup": backup_dir.name,
            "device": device_info.device_name,
            "result": result
        })
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY OF ALL BACKUPS")
    print("=" * 70)
    
    total_critical = sum(r["result"]["threat_counts"]["CRITICAL"] for r in results)
    total_high = sum(r["result"]["threat_counts"]["HIGH"] for r in results)
    total_threats = sum(
        sum(v for k, v in r["result"]["threat_counts"].items() if k != "NONE")
        for r in results
    )
    
    print(f"\nTotal Backups Analyzed: {len(results)}")
    print(f"Total Threats Found: {total_threats}")
    print(f"  🔴 CRITICAL: {total_critical}")
    print(f"  🟠 HIGH: {total_high}")
    
    if total_critical > 0:
        print(f"\n⚠️  ACTION REQUIRED: {total_critical} CRITICAL threats detected!")
        print("   Review the details above carefully.")
    elif total_high > 0:
        print(f"\n⚠️  {total_high} HIGH priority threats detected - review recommended.")
    else:
        print("\n✅ No CRITICAL or HIGH threats detected across all backups.")
    
    # Save detailed report
    report_file = Path(f"backup_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("iPhone Backup Security Scan Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        
        for r in results:
            f.write(f"\n{'─' * 70}\n")
            f.write(f"Backup: {r['backup']}\n")
            f.write(f"Device: {r['device']}\n")
            f.write(f"{'─' * 70}\n\n")
            
            result = r["result"]
            f.write(f"Total Profiles: {result['total_profiles']}\n")
            f.write(f"CRITICAL: {result['threat_counts']['CRITICAL']}\n")
            f.write(f"HIGH: {result['threat_counts']['HIGH']}\n")
            f.write(f"MEDIUM: {result['threat_counts']['MEDIUM']}\n")
            f.write(f"LOW: {result['threat_counts']['LOW']}\n")
            f.write(f"NONE: {result['threat_counts']['NONE']}\n\n")
            
            if result["critical_threats"]:
                f.write("CRITICAL THREATS:\n")
                for threat in result["critical_threats"]:
                    f.write(f"\n  Type: {threat.profile_type}\n")
                    f.write(f"  Name: {threat.display_name or 'Unknown'}\n")
                    f.write(f"  ID: {threat.profile_id}\n")
                    if threat.organization:
                        f.write(f"  Organization: {threat.organization}\n")
                    f.write(f"  Indicators:\n")
                    for ind in threat.suspicious_indicators or []:
                        f.write(f"    • {ind}\n")
                f.write("\n")
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
