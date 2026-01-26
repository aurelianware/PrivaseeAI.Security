#!/usr/bin/env python3
"""Quick test of improved threat detection with false positive reduction."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.device_info import DeviceInfoExtractor

def main():
    # Find most recent iMazing backup
    imazing_path = Path("/Volumes/bk/iMazing.Backups")
    
    if not imazing_path.exists():
        print(f"❌ iMazing backup path not found: {imazing_path}")
        return 1
    
    backups = [d for d in imazing_path.iterdir() if d.is_dir()]
    if not backups:
        print(f"❌ No backups found in {imazing_path}")
        return 1
    
    # Get most recent backup
    backup_dir = max(backups, key=lambda d: d.stat().st_mtime)
    
    print("=" * 60)
    print("Improved Threat Detection Test")
    print("=" * 60)
    print(f"\nAnalyzing: {backup_dir.name}")
    
    # Extract security profiles
    extractor = DeviceInfoExtractor(str(backup_dir))
    
    print("\n🔍 Extracting security profiles...")
    profiles = extractor.extract_security_profiles()
    
    print(f"✅ Found {len(profiles)} total profiles")
    
    # Count by threat level
    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    
    print("\n" + "=" * 60)
    print("THREAT ANALYSIS RESULTS")
    print("=" * 60)
    
    for profile in profiles:
        level = profile.threat_level.value
        threat_counts[level] += 1
        
        # Only show profiles with threats (not NONE)
        if profile.threat_level.value != "NONE":
            print(f"\n🔴 {profile.threat_level.value} - {profile.profile_type}")
            print(f"   ID: {profile.profile_id[:80]}...")
            if profile.display_name:
                print(f"   Name: {profile.display_name}")
            if profile.organization:
                print(f"   Org: {profile.organization}")
            if profile.suspicious_indicators:
                print(f"   Indicators:")
                for indicator in profile.suspicious_indicators:
                    print(f"      • {indicator}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total profiles: {len(profiles)}")
    print(f"  🔴 CRITICAL: {threat_counts['CRITICAL']}")
    print(f"  🟠 HIGH: {threat_counts['HIGH']}")
    print(f"  🟡 MEDIUM: {threat_counts['MEDIUM']}")
    print(f"  🔵 LOW: {threat_counts['LOW']}")
    print(f"  ✅ NONE (Clean): {threat_counts['NONE']}")
    
    print("\n" + "=" * 60)
    print("IMPROVEMENT ANALYSIS")
    print("=" * 60)
    
    total_threats = sum(v for k, v in threat_counts.items() if k != "NONE")
    print(f"\nBefore: 27 threats (2 VPN MEDIUM, 25 MDM CRITICAL)")
    print(f"After:  {total_threats} threats")
    print(f"Reduction: {27 - total_threats} false positives removed ✅")
    
    if threat_counts['CRITICAL'] > 0:
        print(f"\n⚠️  {threat_counts['CRITICAL']} CRITICAL threats still detected - review carefully!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
