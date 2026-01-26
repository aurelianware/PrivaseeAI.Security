#!/usr/bin/env python3
"""Test iOS backup analysis on iMazing backup."""

from pathlib import Path
from src.privaseeai_security.device_info import DeviceInfoExtractor

# iMazing backup location (on external drive)
backup_dir = Path("/Volumes/bk/iMazing.Backups")

print("=" * 60)
print("iOS Backup Analyzer Test - iMazing")
print("=" * 60)

if not backup_dir.exists():
    print(f"❌ Backup directory not found: {backup_dir}")
    exit(1)

# Find all backups in this directory
backups = [d for d in backup_dir.glob("*/") if d.is_dir()]
if not backups:
    print(f"❌ No backup directories found in: {backup_dir}")
    exit(1)

print(f"\n✅ Found {len(backups)} backup(s)")

# Find most recent VALID backup
valid_backups = []
for b in backups:
    if (b / "Info.plist").exists():
        valid_backups.append(b)
        print(f"  • {b.name} - ✅ Valid")
    else:
        print(f"  • {b.name} - ❌ Missing Info.plist")

if not valid_backups:
    print(f"\n❌ No valid backups found")
    exit(1)

latest_backup = max(valid_backups, key=lambda p: p.stat().st_mtime)
print(f"\n📱 Analyzing most recent backup:")
print(f"   Path: {latest_backup.name}")

print("\n" + "-" * 60)

# Initialize extractor
extractor = DeviceInfoExtractor(str(latest_backup))

# Validate backup
print("\n🔍 Validating backup structure...")
if not extractor.validate_backup():
    print("❌ Invalid backup structure")
    print("\nPossible reasons:")
    print("- Backup is encrypted (password required)")
    print("- Backup is corrupted")
    print("- Missing required files (Info.plist, Manifest files)")
    exit(1)

print("✅ Backup is valid")

# Extract device info
print("\n📋 Device Information:")
print("-" * 60)
device_info = extractor.extract_device_info()
print(f"Device ID:     {device_info.device_id}")
print(f"Device Name:   {device_info.device_name}")
print(f"iOS Version:   {device_info.ios_version}")
print(f"Model:         {device_info.model}")
if device_info.serial_number:
    print(f"Serial:        {device_info.serial_number}")
if device_info.build_version:
    print(f"Build:         {device_info.build_version}")

# Extract installed apps
print("\n📱 Installed Applications:")
print("-" * 60)
apps = extractor.get_installed_apps()
if apps:
    print(f"Found {len(apps)} apps:")
    for app in apps[:10]:
        print(f"  • {app.bundle_id}")
    if len(apps) > 10:
        print(f"  ... and {len(apps) - 10} more")
else:
    print("No apps found (may require unencrypted backup)")

# Extract VPN profiles
print("\n🔒 VPN Profiles:")
print("-" * 60)
vpn_profiles = extractor.extract_vpn_profiles()
if vpn_profiles:
    print(f"Found {len(vpn_profiles)} VPN profile(s):")
    for profile in vpn_profiles:
        print(f"\n  Profile ID: {profile.profile_id}")
        print(f"  Type:       {profile.profile_type}")
        print(f"  Signed:     {profile.is_signed}")
        if profile.organization:
            print(f"  Org:        {profile.organization}")
        if profile.display_name:
            print(f"  Name:       {profile.display_name}")
        if profile.suspicious_indicators:
            print(f"  ⚠️  Threats:  {', '.join(profile.suspicious_indicators)}")
            print(f"  Level:      {profile.threat_level}")
else:
    print("No VPN profiles found")

# Extract MDM profiles
print("\n🏢 MDM Profiles:")
print("-" * 60)
mdm_profiles = extractor.get_mdm_profiles()
if mdm_profiles:
    print(f"Found {len(mdm_profiles)} MDM profile(s):")
    for profile in mdm_profiles:
        print(f"\n  Profile ID: {profile.profile_id}")
        print(f"  Type:       {profile.profile_type}")
        print(f"  Signed:     {profile.is_signed}")
        if profile.organization:
            print(f"  Org:        {profile.organization}")
        if profile.suspicious_indicators:
            print(f"  ⚠️  Threats:  {', '.join(profile.suspicious_indicators)}")
else:
    print("No MDM profiles found")

# Analyze network configuration
print("\n🌐 Network Configuration:")
print("-" * 60)
network_config = extractor.analyze_network_configuration()
if network_config.get("dns_servers"):
    print(f"DNS Servers: {', '.join(network_config['dns_servers'])}")
else:
    print("DNS Servers: None found")

if network_config.get("wifi_networks"):
    print(f"WiFi Networks: {len(network_config['wifi_networks'])} saved")
else:
    print("WiFi Networks: None found")

if network_config.get("proxy_settings"):
    print(f"Proxy: {network_config['proxy_settings']}")
else:
    print("Proxy: None configured")

# Extract all security profiles
print("\n🛡️  Security Profile Analysis:")
print("-" * 60)
security_profiles = extractor.extract_security_profiles()
if security_profiles:
    threats_found = [p for p in security_profiles if p.threat_level != "NONE"]
    
    if threats_found:
        print(f"🚨 THREATS DETECTED: {len(threats_found)} suspicious profile(s)\n")
        for profile in threats_found:
            print(f"⚠️  {profile.profile_type} Profile: {profile.profile_id}")
            print(f"   Threat Level: {profile.threat_level}")
            print(f"   Indicators:")
            for indicator in profile.suspicious_indicators:
                print(f"     • {indicator}")
            print()
    else:
        print("✅ No threats detected - all profiles appear legitimate")
else:
    print("No security profiles found")

print("\n" + "=" * 60)
print("Analysis Complete")
print("=" * 60)
