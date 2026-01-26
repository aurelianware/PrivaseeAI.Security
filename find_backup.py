#!/usr/bin/env python3
"""Find Info.plist in backup directories."""

from pathlib import Path
import plistlib

backup_base = Path.home() / "Library/Application Support/MobileSync/Backup"
backup_dir = backup_base / "00008140-0005355630E3C01C"

print(f"Searching for Info.plist in: {backup_dir}\n")

# Check parent directory
print("Checking parent directory:")
for item in sorted(backup_base.iterdir()):
    if item.is_dir():
        info_plist = item / "Info.plist"
        manifest_plist = item / "Manifest.plist"
        if info_plist.exists() or manifest_plist.exists():
            print(f"\n✅ Found backup: {item.name}")
            print(f"   Info.plist:     {info_plist.exists()}")
            print(f"   Manifest.plist: {manifest_plist.exists()}")
            print(f"   Manifest.db:    {(item / 'Manifest.db').exists()}")
            
            # Try to read Info.plist
            if info_plist.exists():
                try:
                    with open(info_plist, 'rb') as f:
                        info = plistlib.load(f)
                        print(f"   Device Name:    {info.get('Device Name', 'Unknown')}")
                        print(f"   iOS Version:    {info.get('Product Version', 'Unknown')}")
                        print(f"   Last Backup:    {info.get('Last Backup Date', 'Unknown')}")
                except Exception as e:
                    print(f"   Error reading Info.plist: {e}")
            
            # Check encryption
            if manifest_plist.exists():
                try:
                    with open(manifest_plist, 'rb') as f:
                        manifest = plistlib.load(f)
                        is_encrypted = manifest.get("IsEncrypted", False)
                        print(f"   Encrypted:      {is_encrypted}")
                except Exception as e:
                    print(f"   Error reading Manifest.plist: {e}")

# Also check in subdirectories
print("\n" + "="*60)
print("\nChecking subdirectories of current backup:")
for subdir in sorted(backup_dir.iterdir())[:5]:
    if subdir.is_dir():
        files = list(subdir.iterdir())[:3]
        print(f"\n{subdir.name}/: {len(list(subdir.iterdir()))} files")
        for f in files:
            print(f"  - {f.name}")
