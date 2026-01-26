#!/usr/bin/env python3
"""Check iPhone backup structure."""

from pathlib import Path
import plistlib

backup_dir = Path.home() / "Library/Application Support/MobileSync/Backup/00008140-0005355630E3C01C"

print(f"Checking: {backup_dir}\n")
print("Files in backup:")
for item in sorted(backup_dir.iterdir())[:20]:
    print(f"  {item.name}")

print("\n" + "="*60)

# Check for key files
info_plist = backup_dir / "Info.plist"
manifest_plist = backup_dir / "Manifest.plist"
manifest_db = backup_dir / "Manifest.db"

print("\nKey files:")
print(f"Info.plist:     {info_plist.exists()}")
print(f"Manifest.plist: {manifest_plist.exists()}")
print(f"Manifest.db:    {manifest_db.exists()}")

# Try to read Info.plist
if info_plist.exists():
    print("\n" + "="*60)
    print("Info.plist contents:")
    try:
        with open(info_plist, 'rb') as f:
            info = plistlib.load(f)
            for key, value in sorted(info.items()):
                if isinstance(value, bytes):
                    print(f"  {key}: <binary data>")
                else:
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"  Error reading: {e}")

# Check if encrypted
if manifest_plist.exists():
    print("\n" + "="*60)
    print("Manifest.plist encryption check:")
    try:
        with open(manifest_plist, 'rb') as f:
            manifest = plistlib.load(f)
            is_encrypted = manifest.get("IsEncrypted", False)
            print(f"  IsEncrypted: {is_encrypted}")
            if is_encrypted:
                print("\n  ⚠️  BACKUP IS ENCRYPTED")
                print("  You need to create an unencrypted backup to analyze:")
                print("  1. Connect iPhone to Mac")
                print("  2. Open Finder")
                print("  3. Select iPhone")
                print("  4. UNCHECK 'Encrypt local backup'")
                print("  5. Click 'Back Up Now'")
    except Exception as e:
        print(f"  Error reading: {e}")
