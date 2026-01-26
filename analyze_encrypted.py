#!/usr/bin/env python3
"""Analyze encrypted iPhone backup metadata."""

from pathlib import Path
import plistlib
import sqlite3
from datetime import datetime

backup_base = Path.home() / "Library/Application Support/MobileSync/Backup"

print("=" * 60)
print("Encrypted Backup Analyzer")
print("=" * 60)

# Find all backups
backups = [d for d in backup_base.glob("*/") if d.is_dir()]
print(f"\nFound {len(backups)} backup directories\n")

for backup_dir in sorted(backups, key=lambda x: x.stat().st_mtime, reverse=True):
    print("=" * 60)
    print(f"Backup: {backup_dir.name}")
    print(f"Modified: {datetime.fromtimestamp(backup_dir.stat().st_mtime)}")
    print("-" * 60)
    
    info_plist = backup_dir / "Info.plist"
    manifest_plist = backup_dir / "Manifest.plist"
    manifest_db = backup_dir / "Manifest.db"
    status_plist = backup_dir / "Status.plist"
    
    # Check what files exist
    print(f"Info.plist:     {'✅' if info_plist.exists() else '❌'}")
    print(f"Manifest.plist: {'✅' if manifest_plist.exists() else '❌'}")
    print(f"Manifest.db:    {'✅' if manifest_db.exists() else '❌'}")
    print(f"Status.plist:   {'✅' if status_plist.exists() else '❌'}")
    
    # Read Info.plist (always readable, even if encrypted)
    if info_plist.exists():
        print("\n📋 Device Information (from Info.plist):")
        try:
            with open(info_plist, 'rb') as f:
                info = plistlib.load(f)
                
            print(f"  Device Name:      {info.get('Device Name', 'Unknown')}")
            print(f"  Product Type:     {info.get('Product Type', 'Unknown')}")
            print(f"  Product Version:  {info.get('Product Version', 'Unknown')}")
            print(f"  Build Version:    {info.get('Build Version', 'Unknown')}")
            print(f"  Serial Number:    {info.get('Serial Number', 'Unknown')}")
            print(f"  Phone Number:     {info.get('Phone Number', 'Not available')}")
            print(f"  IMEI:             {info.get('IMEI', 'Not available')}")
            
            # Display name and Unique Identifier
            if 'Display Name' in info:
                print(f"  Display Name:     {info['Display Name']}")
            if 'Unique Identifier' in info:
                print(f"  Device ID:        {info['Unique Identifier']}")
            
            # Last backup date
            if 'Last Backup Date' in info:
                print(f"  Last Backup:      {info['Last Backup Date']}")
                
        except Exception as e:
            print(f"  ❌ Error reading Info.plist: {e}")
    
    # Read Manifest.plist (check encryption status)
    if manifest_plist.exists():
        print("\n🔒 Backup Status (from Manifest.plist):")
        try:
            with open(manifest_plist, 'rb') as f:
                manifest = plistlib.load(f)
            
            is_encrypted = manifest.get("IsEncrypted", False)
            print(f"  Encrypted:        {'🔐 YES' if is_encrypted else '✅ NO'}")
            
            if 'Date' in manifest:
                print(f"  Backup Date:      {manifest['Date']}")
            
            if 'BackupKeyBag' in manifest:
                print(f"  Has Key Bag:      ✅ (needed for decryption)")
            
            # Show what we can/can't access
            if is_encrypted:
                print("\n  ⚠️  ENCRYPTED - Limited Access:")
                print("    ✅ Device info (readable)")
                print("    ❌ App data (encrypted)")
                print("    ❌ VPN profiles (encrypted)")
                print("    ❌ MDM profiles (encrypted)")
                print("    ❌ Network configs (encrypted)")
                print("    ℹ️  Need password + pymobiledevice3 to decrypt")
            else:
                print("\n  ✅ UNENCRYPTED - Full Access:")
                print("    ✅ Device info")
                print("    ✅ App data")
                print("    ✅ VPN profiles")
                print("    ✅ MDM profiles")
                print("    ✅ Network configs")
                
        except Exception as e:
            print(f"  ❌ Error reading Manifest.plist: {e}")
    
    # Try to check Manifest.db (won't work if encrypted)
    if manifest_db.exists():
        print("\n💾 Manifest Database:")
        try:
            conn = sqlite3.connect(str(manifest_db))
            cursor = conn.cursor()
            
            # Try to query (will fail if encrypted)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            if tables:
                print(f"  ✅ Readable - Found {len(tables)} table(s)")
                cursor.execute("SELECT COUNT(*) FROM Files")
                file_count = cursor.fetchone()[0]
                print(f"  Files tracked:    {file_count}")
            else:
                print("  ⚠️  Database exists but no tables found")
                
            conn.close()
            
        except Exception as e:
            print(f"  🔐 Encrypted - Cannot read without password")
            print(f"     Error: {str(e)[:50]}...")
    
    print()

print("=" * 60)
print("\n💡 TIP: For full analysis, create an unencrypted backup:")
print("   Finder → Select iPhone → Uncheck 'Encrypt local backup'")
print("   → Click 'Back Up Now'")
print("=" * 60)
