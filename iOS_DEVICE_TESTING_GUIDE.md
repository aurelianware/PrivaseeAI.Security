# Testing PrivaseeAI.Security Against Actual iOS Devices

## Overview

You have **two main approaches** for testing with real iOS devices:

1. **Live Log Monitoring** - Monitor VPN logs in real-time as they're generated
2. **iOS Backup Analysis** - Analyze device backups for profiles, configurations, and historical data

---

## Approach 1: Live VPN Log Monitoring (Recommended First)

This is the **fastest way** to see your system working with real data.

### Step 1: Connect iOS Device & Enable Logging

#### Option A: WireGuard on iOS (If using WireGuard directly)

```bash
# WireGuard logs are typically accessed via:
# 1. Settings > WireGuard > [Your Connection] > Export Log File

# Or programmatically through iOS device connection:
# Note: Requires device connected via USB and iTunes/Finder
```

#### Option B: ProtonVPN on iOS

**Enable Debug Logging:**
1. Open ProtonVPN app on iPhone
2. Go to Settings → Advanced → Diagnostics
3. Enable "Debug Logging"
4. Reproduce VPN activity
5. Export logs via Settings → Advanced → Export Logs

**Access logs on Mac:**
```bash
# If you sync iPhone with Mac, logs may be in:
~/Library/Logs/ProtonVPN/
~/Library/Application Support/ProtonVPN/

# Or connect via USB and use Console.app (see below)
```

### Step 2: Access iOS Device Logs via Console.app (macOS)

This is the **most reliable method** for real-time iOS log monitoring:

```bash
# 1. Connect iPhone to Mac via USB/Lightning cable
# 2. Trust the computer on iPhone when prompted
# 3. Open Console.app on Mac (/Applications/Utilities/Console.app)
```

**In Console.app:**

1. **Select your iPhone** in left sidebar (under "Devices")
2. **Apply filters** to see VPN-related logs:
   - Filter for: `WireGuard` or `ProtonVPN` or `VPN` or `NetworkExtension`
3. **Start streaming** - Click "Start" button
4. **Use your VPN** on iPhone - connect/disconnect, browse
5. **Watch logs appear** in real-time

**Export logs for analysis:**
- Select logs → Right-click → "Save Selected Messages"
- Save to a file (e.g., `ios_vpn_logs_2026-01-26.txt`)

### Step 3: Point PrivaseeAI to iOS Logs

#### Method A: Export & Monitor File

```bash
# Save Console.app logs to a directory
mkdir -p ~/ios_device_logs

# Configure PrivaseeAI to monitor this directory
cat >> .env << 'EOF'
VPN_LOG_DIR=~/ios_device_logs
WATCH_INTERVAL=2
EOF

# Start monitoring
python -m privaseeai_security
```

**In another terminal, continuously export logs:**
```bash
# This requires keeping Console.app open and manually exporting
# Or use this script to continuously copy new logs
```

#### Method B: Real-time Log Streaming (Advanced)

Use `libimobiledevice` to stream logs directly:

```bash
# Install libimobiledevice (if not already installed)
brew install libimobiledevice

# Stream device logs to file
idevicesyslog > ~/ios_device_logs/live.log &

# Filter for VPN logs only
idevicesyslog | grep -i "wireguard\|protonvpn\|vpn" > ~/ios_device_logs/vpn_live.log &
```

**Configure PrivaseeAI to monitor live stream:**
```bash
cat >> .env << 'EOF'
VPN_LOG_DIR=~/ios_device_logs
WATCH_INTERVAL=1
EOF

# Start monitoring
python -m privaseeai_security
```

### Step 4: Generate Test Traffic

**On your iPhone:**

1. **Connect to VPN** (ProtonVPN or WireGuard)
2. **Perform normal browsing** for 5-10 minutes
3. **Manually switch servers** 3-4 times (triggers server hopping detection)
4. **Force reconnections** - toggle VPN off/on
5. **Use location services** - open Maps, Weather, etc.

**Expected detections:**

- If UDP is blocked: `TRANSPORT_MANIPULATION` alert
- If API calls are excessive: `API_TRACKING` alert
- If you switch servers rapidly: `FORCED_RECONNECTION` alert

### Step 5: Verify Detections

```bash
# Watch PrivaseeAI output
tail -f logs/privaseeai_security.log

# Expected output:
# 🟠 THREAT DETECTED: TRANSPORT_MANIPULATION (MEDIUM)
# 🔴 THREAT DETECTED: API_TRACKING (HIGH)
# 🟠 THREAT DETECTED: FORCED_RECONNECTION (MEDIUM)

# Check Telegram for alerts (if configured)
```

---

## Approach 2: iOS Backup Analysis

This analyzes **installed profiles, configurations, and persistence mechanisms**.

### Step 1: Create iOS Backup

#### Option A: Encrypted Backup (Recommended)

```bash
# Using Finder (macOS Catalina+)
# 1. Connect iPhone via USB
# 2. Open Finder
# 3. Select iPhone in sidebar
# 4. Check "Encrypt local backup"
# 5. Set password (remember it!)
# 6. Click "Back Up Now"

# Backup location:
# ~/Library/Application Support/MobileSync/Backup/

# Find your device backup
ls -la ~/Library/Application\ Support/MobileSync/Backup/
# Output: [DEVICE_ID]/
```

#### Option B: Unencrypted Backup

**Note:** Some data (like passwords, Health data) won't be included.

```bash
# Same as above but don't check "Encrypt local backup"
```

### Step 2: Configure PrivaseeAI for Backup Analysis

```bash
# Add to .env
cat >> .env << 'EOF'
BACKUP_DIRECTORY=~/Library/Application Support/MobileSync/Backup
ENABLE_BACKUP_MONITORING=true
BACKUP_SCAN_INTERVAL=3600
EOF
```

### Step 3: Analyze Backup for Threats

#### Manual Analysis (Quick Test)

Use the PrivaseeAI CLI to analyze existing backups:

```bash
# Scan all iOS backups
privasee scan

# Or specify a custom backup path
privasee scan --backup-path ~/Library/Application\ Support/iMazing/Backups
```

#### Automated Monitoring

```bash
# Start daemon with backup monitoring enabled
python -m privaseeai_security

# PrivaseeAI will:
# 1. Scan existing backups on startup
# 2. Monitor backup directory for changes
# 3. Analyze new backups automatically
# 4. Alert on suspicious profiles/configurations
```

### Step 4: Look for Persistence Indicators

**What to check in backups:**

1. **VPN Profiles** - Looking for:
   - Localhost routing (127.0.0.1 endpoints)
   - Unsigned or suspicious profiles
   - Profiles that weren't user-installed

2. **MDM Profiles** - Looking for:
   - Unauthorized management profiles
   - Unexpected remote management
   - Suspicious organizations

3. **Configuration Profiles** - Looking for:
   - eSIM profiles
   - Carrier bundles
   - DNS configurations

4. **Persistence Across Resets** - Looking for:
   - Files/profiles that survive factory reset
   - Automatic reinstallation mechanisms

**Note:** Full backup analysis requires the **Carrier Compromise Detector** (Week 2-3 enhancement).

---

## Approach 3: Combined Live + Backup Monitoring (Most Comprehensive)

This gives you **complete coverage**:

### Configuration

```bash
cat > .env << 'EOF'
# Live VPN Log Monitoring
VPN_LOG_DIR=~/ios_device_logs
WATCH_INTERVAL=2

# iOS Backup Analysis
BACKUP_DIRECTORY=~/Library/Application Support/MobileSync/Backup
ENABLE_BACKUP_MONITORING=true
BACKUP_SCAN_INTERVAL=3600

# Alert Configuration
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID=your_chat_id

# Enable all monitors
ENABLE_VPN_MONITORING=true
ENABLE_API_ABUSE_MONITORING=true
ENABLE_CERTIFICATE_VALIDATION=true
ENABLE_BACKUP_MONITORING=true

# VPN Settings (your known-good values)
VPN_PROVIDER=protonvpn
EXPECTED_TRANSPORT=udp
TRUSTED_CERT_FINGERPRINT=6a1e93785520dade
EOF
```

### Workflow

1. **Connect iPhone via USB**
2. **Start log streaming**:
   ```bash
   idevicesyslog | grep -i "vpn" > ~/ios_device_logs/live.log &
   ```
3. **Start PrivaseeAI daemon**:
   ```bash
   python -m privaseeai_security
   ```
4. **Use iPhone normally** for 1-2 hours
5. **Create backup** (Finder → Back Up Now)
6. **Monitor alerts** on Telegram

---

## Testing Scenarios

### Scenario 1: Detect TCP Fallback

**Test Steps:**
1. Connect iPhone to Mac via USB
2. Start Console.app, filter for "WireGuard"
3. Connect to VPN on iPhone
4. Watch for "socketType value: tcp" in logs
5. Export logs and feed to PrivaseeAI

**Expected Result:**
```
🟠 THREAT DETECTED: TRANSPORT_MANIPULATION
Severity: MEDIUM
Indicators: ['UDP_BLOCKED', 'TCP_FALLBACK']
Details: WireGuard forced to use TCP instead of UDP
```

### Scenario 2: Detect API Rate Limiting

**Test Steps:**
1. Use ProtonVPN app with debug logging enabled
2. Open multiple location-based apps (Maps, Weather, etc.)
3. Force VPN reconnections several times
4. Export ProtonVPN logs
5. Feed to PrivaseeAI

**Expected Result:**
```
🔴 THREAT DETECTED: API_TRACKING
Severity: HIGH
Indicators: ['RATE_LIMIT', 'LOCATION_API']
Details: API rate limited - possible location tracking attempt
```

### Scenario 3: Detect Server Hopping

**Test Steps:**
1. Connect to VPN server 1
2. Browse for 1 minute
3. Switch to server 2
4. Browse for 1 minute
5. Repeat for servers 3 and 4 within 10 minutes

**Expected Result:**
```
🟠 THREAT DETECTED: FORCED_RECONNECTION
Severity: MEDIUM
Indicators: ['RAPID_SWITCHING', 'CONNECTION_DISRUPTION']
Details: 4 different servers in 7 minutes
```

### Scenario 4: Validate Certificate

**Test Steps:**
1. Connect to legitimate ProtonVPN server
2. Check certificate in logs
3. PrivaseeAI should validate against known-good cert

**Expected Result:**
```
✅ Certificate validated: 6a1e93785520dade
Threat Level: NONE
Status: Legitimate ProtonVPN connection
```

---

## Troubleshooting

### Issue: Can't see iPhone logs in Console.app

**Solutions:**
```bash
# 1. Check device is trusted
idevice_id -l
# Should show your device UDID

# 2. Check device connection
ideviceinfo
# Should show device details

# 3. Restart Console.app and device
# 4. Try different USB cable/port
```

### Issue: libimobiledevice not working

**Solutions:**
```bash
# Reinstall libimobiledevice
brew uninstall libimobiledevice
brew install --HEAD libimobiledevice

# Check usbmuxd is running
brew services list | grep usbmux

# Restart services
brew services restart usbmuxd
```

### Issue: Backup is encrypted and password unknown

**Solutions:**
```bash
# 1. Create new unencrypted backup
#    Finder → Uncheck "Encrypt local backup"

# 2. Or provide password to PrivaseeAI
#    (Requires pymobiledevice3 configuration)

# 3. Use ibackupbot or similar tools to decrypt
#    (Not recommended - use native tools)
```

### Issue: No logs appearing in monitored directory

**Solutions:**
```bash
# 1. Verify file watcher is working
python3 << 'EOF'
from src.privaseeai_security.file_watcher import FileWatcher
watcher = FileWatcher(["~/ios_device_logs"], interval=2)
print("Watching:", watcher.paths)
watcher.start()
import time
time.sleep(10)
watcher.stop()
EOF

# 2. Check file permissions
ls -la ~/ios_device_logs

# 3. Manually test log processing
python3 << 'EOF'
from src.privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor
monitor = VPNIntegrityMonitor()
log_line = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
threat = monitor.analyze_log_entry(log_line, log_type="wireguard")
if threat:
    print(f"✅ Detection working: {threat.attack_type}")
EOF
```

---

## Advanced: Continuous iOS Device Monitoring

### Set Up Persistent Log Collection

Create a LaunchAgent to continuously collect iOS logs:

```bash
cat > ~/Library/LaunchAgents/com.privaseeai.ioscollector.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.privaseeai.ioscollector</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/idevicesyslog</string>
    </array>
    <key>StandardOutPath</key>
    <string>/Users/mark/ios_device_logs/continuous.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/mark/ios_device_logs/collector-error.log</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Load the agent
launchctl load ~/Library/LaunchAgents/com.privaseeai.ioscollector.plist

# Logs will continuously stream to ~/ios_device_logs/continuous.log
# PrivaseeAI will monitor this file automatically
```

---

## Quick Start: Test Right Now (5 Minutes)

**Fastest way to see it working:**

```bash
# 1. Connect iPhone via USB
# 2. Open Terminal

# Start log streaming
mkdir -p ~/ios_device_logs
idevicesyslog | grep -i "vpn\|wireguard\|proton" > ~/ios_device_logs/test.log &

# 3. Use VPN on iPhone for 2-3 minutes

# 4. Stop streaming (after 2-3 minutes)
killall idevicesyslog

# 5. Analyze the collected logs
python3 << 'EOF'
from pathlib import Path
from src.privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor

monitor = VPNIntegrityMonitor()
log_file = Path.home() / "ios_device_logs" / "test.log"

threats_found = []
with open(log_file, 'r') as f:
    for line in f:
        threat = monitor.analyze_log_entry(line, log_type="wireguard")
        if threat and threat not in threats_found:
            threats_found.append(threat)
            print(f"\n🚨 THREAT: {threat.attack_type}")
            print(f"   Level: {threat.threat_level}")
            print(f"   Indicators: {threat.indicators}")

if not threats_found:
    print("\n✅ No threats detected (or logs don't contain VPN data)")
    print("   Try using VPN more actively and check log format")
EOF
```

---

## Summary: Recommended Testing Flow

### Phase 1: Quick Test (Today - 15 minutes)
1. Connect iPhone via USB
2. Stream logs with `idevicesyslog`
3. Use VPN for a few minutes
4. Analyze collected logs manually

### Phase 2: Live Monitoring (Tomorrow - 30 minutes)
1. Set up continuous log collection
2. Configure PrivaseeAI to monitor logs
3. Start daemon
4. Test for 1-2 hours of normal usage

### Phase 3: Backup Analysis (Week 2 - After enhancement)
1. Create iOS backup
2. Enable backup monitoring
3. Scan for profiles and configurations
4. Track persistence mechanisms

### Phase 4: 24/7 Production (Week 2+)
1. Deploy as LaunchAgent
2. Both log monitoring AND backup analysis
3. Telegram alerts for all threats
4. Continuous protection

---

## What You're Testing For

### ✅ Your Known Attacks:
1. **TCP Fallback** - Will appear in WireGuard logs
2. **API Rate Limiting** - Will appear in ProtonVPN logs
3. **Server Hopping** - Will appear in connection logs
4. **Certificate Issues** - Will appear in VPN logs

### ✅ New Potential Threats:
1. **Localhost Routing** - Will appear in backup profiles (Week 2)
2. **eSIM Manipulation** - Will appear in backup data (Week 2)
3. **DNS Tampering** - Will appear in network logs
4. **Persistence** - Will appear in backup comparison (Week 2)

---

## Next Steps

1. **Start with Phase 1** - Quick test right now
2. **Verify detection works** - See threats identified
3. **Move to Phase 2** - Live monitoring setup
4. **Wait for Week 2** - Full backup analysis

**You can test live VPN monitoring TODAY with what you've built!**

Questions about any specific testing scenario?
