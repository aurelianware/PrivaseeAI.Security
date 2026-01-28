# 🚀 Quick Installation & Usage - MVP v0.1.0

## What's New - Real-Time Orchestration System

Your PrivaseeAI Security system now has a **central orchestrator** and **CLI interface** that brings all monitors together into a working protection system!

---

## Installation (2 minutes)

### 1. Install Dependencies

```bash
cd /Users/karkusdog/git/PrivaseeAI.Security

# Install Python dependencies
pip install -r requirements.txt

# Install in development mode with CLI command
pip install -e .
```

### 2. Verify Installation

```bash
# The 'privasee' command should now be available
privasee --version

# Check configuration
privasee config
```

---

## Usage

### Start Real-Time Monitoring

```bash
# Start continuous monitoring (runs until Ctrl+C)
privasee start

# With custom interval (seconds between checks)
privasee start --interval 60

# Disable Telegram alerts
privasee start --no-telegram

# Custom backup path
privasee start --backup-path ~/Library/Application\ Support/iMazing/Backups
```

**What it does:**
- Runs all 3 monitors concurrently (VPN, API, Carrier)
- Performs initial backup scan on startup
- Aggregates threats from all sources
- Sends Telegram alerts for CRITICAL/HIGH threats
- Logs all detections
- Shows periodic threat summaries

**Output:**
```
┌─────────────────────────────────────┐
│    PrivaseeAI Security              │
│ 🛡️  iOS Threat Detection & Monitoring │
└─────────────────────────────────────┘

🚀 Starting PrivaseeAI Security Orchestrator
Running initial backup scan...
Initial scan complete: 3 carrier threats found

✅ Monitoring started successfully
Press Ctrl+C to stop
```

### Run One-Time Scan

```bash
# Quick security scan without continuous monitoring
privasee scan

# Verbose output with details
privasee scan --verbose
```

**Output:**
```
🔍 Running security scan...

✅ Scan complete

┌──────────── 🚨 Threat Summary ────────────┐
│ Severity  │ Count │ Indicator │
├───────────┼───────┼───────────┤
│ CRITICAL  │   1   │    🚨     │
│ HIGH      │   2   │    🔴     │
│ MEDIUM    │   0   │    —      │
│ LOW       │   1   │    🟡     │
└───────────┴───────┴───────────┘

Threats by Source:
  • Carrier: 4

Total Threats: 4
```

### Check Configuration

```bash
privasee config
```

Shows:
- Auto-detected backup path
- Whether backups exist
- Telegram configuration status
- Default monitoring settings

### View Status (placeholder)

```bash
privasee status
```

*Note: Full status monitoring requires a daemon - coming in next iteration*

### View Alerts (placeholder)

```bash
privasee alerts
privasee alerts --count 50
```

*Note: Alert history requires database - coming in next iteration*

---

## Configuration

### Environment Variables

```bash
# Required for Telegram alerts
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"
```

### Configuration File (Optional)

Copy the example config:

```bash
cp config.yaml.example ~/.config/privaseeai/config.yaml
```

Edit the file to customize:
- Monitoring intervals
- Alert thresholds
- Backup paths
- Telegram settings

---

## Testing It Out

### 1. Quick Test (no iPhone needed)

```bash
# Check if CLI works
privasee config

# Run scan (will scan any existing backups)
privasee scan
```

### 2. With iPhone

```bash
# 1. Connect iPhone via USB
# 2. Trust the computer
# 3. Create a backup (Settings > General > Transfer or Reset iPhone > Backup)

# 4. Start monitoring
privasee start
```

### 3. Test Telegram Alerts

```bash
# Set up Telegram first
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."

# Start with Telegram enabled
privasee start

# Any CRITICAL or HIGH threats will send Telegram alerts
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                 CLI (cli.py)                     │
│  Commands: start, scan, status, alerts, config  │
└───────────────────┬─────────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │   Orchestrator      │
         │  (orchestrator.py)  │
         │                     │
         │  Runs concurrently: │
         └──────────┬──────────┘
                    │
      ┌─────────────┼─────────────┐
      │             │             │
┌─────▼────┐  ┌────▼─────┐  ┌───▼──────┐
│   VPN    │  │   API    │  │ Carrier  │
│ Monitor  │  │ Monitor  │  │ Monitor  │
└─────┬────┘  └────┬─────┘  └───┬──────┘
      │            │            │
      └────────────┴────────────┘
                   │
          ┌────────▼────────┐
          │ Telegram Alerter│
          └─────────────────┘
```

---

## What Works Now (MVP v0.1.0)

✅ **CLI Commands**: `start`, `scan`, `config`  
✅ **Concurrent Monitoring**: All 3 monitors run together  
✅ **Threat Aggregation**: Threats from all sources collected  
✅ **Telegram Alerts**: CRITICAL/HIGH threats trigger alerts  
✅ **Rich Console Output**: Pretty tables and status  
✅ **Graceful Shutdown**: Ctrl+C stops cleanly  
✅ **Auto-detection**: Finds iOS backups automatically  
✅ **Deduplication**: Same threat not reported multiple times  

---

## What's Next

🔄 **Persistent Daemon**: Run as background service  
🔄 **Real-time Status**: Check running monitors via CLI  
🔄 **Threat Database**: Store and query threat history  
🔄 **Live Log Tailing**: Monitor iOS syslog in real-time  
🔄 **Web Dashboard**: View threats in browser  

---

## Troubleshooting

### "privasee: command not found"

```bash
# Reinstall in development mode
pip install -e .

# Or run directly
python -m privaseeai_security start
```

### "Backup path not found"

```bash
# Specify path manually
privasee start --backup-path ~/path/to/backups

# Or check auto-detected path
privasee config
```

### "No threats detected"

This is good! It means:
- Your backups don't show carrier compromise
- No malicious eSIM profiles found
- System is clean

To test with known-bad data, use test fixtures:
```bash
# Point to test fixtures
privasee scan --backup-path tests/fixtures/ios_backups
```

---

## Example Session

```bash
$ privasee config
┌─────────────────────────────────────────┐
│            Configuration                │
├──────────────────┬──────────────────────┤
│ Backup Path      │ ~/Library/Applicat...│
│ Backup Path Ex...│ ✅ Yes               │
│ Default Interval │ 30 seconds           │
│ Telegram Config..│ ✅ Yes               │
└──────────────────┴──────────────────────┘

$ privasee scan
🔍 Running security scan...

✅ Scan complete

No threats detected

$ privasee start
┌─────────────────────────────────────┐
│    PrivaseeAI Security              │
│ 🛡️  iOS Threat Detection & Monitoring │
└─────────────────────────────────────┘

🚀 Starting PrivaseeAI Security Orchestrator
Running initial backup scan...
Initial scan complete: 0 carrier threats found

✅ Monitoring started successfully
Press Ctrl+C to stop

^C
Stopping...
✅ Stopped
```

---

## Ready to Use!

Your MVP orchestration system is complete and ready to protect your iPhone! 🛡️

**Next Step**: Run `privasee start` and let it monitor your device.
