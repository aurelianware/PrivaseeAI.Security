# VPN Monitor Daemon - 24/7 Security Monitoring

Real-time monitoring daemon that watches VPN logs for security threats and sends instant alerts.

## Features

✅ **Continuous Monitoring** - Scans VPN logs every 10 seconds for new threats  
✅ **Real-time Alerts** - Telegram notifications for HIGH and CRITICAL threats  
✅ **Auto-Start** - Runs automatically on macOS boot via LaunchAgent  
✅ **Attack Detection** - Detects TCP fallback, API abuse, server hopping  
✅ **Low Resource Usage** - Efficient tail-based log reading  

## Quick Start

### 1. Test the Daemon

```bash
./vpn_monitor_control.sh test
```

This runs a single scan to verify everything works.

### 2. Install for 24/7 Monitoring

```bash
./vpn_monitor_control.sh install
```

The daemon will now:
- Start immediately
- Auto-start on system boot
- Monitor logs continuously
- Write alerts to `/tmp/vpn_monitor_alerts.txt`

### 3. (Optional) Enable Telegram Alerts

1. **Create a Telegram Bot:**
   - Open Telegram, search for `@BotFather`
   - Send `/newbot` and follow prompts
   - Copy your bot token (looks like `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`)

2. **Get Your Chat ID:**
   - Send a message to your bot
   - Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Find your `chat_id` in the JSON response

3. **Update LaunchAgent:**
   Edit `com.privaseeai.vpnmonitor.plist` and add before `</array>`:
   ```xml
   <string>--telegram-token</string>
   <string>YOUR_BOT_TOKEN</string>
   <string>--telegram-chat-id</string>
   <string>YOUR_CHAT_ID</string>
   ```

4. **Restart Daemon:**
   ```bash
   ./vpn_monitor_control.sh restart
   ```

## Management Commands

```bash
./vpn_monitor_control.sh <command>
```

| Command | Description |
|---------|-------------|
| `install` | Install and start the daemon |
| `uninstall` | Stop and remove the daemon |
| `start` | Start the daemon |
| `stop` | Stop the daemon |
| `restart` | Restart the daemon |
| `status` | Check if daemon is running |
| `logs` | Show live daemon logs |
| `alerts` | Show recent alerts |
| `test` | Run a test scan |

## Monitoring

### View Live Logs
```bash
./vpn_monitor_control.sh logs
```

### View Recent Alerts
```bash
./vpn_monitor_control.sh alerts
```

### Check Status
```bash
./vpn_monitor_control.sh status
```

## Log Files

- **Daemon Log:** `/tmp/vpn_monitor_daemon.log` - All daemon activity
- **Alerts:** `/tmp/vpn_monitor_alerts.txt` - Detected threats
- **stdout:** `/tmp/vpn_monitor_stdout.log` - Standard output
- **stderr:** `/tmp/vpn_monitor_stderr.log` - Error output

## What Gets Monitored?

The daemon watches these directories for VPN logs:
- `~/Library/Logs/` - macOS system logs
- Project directory - Your downloaded VPN logs

It detects:
- **TCP Fallback** - VPN forced to use TCP (indicates UDP blocking)
- **API Rate Limiting** - Excessive API calls (tracking attempts)
- **Server Hopping** - Rapid reconnections (forced disconnects)
- **Certificate Issues** - Unknown or suspicious certificates

## Alert Levels

- 🔴 **CRITICAL** - Immediate action required (MITM attack, malicious config)
- 🟠 **HIGH** - Serious threat (API tracking, forced protocol changes)
- 🟡 **MEDIUM** - Suspicious activity (server hopping, connection issues)
- 🔵 **LOW** - Informational (unsigned profiles, minor issues)

## Troubleshooting

### Daemon won't start
```bash
# Check logs
./vpn_monitor_control.sh logs

# Verify plist syntax
plutil com.privaseeai.vpnmonitor.plist
```

### No threats detected
- Make sure VPN logs exist in monitored directories
- Run test mode to verify: `./vpn_monitor_control.sh test`
- Check log file paths in the plist

### Telegram not working
- Verify bot token and chat ID are correct
- Test manually: `curl https://api.telegram.org/bot<TOKEN>/getMe`
- Check daemon logs for error messages

## Uninstall

```bash
./vpn_monitor_control.sh uninstall
```

This removes the daemon completely while preserving alert logs.

## Technical Details

- **Language:** Python 3.11+
- **Dependencies:** PrivaseeAI.Security monitoring modules
- **Launch Method:** macOS LaunchAgent
- **Scan Interval:** 10 seconds (configurable)
- **Resource Usage:** ~5-10MB RAM, negligible CPU

## Security

The daemon:
- ✅ Runs with user permissions (not root)
- ✅ Only reads log files
- ✅ Stores alerts locally
- ✅ Optional Telegram (you control the bot)
- ✅ No external dependencies beyond logs

---

**Questions?** Check the main [README.md](README.md) or open an issue.
