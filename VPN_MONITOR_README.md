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
- 🔵 **LOW** - Noise / low-risk pattern (NWPathMonitor storms, isExpensive flaps)
- ⚪ **INFO** - Neutral observation (TCP transport, API cooldown, user reconnect)

## Timeline Analysis (`privasee analyze`)

The timeline engine reasons about a whole WireGuard/Proton VPN session rather
than scoring individual lines, so normal iOS Network Extension churn is no longer
mistaken for an attack.

### Run it

```bash
# Human-readable timeline, metrics and judgments
privasee analyze path/to/WireGuard.log

# Show INFO/LOW judgments too (default shows only MEDIUM+)
privasee analyze path/to/WireGuard.log --verbose

# Machine-readable output
privasee analyze path/to/WireGuard.log --json

# Compare metrics against a known-good session
privasee analyze today.log --baseline yesterday.log
```

You can also run the standalone scanner without installing the CLI:

```bash
python scan_vpn_logs.py "WireGuard Logs (1).log"
python scan_vpn_logs.py proton_vpn.log --verbose
```

The command exits non-zero only when there is an actionable (MEDIUM or higher)
judgment, so it is safe to use in automation.

### Timestamp rule

**Event time always comes from the log line, never wall-clock time.** Every
`VpnLogEvent.ts` is parsed from the line's ISO-8601 prefix and normalised to
timezone-aware UTC. All time windows (path-storm bursts, DNS64 hopping, keepalive
asymmetry) are measured in *log* time, so a January log analysed in August still
uses January timestamps. Lines with no parseable timestamp prefix are skipped
(NWPath continuation lines are folded into the event that opened the block).

### Severity policy

Observations are recorded separately from judgments; judgments always carry a
`confidence` (0–1) and a list of benign `alternatives`.

| Log signal | Default | Escalates when |
|------------|---------|----------------|
| `socketType tcp` | INFO `TRANSPORT_TCP` | LOW only if TCP persists > 15 min with no later `udp` and no `userInitiated` stop |
| `socketType udp` | NONE (normal) | — |
| API `cooldown(...)` | INFO `API_COOLDOWN` | — (not scored as tracking here) |
| DNS64 IP change | INFO | MEDIUM at ≥ 4 unique IPs within 10 log-time minutes with no user reconnect |
| Certificate "seems up to date" | no threat | — |
| Unknown cert fingerprint | LOW | never HIGH; fingerprints < 32 hex chars are ignored |
| NWPathMonitor bumps | LOW `PATH_MONITOR_STORM` | > 60 bumps/hr, or 3+ in 60s while path stays satisfied |
| `isExpensive` flap | LOW `EXPENSIVE_FLAP` | only while path stays viable |
| Handshake gap near sleep/wake | INFO `SLEEP_HANDSHAKE_GAP` | expected on a locked iPhone |
| Peer change after user stop/start | INFO `PEER_SWITCH` | MEDIUM `UNEXPECTED_PEER_SWITCH` if no stop/start between |
| Keepalive send ≫ recv | LOW `KEEPALIVE_ASYMMETRY` | only with no sleep in the 10-min window |

The scanner prints "disconnect immediately / your network may be compromised"
**only** when there is a HIGH/CRITICAL judgment with confidence ≥ 0.7 — never for
ordinary Proton/iOS behaviour.

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
