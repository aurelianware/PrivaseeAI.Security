# Quick Start Guide - 5 Minutes to Protection

Get PrivaseeAI Security running and protect your iPhone in 5 minutes.

---

## ⚡ Super Quick Start

```bash
# 1. Clone and install (2 minutes)
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security
pip install -r requirements.txt
pip install -e .

# 2. Verify installation
privasee --version

# 3. Run your first scan
privasee scan

# 4. Start monitoring
privasee start
```

**That's it!** You're now monitoring your iPhone for threats.

---

## 🎯 What You Just Did

✅ **Installed** PrivaseeAI Security CLI  
✅ **Scanned** your existing iOS backups for threats  
✅ **Started** continuous monitoring (runs until you press Ctrl+C)  

The system is now:
- Checking for VPN manipulation every 60 seconds
- Scanning iOS backups for suspicious profiles
- Monitoring for API abuse and tracking attempts

---

## 🔔 Add Telegram Alerts (Optional - 3 minutes)

Get instant notifications when threats are detected:

### 1. Create Telegram Bot

1. Open Telegram, search `@BotFather`
2. Send: `/newbot`
3. Follow prompts, copy your bot token

### 2. Get Chat ID

1. Message your new bot (say "hello")
2. Visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
3. Find your `chat_id` in the response

### 3. Configure

```bash
# Add to ~/.zshrc or ~/.bashrc
echo 'export TELEGRAM_BOT_TOKEN="your_token_here"' >> ~/.zshrc
echo 'export TELEGRAM_CHAT_ID="your_chat_id_here"' >> ~/.zshrc

# Reload
source ~/.zshrc

# Verify
privasee config
```

Should show: `Telegram Configured: ✅ Yes`

---

## 📋 Common Commands

```bash
# Check configuration and system status
privasee config

# Scan iOS backups once
privasee scan

# Start continuous monitoring
privasee start

# Monitor with custom interval (seconds)
privasee start --interval 120

# Monitor without Telegram
privasee start --no-telegram

# Stop monitoring
# Press Ctrl+C in the terminal
```

---

## 🔍 What Gets Monitored

### Automatic (No iPhone Connection Required)
- **iOS Backups** - Scans `~/Library/Application Support/MobileSync/Backup`
- **Carrier Profiles** - Checks for suspicious MDM/configuration profiles
- **Backup Changes** - Monitors for new profiles appearing

### Optional (Advanced - iPhone Connected via USB)
- **Live VPN Logs** - Real-time WireGuard/ProtonVPN log analysis
- **Connection Patterns** - Detects forced reconnections and server hopping
- **API Calls** - Identifies rate limiting and tracking attempts

For live monitoring setup, see [iOS_DEVICE_TESTING_GUIDE.md](iOS_DEVICE_TESTING_GUIDE.md)

---

## 🚨 Understanding Threats

When `privasee scan` or `privasee start` finds threats, you'll see:

```bash
Threats Detected:
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Severity  ┃ Type       ┃ Count   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━┩
│ CRITICAL  │ VPN_MITM   │ 0       │
│ HIGH      │ CARRIER    │ 2       │  ← Action needed!
│ MEDIUM    │ API_ABUSE  │ 1       │
└───────────┴────────────┴─────────┘
```

### What to Do

**🔴 CRITICAL** - Immediate action required
- Disconnect from network
- Review threat details
- Contact security expert

**🟠 HIGH** - Serious threat
- Review threat details in logs
- Consider switching VPN providers
- Check installed profiles on iPhone

**🟡 MEDIUM** - Suspicious activity
- Monitor the situation
- May be false positive
- Switch networks if persistent

**🟢 None/Clean** - All good!
- Keep monitoring
- Run periodic scans

---

## 🔧 Troubleshooting

### "privasee: command not found"

```bash
cd /path/to/PrivaseeAI.Security
pip install -e .
```

### "No backups found"

Create an iPhone backup:
1. Connect iPhone to Mac via USB
2. Open Finder
3. Select iPhone in sidebar
4. Click "Back Up Now"

Or specify custom path:
```bash
privasee scan --backup-path /path/to/backups
```

### Python version error

Requires Python 3.11+:
```bash
python3 --version  # Check version
brew install python@3.11  # Install if needed (macOS)
```

---

## 📚 Next Steps

### For Regular Users
1. ✅ Run `privasee scan` weekly
2. ✅ Set up Telegram alerts
3. ✅ Check logs occasionally

### For Advanced Users
4. 📖 Read [ORCHESTRATOR_GUIDE.md](ORCHESTRATOR_GUIDE.md) - Full CLI reference
5. 📖 Read [iOS_DEVICE_TESTING_GUIDE.md](iOS_DEVICE_TESTING_GUIDE.md) - Live monitoring setup
6. ⚙️ Set up as LaunchAgent for 24/7 monitoring
7. 🛠️ Customize via `config.yaml`

### For Developers
8. 📖 Read [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup
9. 🧪 Run tests: `pytest`
10. 📊 Check coverage: `pytest --cov`

---

## 🎉 You're Protected!

PrivaseeAI Security is now watching your iPhone for:
- VPN manipulation and forced protocol changes
- Suspicious carrier profiles and MDM configurations
- API abuse and location tracking attempts
- Certificate tampering and MITM attacks

**Keep it running** with `privasee start` for continuous protection, or run `privasee scan` periodically.

---

## 📞 Need Help?

- **Full Documentation**: [README.md](README.md)
- **CLI Reference**: [ORCHESTRATOR_GUIDE.md](ORCHESTRATOR_GUIDE.md)
- **User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
- **Report Issues**: [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
- **Security Concerns**: [SECURITY.md](SECURITY.md)
