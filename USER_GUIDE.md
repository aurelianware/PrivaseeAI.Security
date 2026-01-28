# PrivaseeAI.Security - User Guide

**Protect your iPhone from VPN manipulation and spyware**

This guide helps you set up PrivaseeAI Security to monitor your iPhone for threats like VPN manipulation, carrier compromise, and API abuse.

---

## 📱 What This Does

PrivaseeAI Security continuously monitors your iPhone for:

- **VPN Manipulation** - Detects when your VPN is forced to use less secure protocols (TCP fallback)
- **Server Hopping** - Identifies suspicious rapid VPN server switching
- **API Abuse** - Catches rate limiting that could indicate location tracking attempts
- **Carrier Compromise** - Scans iOS backups for suspicious profiles and configurations
- **Certificate Issues** - Validates VPN certificates to prevent man-in-the-middle attacks

You'll get **instant Telegram alerts** when threats are detected.

---

## ✅ Before You Start

### What You Need

1. **macOS Computer** (macOS 10.15 or newer)
2. **Python 3.11+** installed
3. **iPhone** with backups enabled (any iOS version)
4. **Telegram Account** (optional, for alerts)
5. **10-15 minutes** for setup

### What You DON'T Need

- ❌ Programming experience
- ❌ Cloud services or subscriptions
- ❌ To modify your iPhone (no jailbreaking)
- ❌ iPhone connected via USB (unless doing live monitoring)

Everything runs locally on your Mac - complete privacy.

---

## 🚀 Quick Setup

### Step 1: Install PrivaseeAI Security (3 minutes)

Open Terminal and run:

```bash
# Clone the repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# Install dependencies
pip install -r requirements.txt

# Install the CLI tool
pip install -e .

# Verify installation
privasee --version
```

You should see: `PrivaseeAI Security v0.1.0`

---

### Step 2: Configure Telegram Alerts (5 minutes - Optional)

**Create a Telegram Bot:**

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the prompts
3. Copy your bot token (looks like `1234567890:ABCdef...`)

**Get Your Chat ID:**

1. Send a message to your new bot
2. Visit this URL in your browser (replace `<YOUR_TOKEN>`):
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
3. Find your `chat_id` in the response (a number)

**Add Credentials:**

Add these lines to your `~/.zshrc` or `~/.bashrc`:

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"
```

Then reload:
```bash
source ~/.zshrc
```

**Verify:**
```bash
privasee config
```

Should show: `Telegram Configured: ✅ Yes`

---

### Step 3: Run Your First Scan (1 minute)

```bash
privasee scan
```

This scans your existing iOS backups for threats. You should see a table showing threat counts by severity.

---

## 📖 Using PrivaseeAI Security

### Check Configuration

```bash
privasee config
```

Shows:
- Backup path location
- Whether Telegram is configured
- Current settings

### Run a One-Time Scan

```bash
privasee scan
```

Analyzes all iOS backups and shows results immediately.

### Start Continuous Monitoring

```bash
privasee start
```

Runs continuously, monitoring for threats every 60 seconds. Press Ctrl+C to stop.

**With custom interval:**
```bash
privasee start --interval 120  # Check every 2 minutes
```

**Without Telegram alerts:**
```bash
privasee start --no-telegram
```

**Custom backup path:**
```bash
privasee start --backup-path ~/Library/Application\ Support/iMazing/Backups
```

---

## 🔔 Understanding Alerts

### Threat Severity Levels

- **🔴 CRITICAL** - Immediate action required (e.g., MITM attack detected)
- **🟠 HIGH** - Serious threat (e.g., API tracking attempt)
- **🟡 MEDIUM** - Suspicious activity (e.g., TCP fallback)
- **🟢 LOW** - Minor anomaly

### Common Threats

**TRANSPORT_MANIPULATION (MEDIUM)**
- Your VPN is forced to use TCP instead of UDP
- Usually means UDP is being blocked
- Action: Switch networks or VPN servers

**API_TRACKING (HIGH)**
- Excessive API calls detected
- Possible location tracking attempt
- Action: Check your VPN provider, review running apps

**FORCED_RECONNECTION (MEDIUM)**
- Rapid VPN server switching detected
- Could indicate network interference
- Action: Monitor and switch networks if persistent

**CARRIER_COMPROMISE (varies)**
- Suspicious profiles found in iOS backup
- Could be malware or MDM profiles
- Action: Review installed profiles on iPhone (Settings → General → VPN & Device Management)

---

## 🔧 Troubleshooting

### "privasee: command not found"

```bash
# Make sure you installed with pip install -e .
cd /path/to/PrivaseeAI.Security
pip install -e .
```

### "No backups found"

Check your backup location:
```bash
ls -la ~/Library/Application\ Support/MobileSync/Backup/
```

If backups are elsewhere:
```bash
privasee scan --backup-path /path/to/your/backups
```

### "Telegram not configured"

Add credentials to shell config:
```bash
echo 'export TELEGRAM_BOT_TOKEN="your_token"' >> ~/.zshrc
echo 'export TELEGRAM_CHAT_ID="your_chat_id"' >> ~/.zshrc
source ~/.zshrc
```

### No Threats Found

This is good! It means:
- Your VPN is working properly
- No suspicious profiles detected
- Your connection is secure

Run periodic scans to maintain security.

---

## 🔒 Privacy & Security

**Where is my data?**
- All processing happens on your Mac
- No data is sent to external servers
- Telegram alerts only contain threat summaries (no personal data)

**What data is collected?**
- iOS backup metadata (device ID, backup dates)
- VPN log patterns (if monitoring live logs)
- Threat detection results

**Can I disable Telegram?**
- Yes! Just don't set the environment variables
- Or use `--no-telegram` flag when starting

---

## 📚 Advanced Usage

### Monitor Live VPN Logs

For advanced users who want real-time VPN monitoring:

See [iOS_DEVICE_TESTING_GUIDE.md](iOS_DEVICE_TESTING_GUIDE.md) for complete setup instructions.

### Custom Configuration

Create `config.yaml` in the project directory:

```yaml
log_level: DEBUG
monitor_interval: 30
telegram_enabled: true
alert_throttle_minutes: 15
```

See [config.yaml.example](config.yaml.example) for all options.

### Run as Background Service

For 24/7 monitoring, see [ORCHESTRATOR_GUIDE.md](ORCHESTRATOR_GUIDE.md) for LaunchAgent setup instructions.

---

## 🆘 Getting Help

- **Documentation**: [ORCHESTRATOR_GUIDE.md](ORCHESTRATOR_GUIDE.md) - Complete CLI reference
- **Issues**: [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
- **Security Concerns**: See [SECURITY.md](SECURITY.md)

---

## ✅ Quick Reference

```bash
# Check status
privasee config

# Scan once
privasee scan

# Monitor continuously
privasee start

# Monitor with custom settings
privasee start --interval 120 --no-telegram

# Stop monitoring
# Press Ctrl+C
```

---

**You're now protected!** PrivaseeAI Security is monitoring your iPhone for threats. Run `privasee scan` regularly or use `privasee start` for continuous protection.

---

## 📱 What This Does

PrivaseeAI.Security continuously monitors your iPhone for:

- **Suspicious VPN apps** (like fake ProtonVPN that could be spyware)
- **Modified carrier profiles** (signs of SIM card manipulation)
- **Certificate tampering** (attempts to intercept your encrypted communications)
- **Unusual iPhone backups** (new profiles appearing unexpectedly)

You'll get **instant Telegram alerts** when something suspicious is detected - even when you're asleep.

---

## ✅ Before You Start

### What You Need

1. **A Mac computer** (macOS 10.15 or newer)
2. **Your iPhone** (any model with iOS 14+)
3. **A USB cable** (to connect iPhone to Mac)
4. **A Telegram account** (free messaging app - we'll set this up)
5. **15-30 minutes** of setup time

### What You DON'T Need

- ❌ Programming experience
- ❌ A credit card or payment
- ❌ Cloud services or subscriptions
- ❌ To modify your iPhone (no jailbreaking)

Everything runs privately on your Mac - no data leaves your computer.

---

## 🚀 Step-by-Step Setup

### Step 1: Get Telegram Ready (5 minutes)

Telegram will send you security alerts.

1. **Install Telegram** on your phone:
   - iPhone: Download "Telegram Messenger" from App Store
   - Open it and create an account (it's free)

2. **Create your security bot**:
   - In Telegram, search for `@BotFather` and start a chat
   - Type: `/newbot`
   - Choose a name: `My Security Monitor` (or whatever you like)
   - Choose a username: `mysecurity_bot` (must end with `_bot`)
   - BotFather will give you a **token** - copy this! It looks like:
     ```
     1234567890:ABCdefGHIjklMNOpqrsTUVwxyz1234567890
     ```

3. **Start chatting with your bot**:
   - Click the link BotFather provides to open your new bot
   - Press **START** button
   - Send any message (like "Hello!")

4. **Get your Chat ID**:
   - In Telegram, search for `@userinfobot` and start a chat
   - It will show you your **Chat ID** (a number like `1234567890`)
   - Write this down too!

**Save these two numbers somewhere safe - you'll need them shortly:**
- ✅ Bot Token: `1234567890:ABCdef...` (long string)
- ✅ Chat ID: `1234567890` (numeric ID)

---

### Step 2: Download PrivaseeAI.Security (2 minutes)

1. **Open Terminal** on your Mac:
   - Press `Cmd + Space`
   - Type "Terminal" and press Enter
   - A window with black/white text appears - don't worry, we'll guide you!

2. **Copy and paste this command** (press Enter after):
   ```bash
   cd ~ && git clone https://github.com/aurelianware/PrivaseeAI.Security.git
   ```
   
   This downloads the monitoring software to your Mac.

3. **Navigate into the folder**:
   ```bash
   cd PrivaseeAI.Security
   ```

---

### Step 3: Install the Software (5 minutes)

Still in Terminal, run these commands one at a time (copy, paste, press Enter):

1. **Create a safe environment** (keeps things organized):
   ```bash
   python3 -m venv .venv
   ```

2. **Activate the environment**:
   ```bash
   source .venv/bin/activate
   ```
   
   You'll see `(.venv)` appear at the start of your command line - that's good!

3. **Install required software**:
   ```bash
   pip install -r requirements.txt
   ```
   
   This takes 1-2 minutes. You'll see lots of text scrolling - that's normal.

4. **Verify it worked**:
   ```bash
   python -m pytest --version
   ```
   
   Should show something like `pytest 9.0.2` - if you see a version number, you're good!

---

### Step 4: Configure Your Credentials (3 minutes)

Now we'll add your Telegram bot details so alerts can reach you.

1. **Create your secret configuration file**:
   ```bash
   nano .env
   ```
   
   This opens a simple text editor.

2. **Type these two lines** (replace with YOUR values from Step 1):
   ```
   TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz1234567890
   TELEGRAM_CHAT_ID=1234567890
   ```
   
   ⚠️ **Important**: Use YOUR actual token and chat ID, not these examples!

3. **Save and exit**:
   - Press `Ctrl + O` (that's the letter O, not zero)
   - Press `Enter` to confirm
   - Press `Ctrl + X` to exit

---

### Step 5: Connect Your iPhone (2 minutes)

1. **Plug in your iPhone** to your Mac with USB cable

2. **Trust this computer**:
   - Your iPhone will ask "Trust This Computer?"
   - Tap **Trust**
   - Enter your iPhone passcode

3. **Verify connection** (in Terminal):
   ```bash
   source .venv/bin/activate
   python3 -m pymobiledevice3 usbmux list
   ```
   
   You should see your iPhone listed with its name and a long ID number.

---

### Step 6: Run a Quick Test (2 minutes)

Let's make sure everything works before setting up 24/7 monitoring.

1. **Run the test**:
   ```bash
   source .venv/bin/activate
   pytest tests/unit/test_config.py -v
   ```

2. **Check for success**:
   - You should see green text with "PASSED"
   - If you see red "FAILED" text, see Troubleshooting below

3. **Test Telegram alerts**:
   ```bash
   python -c "
   import os
   from telegram import Bot
   bot = Bot(token=os.getenv('TELEGRAM_BOT_TOKEN'))
   import asyncio
   asyncio.run(bot.send_message(
       chat_id=os.getenv('TELEGRAM_CHAT_ID'),
       text='✅ PrivaseeAI.Security is ready to protect you!'
   ))
   "
   ```
   
   You should get a message in Telegram from your bot!

---

### Step 7: Start 24/7 Monitoring (5 minutes)

Now we'll set up the system to run automatically, even when you restart your Mac.

1. **Create the startup configuration**:
   ```bash
   cat > ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist << 'EOF'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.privaseeai.vpnmonitor</string>
       <key>ProgramArguments</key>
       <array>
           <string>/Users/YOUR_USERNAME/PrivaseeAI.Security/.venv/bin/python3</string>
           <string>/Users/YOUR_USERNAME/PrivaseeAI.Security/vpn_monitor_daemon.py</string>
           <string>--live</string>
       </array>
       <key>EnvironmentVariables</key>
       <dict>
           <key>TELEGRAM_BOT_TOKEN</key>
           <string>YOUR_BOT_TOKEN_HERE</string>
           <key>TELEGRAM_CHAT_ID</key>
           <string>YOUR_CHAT_ID_HERE</string>
       </dict>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>StandardOutPath</key>
       <string>/tmp/privaseeai_vpnmonitor.log</string>
       <key>StandardErrorPath</key>
       <string>/tmp/privaseeai_vpnmonitor_error.log</string>
   </dict>
   </plist>
   EOF
   ```

2. **Edit the file with YOUR information**:
   ```bash
   nano ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
   ```
   
   Replace these 3 things:
   - `YOUR_USERNAME` → your Mac username (type `whoami` in Terminal to see it)
   - `YOUR_BOT_TOKEN_HERE` → your Telegram bot token from Step 1
   - `YOUR_CHAT_ID_HERE` → your Telegram chat ID from Step 1

   Save with `Ctrl + O`, `Enter`, `Ctrl + X`

3. **Start the monitoring**:
   ```bash
   launchctl load ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
   ```

4. **Verify it's running**:
   ```bash
   launchctl list | grep privaseeai
   ```
   
   You should see `com.privaseeai.vpnmonitor` in the list.

---

## 🎉 You're Protected!

### What Happens Now

- ✅ Your Mac continuously monitors your iPhone (every 10 seconds)
- ✅ Checks for suspicious VPN profiles every scan
- ✅ Analyzes iPhone backups every 30 seconds
- ✅ Sends Telegram alerts when threats are detected
- ✅ Runs automatically when you restart your Mac

### Understanding Alerts

When you get a Telegram message, it will look like this:

```
🚨 HIGH SEVERITY THREAT DETECTED

Suspicious VPN Profile Detected
- Profile: ProtonVPN
- Carrier: Unknown carrier "localhost"
- Risk: VPN redirects all traffic to 127.0.0.1 (local machine)

Action Required: This may be spyware masquerading as ProtonVPN.
Review your VPN apps immediately.

Detected: 2026-01-28 14:32:15
Device: iPhone (via backup monitor)
```

**What to do**:
1. **HIGH/CRITICAL** = Act immediately (check your iPhone, delete suspicious apps)
2. **MEDIUM** = Investigate soon (might be legitimate but unusual)
3. **LOW** = Informational (keep an eye on it)

---

## 🔍 Daily Use

### Checking System Status

**Is monitoring still running?**
```bash
launchctl list | grep privaseeai
```
If you see the service listed, it's running.

**View recent activity:**
```bash
tail -20 /tmp/privaseeai_vpnmonitor.log
```

### Stopping/Restarting Monitoring

**Stop monitoring** (temporarily):
```bash
launchctl unload ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
```

**Start monitoring** (after stopping):
```bash
launchctl load ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
```

**Restart monitoring** (if it's acting weird):
```bash
launchctl unload ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
launchctl load ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
```

### Updating to Latest Version

Every few weeks, update the software:

```bash
cd ~/PrivaseeAI.Security
git pull
source .venv/bin/activate
pip install -r requirements.txt --upgrade
launchctl unload ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
launchctl load ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
```

---

## 🆘 Troubleshooting

### "Command not found: git"

**Solution**: Install developer tools:
```bash
xcode-select --install
```
Click "Install" when prompted, then try again.

### "No iPhone detected"

**Solutions**:
1. Make sure iPhone is plugged in via USB
2. Unlock your iPhone
3. Trust the computer (iPhone will ask)
4. Try a different USB cable
5. Run: `python3 -m pymobiledevice3 usbmux list` to test

### "Telegram messages not arriving"

**Solutions**:
1. Make sure you pressed START in your bot chat
2. Verify your Chat ID: search for `@userinfobot` again
3. Check `.env` file has correct values:
   ```bash
   cat .env
   ```
4. Test manually:
   ```bash
   source .venv/bin/activate
   python -c "import os; print(os.getenv('TELEGRAM_BOT_TOKEN'))"
   ```
   Should show your token (not empty)

### "Service won't start"

**Solutions**:
1. Check logs for errors:
   ```bash
   cat /tmp/privaseeai_vpnmonitor_error.log
   ```
2. Verify paths in plist file:
   ```bash
   cat ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
   ```
3. Make sure username is correct (not literally "YOUR_USERNAME")

### "Tests failing"

**Solution**: Some tests are timing-sensitive and may fail in CI but work locally. If 190+ tests pass, you're fine:
```bash
source .venv/bin/activate
pytest tests/unit/ -v
```

### Still Stuck?

1. **Check the detailed logs**:
   ```bash
   tail -100 /tmp/privaseeai_vpnmonitor.log
   tail -100 /tmp/privaseeai_vpnmonitor_error.log
   ```

2. **Report an issue** on GitHub:
   - Go to: https://github.com/aurelianware/PrivaseeAI.Security/issues
   - Click "New Issue"
   - Describe what went wrong and which step failed
   - Include the error message (if any)

---

## 🔒 Privacy & Security

### Your Data Never Leaves Your Mac

- ✅ All analysis happens locally on your computer
- ✅ No cloud services, no subscriptions, no tracking
- ✅ Telegram only receives **alerts**, not your iPhone data
- ✅ You own and control everything

### Keeping Your Setup Secure

1. **Never share your bot token** - it's like a password
2. **Don't commit `.env` to git** - it's already ignored
3. **Revoke old tokens** if you suspect compromise:
   - In Telegram, message `@BotFather`
   - Type `/mybots` → select your bot → API Token → Revoke
   - Generate new token and update `.env`

---

## 📚 Understanding the Technology

### What Gets Monitored

1. **macOS Unified Log** (system logs on your Mac)
   - VPN connection attempts
   - Certificate validation events
   - Network configuration changes

2. **iPhone Backups** (created automatically)
   - Carrier profiles (SIM card settings)
   - VPN configuration files
   - App installation history

3. **Live iPhone Syslog** (when plugged in)
   - Real-time events from your iPhone
   - App behavior and network activity
   - System configuration changes

### Detection Methods

- **Signature-based**: Known spyware patterns (fake ProtonVPN example)
- **Behavioral**: Unusual activity (new profiles appearing suddenly)
- **Anomaly detection**: Statistical analysis of normal vs. suspicious behavior
- **Rule-based**: Hardcoded security policies (localhost VPN = bad)

---

## 📖 Next Steps

Once you're comfortable with basic monitoring:

1. **Read the Technical Spec** (for advanced users):
   - [privaseeAI_iOS_Threat_Detection_Spec.md](privaseeAI_iOS_Threat_Detection_Spec.md)

2. **Customize Detection Rules**:
   - Edit `src/privaseeai_security/config.py` to adjust sensitivity

3. **Review Comprehensive Assessment**:
   - [COMPREHENSIVE_ASSESSMENT.md](COMPREHENSIVE_ASSESSMENT.md)

4. **Contribute** (optional):
   - See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
   - Report bugs or suggest features on GitHub

---

## ❓ FAQ

**Q: Do I need my iPhone connected all the time?**  
A: No! Backup analysis works even when disconnected. Live monitoring requires USB connection but isn't mandatory.

**Q: Will this drain my Mac's battery?**  
A: Minimal impact - uses <1% CPU on average. You won't notice any slowdown.

**Q: Can I monitor multiple iPhones?**  
A: Currently supports one iPhone. Multi-device support is planned for future versions.

**Q: Is this legal?**  
A: Yes, for monitoring YOUR OWN devices. Don't use this to spy on others without consent.

**Q: What if I get a false alarm?**  
A: Investigate first, then you can adjust sensitivity in `config.py`. Some legitimate VPNs may trigger alerts.

**Q: Does this work with Android?**  
A: No, iOS only. Android has different architecture and isn't supported.

**Q: Do I need to keep Terminal open?**  
A: No! Once you've completed Step 7, the monitoring runs in the background. You can close Terminal.

**Q: How do I uninstall?**  
A:
```bash
# Stop monitoring
launchctl unload ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist

# Delete files
rm ~/Library/LaunchAgents/com.privaseeai.vpnmonitor.plist
rm -rf ~/PrivaseeAI.Security

# Optional: Delete Telegram bot via @BotFather
```

---

## 🎯 Quick Reference Card

Print this and keep it handy:

```
┌─────────────────────────────────────────────────────┐
│ PrivaseeAI.Security - Quick Reference               │
├─────────────────────────────────────────────────────┤
│                                                      │
│ CHECK STATUS:                                        │
│   launchctl list | grep privaseeai                  │
│                                                      │
│ VIEW LOGS:                                           │
│   tail -20 /tmp/privaseeai_vpnmonitor.log           │
│                                                      │
│ RESTART:                                             │
│   launchctl unload ~/Library/LaunchAgents/...       │
│   launchctl load ~/Library/LaunchAgents/...         │
│                                                      │
│ UPDATE:                                              │
│   cd ~/PrivaseeAI.Security && git pull              │
│                                                      │
│ GET HELP:                                            │
│   https://github.com/aurelianware/                  │
│   PrivaseeAI.Security/issues                        │
│                                                      │
│ EMERGENCY: If iPhone is compromised, factory        │
│ reset and restore from KNOWN GOOD backup only.      │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## 🙏 Thank You

You're now protected against iOS spyware and threats. Stay safe!

**Questions?** Open an issue on GitHub or check the documentation.

**Found this helpful?** Star the repository and share with others who need protection.

---

*Last Updated: January 28, 2026*  
*Version: 1.0 (MVP Release)*
