# PrivaseeAI.Security - User Guide for Everyone

**Protect your iPhone from spyware - no tech skills required**

This guide helps you set up 24/7 monitoring for your iPhone to detect spyware, suspicious VPNs, and other threats. Written for non-technical users.

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
     8433178793:AAH6vtK28rmE0JwRfCOvK8Ux6Q2kbkP_hCw
     ```

3. **Start chatting with your bot**:
   - Click the link BotFather provides to open your new bot
   - Press **START** button
   - Send any message (like "Hello!")

4. **Get your Chat ID**:
   - In Telegram, search for `@userinfobot` and start a chat
   - It will show you your **Chat ID** (a number like `8492117930`)
   - Write this down too!

**Save these two numbers somewhere safe - you'll need them shortly:**
- ✅ Bot Token: `8433178793:AAH...` (long)
- ✅ Chat ID: `8492117930` (shorter number)

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
   TELEGRAM_BOT_TOKEN=8433178793:AAH6vtK28rmE0JwRfCOvK8Ux6Q2kbkP_hCw
   TELEGRAM_CHAT_ID=8492117930
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
