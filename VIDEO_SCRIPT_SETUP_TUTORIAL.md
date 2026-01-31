# PrivaseeAI Security - 5-Minute Setup Tutorial
## Video Script

**Duration:** 5-6 minutes
**Target Audience:** Non-technical iPhone users
**Goal:** Get PrivaseeAI Security running and monitoring their device
**Format:** Screen recording with voiceover

---

## INTRO (0:00 - 0:30)

### [VISUAL]
- Fade in to macOS desktop
- Show iPhone 16 Pro connected via cable
- Title card: "Protect Your iPhone in 5 Minutes"

### [VOICEOVER]
"Hi, I'm Mark, and on January 26th, 2026, my iPhone was hacked at the carrier level. Three commercial security apps that cost me $120 per year completely missed it.

So I built something better. And today, I'm going to show you how to set up **PrivaseeAI Security** - a free, open-source tool that actually works - in just 5 minutes."

### [ON-SCREEN TEXT]
- "January 26, 2026: Real carrier-level attack"
- "3 paid apps failed"
- "So I built this (and it's free)"

---

## PREREQUISITES (0:30 - 1:00)

### [VISUAL]
- Split screen showing:
  - Left: macOS Sonoma desktop
  - Right: iPhone 16 Pro home screen

### [VOICEOVER]
"Before we start, here's what you need:

**First**, a Mac running macOS Ventura or newer. Sorry Windows users - iOS backups work best on Mac.

**Second**, an iPhone running iOS 14 or later. I'm using an iPhone 16 Pro on iOS 18.2, but any recent iPhone works.

**Third**, about 5 minutes of your time.

That's it. No technical skills required. Let's go."

### [ON-SCREEN CHECKLIST]
- ✅ Mac (macOS Ventura+)
- ✅ iPhone (iOS 14+)
- ✅ 5 minutes

---

## STEP 1: BACKUP YOUR IPHONE (1:00 - 2:00)

### [VISUAL]
- Connect iPhone to Mac via cable
- Open Finder
- Select iPhone in sidebar
- Click "Back Up Now"
- Show progress bar

### [VOICEOVER]
"**Step 1:** We need an iPhone backup to analyze. Connect your iPhone to your Mac with a cable.

Open Finder - you'll see your iPhone in the left sidebar under 'Locations'. Click on it.

Now, **important**: Make sure 'Encrypt local backup' is checked. This keeps your data secure. If you haven't set a backup password before, set one now. Don't forget it!

Click 'Back Up Now'. This takes about 2-5 minutes depending on how much data you have. While that's running, let's set up the software."

### [ON-SCREEN ANNOTATIONS]
- Arrow pointing to iPhone in Finder sidebar
- Red circle around "Encrypt local backup" checkbox
- Warning: "Set a backup password you'll remember!"

### [TIME SAVER TIP]
"Pro tip: You probably already have a recent backup. Check the 'Latest Backup' date. If it's from today or yesterday, you can skip this and use the existing one."

---

## STEP 2: INSTALL PYTHON (2:00 - 2:30)

### [VISUAL]
- Open Terminal application
- Type: `python3 --version`
- Show version output: Python 3.11.6

### [VOICEOVER]
"**Step 2:** We need Python installed. Don't worry - it's already on your Mac.

Open Terminal. You can find it by pressing **Command-Space**, typing 'terminal', and hitting Enter.

Type: `python3 --version` and press Enter.

If you see something like 'Python 3.11' or higher - you're good. If not, or if it says Python 2, go to python.org/downloads and install Python 3.11 or newer. Takes 2 minutes."

### [ON-SCREEN TEXT]
```
python3 --version
Python 3.11.6  ✅
```

### [TROUBLESHOOTING CALLOUT]
"Not working? Make sure you type 'python3' with a '3' - not just 'python'."

---

## STEP 3: DOWNLOAD & INSTALL PRIVASEEAI (2:30 - 3:30)

### [VISUAL]
- Open GitHub repository in browser
- Click green "Code" button
- Click "Download ZIP"
- Unzip in Downloads folder
- Terminal commands shown

### [VOICEOVER]
"**Step 3:** Let's grab the software. Open your browser and go to:

**github.com/aurelianware/PrivaseeAI.Security**

Click the green 'Code' button, then 'Download ZIP'.

Once it downloads, find it in your Downloads folder and double-click to unzip it.

Back in Terminal, let's navigate to the folder and install. Type these commands:"

### [ON-SCREEN COMMANDS]
```bash
# Navigate to the downloaded folder
cd ~/Downloads/PrivaseeAI.Security-main

# Install dependencies (takes 1-2 minutes)
pip3 install -r requirements.txt

# Install the package
pip3 install -e .
```

### [VOICEOVER CONTINUED]
"First command navigates to the folder. Second installs all the dependencies - this takes about 2 minutes. Third installs PrivaseeAI itself.

Don't worry about the output scrolling by. As long as you don't see RED error messages, you're fine."

### [VISUAL]
- Show installation progress
- Highlight successful installation message at the end
- "Successfully installed privaseeai-security"

---

## STEP 4: START MONITORING (3:30 - 4:15)

### [VISUAL]
- Terminal with command ready
- Type: `privasee start`
- Show monitoring output with colored severity indicators

### [VOICEOVER]
"**Step 4:** The moment of truth. Let's start protecting your iPhone.

In Terminal, type: `privasee start` and press Enter.

You'll see the system initialize all four security monitors:
- VPN Integrity Monitor - catches protocol manipulation
- API Abuse Monitor - detects location tracking
- Carrier Compromise Detector - finds localhost routing attacks
- Certificate Validator - verifies VPN certificates

If everything's green and says 'RUNNING' - congratulations! Your iPhone is now being monitored in real-time."

### [ON-SCREEN DISPLAY]
```
🛡️  PrivaseeAI Security v0.3.0-alpha

Initializing monitors...
✅ VPNIntegrityMonitor        [RUNNING]
✅ APIAbuseMonitor            [RUNNING]
✅ CarrierCompromiseDetector  [RUNNING]
✅ CertificateValidator       [RUNNING]

📊 Monitoring 1 device
🔍 Analyzing backup: /Users/mark/Library/Application Support/MobileSync/Backup/...
⏱️  Last scan: 2 minutes ago

Press Ctrl+C to stop monitoring
```

### [VISUAL HIGHLIGHT]
- Green checkmarks pulsing
- "All systems operational" message

---

## STEP 5: OPTIONAL - TELEGRAM ALERTS (4:15 - 5:00)

### [VISUAL]
- Split screen: Terminal on left, Telegram on right
- Show @BotFather conversation
- Configure bot token

### [VOICEOVER]
"**Optional Step 5:** Want instant alerts on your phone when threats are detected?

Open Telegram and search for @BotFather. Start a chat and type: `/newbot`

Follow the prompts to create your bot. Copy the token it gives you.

Then in Terminal, type these two commands - replacing the placeholders with your actual token and chat ID:"

### [ON-SCREEN COMMANDS]
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"
```

### [VOICEOVER CONTINUED]
"To get your chat ID, search for @userinfobot on Telegram and start a chat. It'll tell you your ID.

Now when PrivaseeAI detects a threat, you'll get an instant message on Telegram. No more checking logs manually."

### [VISUAL]
- Show example Telegram alert:
```
🔴 HIGH SEVERITY THREAT

[VPN] TRANSPORT_MANIPULATION
WireGuard forced to TCP (UDP blocked)

Detected: 2026-01-26 04:24:15
Device: iPhone 16 Pro

Action Required: Carrier-level attack detected.
```

---

## WHAT HAPPENS NEXT (5:00 - 5:30)

### [VISUAL]
- Dashboard view showing:
  - Real-time threat detection
  - Device health status
  - Monitor statistics

### [VOICEOVER]
"So what happens now?

PrivaseeAI is running in the background, continuously analyzing your iPhone backups for:
- VPN manipulation and UDP blocking
- Location API abuse and tracking attempts
- Carrier-level routing attacks
- Suspicious configuration profiles
- Certificate tampering

If anything suspicious is detected, you'll see it immediately - in the terminal, and on Telegram if you set it up.

The system runs 24/7, checking your backups every time they update. No periodic scans. No waiting. Just continuous protection."

### [ON-SCREEN STATS]
- Backups analyzed: 24
- Threats detected: 0
- Uptime: 3 days 4 hours
- Last check: 30 seconds ago

---

## NEXT STEPS (5:30 - 6:00)

### [VISUAL]
- Show GitHub repository README
- Highlight User Guide link
- Show community Discussions page

### [VOICEOVER]
"**Next steps:**

Check out the **User Guide** on GitHub for detailed explanations of each threat type.

Join the **Discussions** to ask questions or share your experience.

If you find this useful, **star the repository** on GitHub. It's free and open source forever - but stars help others discover it.

Most importantly: Stay safe. Your iPhone deserves better protection than what commercial apps provide.

Thanks for watching. I'm Mark, and I'll see you in the next video where I break down exactly what that January 26th attack looked like."

### [ON-SCREEN LINKS]
- 📖 User Guide: github.com/aurelianware/PrivaseeAI.Security/blob/main/USER_GUIDE.md
- 💬 Discussions: github.com/aurelianware/PrivaseeAI.Security/discussions
- ⭐ Star the repo: github.com/aurelianware/PrivaseeAI.Security

---

## OUTRO (6:00 - 6:15)

### [VISUAL]
- End card with:
  - GitHub repository link
  - "Subscribe for more iOS security content"
  - "Next video: Anatomy of a Carrier-Level Attack"

### [VOICEOVER]
"Don't forget to like and subscribe for more iOS security content. Next video drops in 3 days - I'll show you the actual attack logs from January 26th and explain exactly how PrivaseeAI detects each pattern.

Stay secure, everyone."

### [FADE OUT]
- PrivaseeAI Security logo
- "Open Source. Privacy-First. Battle-Tested."

---

## VIDEO PRODUCTION NOTES

### Equipment Needed
- **Screen Recording:** QuickTime Player or OBS Studio
- **Mic:** Blue Yeti or similar USB microphone
- **Editing:** Final Cut Pro, DaVinci Resolve, or iMovie

### Recording Tips
1. **Screen Resolution:** Record at 1920x1080 or 2560x1440
2. **Font Size:** Increase Terminal font to 18pt for visibility
3. **Mouse Cursor:** Make cursor larger for easier following
4. **Pacing:** Pause 2-3 seconds between commands to let viewers read
5. **B-Roll:** Include close-ups of iPhone being connected, backup progress

### Editing Checklist
- [ ] Add chapter markers at each step
- [ ] Insert on-screen text for all commands
- [ ] Highlight cursor/mouse for important clicks
- [ ] Add subtle background music (royalty-free, low volume)
- [ ] Color grade Terminal output (green = success, yellow = warning)
- [ ] Add captions/subtitles for accessibility
- [ ] Include cards at 3:00 and 5:00 for related videos

### YouTube Metadata

**Title Options:**
1. "Protect Your iPhone from Carrier-Level Attacks in 5 Minutes (Free & Open Source)"
2. "I Was Hacked So I Built This Free iOS Security Tool - Setup Tutorial"
3. "iPhone Security Monitoring That Actually Works - PrivaseeAI Setup Guide"

**Description:**
```
After my iPhone was hacked at the carrier level and three $50+ security apps failed to detect it, I built PrivaseeAI Security - a free, open-source iOS threat detection system that actually works.

In this tutorial, I'll show you how to set it up in 5 minutes to protect your iPhone from:
✅ Carrier-level attacks
✅ VPN manipulation
✅ Location tracking
✅ DNS tampering
✅ Spyware & surveillance

🔗 GitHub Repository: https://github.com/aurelianware/PrivaseeAI.Security
📖 User Guide: https://github.com/aurelianware/PrivaseeAI.Security/blob/main/USER_GUIDE.md
💬 Get Help: https://github.com/aurelianware/PrivaseeAI.Security/discussions

🔒 100% Free | 100% Open Source | 100% Local Processing
No cloud, no subscriptions, no tracking.

📌 Timestamps:
0:00 - Intro: Why I Built This
0:30 - Prerequisites
1:00 - Step 1: Backup Your iPhone
2:00 - Step 2: Install Python
2:30 - Step 3: Download & Install
3:30 - Step 4: Start Monitoring
4:15 - Step 5: Telegram Alerts (Optional)
5:00 - What Happens Next
5:30 - Next Steps & Resources

🎬 Next Video: Anatomy of a Carrier-Level Attack (coming in 3 days)

#iOS #Security #Privacy #OpenSource #iPhone #Cybersecurity #Tutorial
```

**Tags:**
iOS security, iPhone security, privacy, open source, VPN, carrier attack, mobile security, cybersecurity tutorial, surveillance detection, ProtonVPN, threat detection, OSINT, Python, macOS, iPhone hack

**Thumbnail Ideas:**
1. iPhone with red "ATTACKED" overlay + green "PROTECTED" after
2. Split screen: Commercial apps (failed) vs PrivaseeAI (detected)
3. Terminal window showing detected threats with attention-grabbing colors

---

## FOLLOW-UP VIDEO IDEAS

### Video 2: "Anatomy of a Carrier-Level Attack"
- Show actual attack logs from January 26th
- Explain each detection rule
- Demonstrate how PrivaseeAI caught it

### Video 3: "Understanding Threat Alerts"
- Deep dive into each threat type
- Real vs false positives
- How to respond to alerts

### Video 4: "Advanced Configuration"
- Custom detection rules
- Multiple device monitoring
- Dashboard setup
- Integration with other security tools

### Video 5: "Contributing to PrivaseeAI"
- How to report bugs
- Adding new threat detections
- Beta testing process
- Community involvement

---

## B-ROLL FOOTAGE TO RECORD

1. **iPhone close-ups:**
   - Connecting cable to iPhone
   - iPhone backup progress on screen
   - ProtonVPN app running
   - Settings → General → About (iOS version)

2. **Terminal footage:**
   - Installation progress bar
   - Successful installation message
   - Monitor startup sequence
   - Live threat detection

3. **Telegram alerts:**
   - Creating bot with @BotFather
   - Receiving test alert
   - Alert formatting examples

4. **GitHub repository:**
   - Scrolling through README
   - Stars count increasing
   - Issues and Discussions sections

---

**Script Complete. Ready for Production. 🎬**

**Estimated Recording Time:** 2-3 hours (including retakes)
**Estimated Editing Time:** 4-6 hours (for polished final cut)
**Target Upload Date:** Within 7 days of project launch
