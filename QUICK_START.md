# Quick Start Guide - Get Protection Running This Week

## 🚨 Emergency Response Mode

You're under active attack. This guide gets you from **zero to protected in 7 days**.

## Day 0: Setup (30 minutes)

### 1. Add Files to Your Repository

```bash
# In your PrivaseeAI.Security repository

# Add CONTEXT.md to root
cp CONTEXT.md /path/to/PrivaseeAI.Security/

# Add test fixtures
cp -r test_fixtures /path/to/PrivaseeAI.Security/tests/fixtures

# Create monitors directory
mkdir -p /path/to/PrivaseeAI.Security/src/privaseeai_security/monitors
mkdir -p /path/to/PrivaseeAI.Security/src/privaseeai_security/analyzers
mkdir -p /path/to/PrivaseeAI.Security/src/privaseeai_security/collectors
mkdir -p /path/to/PrivaseeAI.Security/src/privaseeai_security/alerting

# Add __init__.py files
touch /path/to/PrivaseeAI.Security/src/privaseeai_security/monitors/__init__.py
touch /path/to/PrivaseeAI.Security/src/privaseeai_security/analyzers/__init__.py
touch /path/to/PrivaseeAI.Security/src/privaseeai_security/collectors/__init__.py
touch /path/to/PrivaseeAI.Security/src/privaseeai_security/alerting/__init__.py
```

### 2. Update Requirements

```bash
# Edit requirements.txt - add these dependencies

# Security & Crypto
cryptography>=41.0.0
pyOpenSSL>=23.3.0
pycryptodome>=3.19.0

# iOS Device
pymobiledevice3>=2.0.0

# Network
scapy>=2.5.0
dnspython>=2.4.0

# Alerting
python-telegram-bot>=20.7

# Database (for later)
sqlalchemy>=2.0.23
redis>=5.0.1

# Install
pip install -r requirements.txt
```

### 3. Set Up Telegram Bot (Optional but Recommended)

```bash
# 1. Message @BotFather on Telegram
# 2. Create new bot: /newbot
# 3. Get your bot token
# 4. Start chat with your bot
# 5. Get your chat ID from: https://api.telegram.org/bot<YourBOTToken>/getUpdates

# Add to .env
echo "TELEGRAM_BOT_TOKEN=your_token_here" >> .env
echo "TELEGRAM_CHAT_ID=your_chat_id" >> .env
```

## Day 1-2: Certificate Validator

### Step 1: Open GitHub Copilot Chat in VS Code

### Step 2: Create Certificate Validator

**Copy this prompt into Copilot:**

```
Create a new module at src/privaseeai_security/crypto/cert_validator.py

Requirements:
- CertificateValidator class with OpenSSL integration
- validate_vpn_certificate() method that checks certificate fingerprints
- Known-good certificate database for ProtonVPN including fingerprint '6a1e93785520dade'
- detect_mitm_indicators() method to check for suspicious certificate chains
- Return ValidationResult dataclass with threat_level (NONE, LOW, MEDIUM, HIGH, CRITICAL)

Use the existing crypto.py module style (it uses cryptography library).
Include comprehensive docstrings explaining the MITM detection logic.
Add type hints for all methods.

Reference: See CONTEXT.md for certificate format and known-good values.
```

### Step 3: Test It

```bash
# Run tests
pytest tests/unit/test_cert_validator.py -v

# If tests don't exist, ask Copilot to create them with this prompt:
```

**Copilot prompt:**
```
Create tests/unit/test_cert_validator.py with pytest tests for CertificateValidator.

Test cases needed:
1. test_validate_known_good_certificate() - ProtonVPN fingerprint '6a1e93785520dade' should pass
2. test_reject_unknown_certificate() - Unknown fingerprint should return HIGH threat
3. test_detect_self_signed_certificate() - Self-signed certs should return CRITICAL
4. test_extract_cert_from_wireguard_log() - Parse real WireGuard log line from tests/fixtures/attack_logs/certificate_refresh.log
5. test_extract_cert_from_protonvpn_json() - Parse ProtonVPN app JSON log

Use pytest fixtures and follow the pattern in tests/unit/test_crypto.py
Aim for 95%+ coverage.
```

## Day 3-4: VPN Integrity Monitor

### Step 1: Create Base Monitor

**Copilot prompt:**
```
Create src/privaseeai_security/monitors/vpn_integrity.py with VPNIntegrityMonitor class.

The monitor should:
- Track VPN connection state changes
- Monitor transport protocol (TCP vs UDP) 
- Detect API rate limiting from VPN provider logs
- Track server hopping patterns
- Use the CertificateValidator for cert validation

Real-world detection targets from tests/fixtures/attack_logs/:
1. WireGuard log shows "socketType value: tcp" when UDP is expected
2. ProtonVPN app log shows "error":"cooldown(TIMESTAMP)" indicating rate limiting
3. Multiple DNS64 server mappings in short time window (4 servers in 7 minutes)

Initialize with Config from src/privaseeai_security/config.py
Use logger from src/privaseeai_security/logger.py
Return ThreatDetection dataclass with severity, type, and indicators

See CONTEXT.md for log formats and detection rules.
```

### Step 2: Add Detection Methods

**For each detection type, use these prompts in sequence:**

**TCP Fallback Detection:**
```
Add analyze_transport_protocol() method to VPNIntegrityMonitor class.

Parse WireGuard logs from tests/fixtures/attack_logs/wireguard_tcp_fallback.log for "socketType value: tcp" or "udp".
Return ThreatLevel.MEDIUM when unexpected TCP fallback occurs.

See CONTEXT.md Priority Detection Rule 1 for logic.
```

**API Rate Limit Detection:**
```
Add detect_api_rate_limiting() method to VPNIntegrityMonitor class.

Parse ProtonVPN logs from tests/fixtures/attack_logs/protonvpn_api_cooldown.json for cooldown errors.
Return ThreatLevel.HIGH for location API rate limits.

See CONTEXT.md Priority Detection Rule 2 for logic.
```

**Server Hopping Detection:**
```
Add analyze_server_hopping() method to VPNIntegrityMonitor.

Parse server IPs from tests/fixtures/attack_logs/server_hopping.log.
Detect 4+ servers in under 10 minutes = ThreatLevel.MEDIUM.

See CONTEXT.md Priority Detection Rule 3 for logic.
```

### Step 3: Create Integration Test

**Copilot prompt:**
```
Create tests/integration/test_vpn_integrity_monitor.py

Test real-world attack patterns from tests/fixtures/attack_logs/:

1. test_detect_tcp_fallback_attack() - Load wireguard_tcp_fallback.log
2. test_detect_api_cooldown_tracking() - Load protonvpn_api_cooldown.json
3. test_detect_rapid_server_hopping() - Load server_hopping.log
4. test_validate_certificate_from_logs() - Load certificate_refresh.log

Follow integration test patterns from tests/integration/test_backup_monitor.py
```

### Step 4: Test with Real Logs

```bash
# Run integration tests
pytest tests/integration/test_vpn_integrity_monitor.py -v

# Should detect all 3 attack types
```

## Day 5: API Abuse Monitor

**Copilot prompt:**
```
Create src/privaseeai_security/monitors/api_abuse.py with APIAbuseMonitor class.

Monitor application API usage patterns:
- Track API request frequency per application
- Detect rate limiting responses (like in tests/fixtures/attack_logs/protonvpn_api_cooldown.json)
- Identify background API activity during device idle
- Return APIThreatDetection with app_identifier, endpoint, threat_level

Follow the monitor pattern from VPNIntegrityMonitor.
See CONTEXT.md for API monitoring patterns.
```

## Day 6: Telegram Alerting

**Copilot prompt:**
```
Create src/privaseeai_security/alerting/telegram.py for real-time alerts.

Requirements:
- TelegramAlerter class using python-telegram-bot library
- send_threat_alert() method accepting ThreatDetection objects
- Format alerts with emoji severity indicators (🟢🟡🟠🔴)
- Configuration via environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)

Alert format:
🔴 CRITICAL THREAT DETECTED
Type: [attack_type]
Severity: [level]
Time: [timestamp]
Details: [details]

Use config pattern from src/privaseeai_security/config.py
```

## Day 7: Integration & Testing

### Step 1: Update Main Daemon

**Copilot prompt:**
```
Update src/privaseeai_security/__main__.py to create unified monitoring daemon.

The daemon should:
- Initialize VPNIntegrityMonitor, APIAbuseMonitor
- Watch directories containing VPN logs (configure in .env as VPN_LOG_DIR)
- Process new log entries in real-time using FileWatcher
- Run threat detection on each log entry
- Send alerts via Telegram for HIGH and CRITICAL threats

Replace the placeholder while loop with actual monitoring logic.
Use existing Config, Logger, FileWatcher from current implementation.
```

### Step 2: Create .env Configuration

```bash
# Create .env file
cat > .env << 'EOF'
# Monitoring Configuration
VPN_LOG_DIR="/Users/mark/Library/Logs/WireGuard"
PROTONVPN_LOG_DIR="/Users/mark/Library/Logs/ProtonVPN"
WATCH_INTERVAL=5
LOG_LEVEL=INFO

# Alert Configuration
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id

# VPN Configuration
VPN_PROVIDER=protonvpn
EXPECTED_TRANSPORT=udp
TRUSTED_CERT_FINGERPRINT=6a1e93785520dade

# Features
ENABLE_VPN_MONITORING=true
ENABLE_API_ABUSE_MONITORING=true
ENABLE_TELEGRAM_ALERTS=true
EOF
```

### Step 3: Run End-to-End Test

```bash
# Test with fixture data first
python -m privaseeai_security --config .env --test-mode

# If successful, run against real logs
python -m privaseeai_security --config .env

# Should start monitoring and alert on any threats
```

### Step 4: Test Alert System

```bash
# Trigger test alert
python -c "
from privaseeai_security.alerting.telegram import TelegramAlerter
from privaseeai_security.monitors.vpn_integrity import ThreatDetection, ThreatLevel

alerter = TelegramAlerter()
test_threat = ThreatDetection(
    threat_level=ThreatLevel.HIGH,
    attack_type='TEST_ALERT',
    indicators=['SYSTEM_TEST'],
    timestamp='2026-01-26T12:00:00Z',
    details='This is a test alert to verify Telegram integration'
)
alerter.send_threat_alert(test_threat)
"
```

## Week 2: Deploy & Monitor

### Step 1: Run as Service (macOS)

Create launch agent:

```bash
# Create plist file
cat > ~/Library/LaunchAgents/com.privaseeai.security.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.privaseeai.security</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>-m</string>
        <string>privaseeai_security</string>
        <string>--config</string>
        <string>/path/to/your/.env</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/privaseeai-security.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/privaseeai-security-error.log</string>
</dict>
</plist>
EOF

# Load service
launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist

# Check status
launchctl list | grep privaseeai
```

### Step 2: Monitor Logs

```bash
# Watch for threats
tail -f /tmp/privaseeai-security.log

# Should see monitoring heartbeat
# Will alert on Telegram for threats
```

### Step 3: Verify Detection

```bash
# Copy your actual WireGuard/ProtonVPN logs to test
cp /path/to/real/wireguard.log tests/fixtures/attack_logs/

# Run against real data
pytest tests/integration/ -v

# Should detect actual threats from your logs
```

## Troubleshooting

### No Alerts Received

```bash
# Check Telegram configuration
python -c "
from privaseeai_security.config import Config
config = Config()
print(f'Bot Token: {config.get(\"TELEGRAM_BOT_TOKEN\")[:10]}...')
print(f'Chat ID: {config.get(\"TELEGRAM_CHAT_ID\")}')
"

# Test Telegram connection
python -m privaseeai_security.alerting.telegram --test
```

### Log Parsing Errors

```bash
# Enable debug logging
LOG_LEVEL=DEBUG python -m privaseeai_security

# Check log format matches expected
head -5 /path/to/vpn.log
```

### Module Import Errors

```bash
# Reinstall in development mode
pip install -e .

# Verify installation
python -c "import privaseeai_security; print(privaseeai_security.__version__)"
```

## Success Checklist

After 7 days, you should have:

- [x] Certificate validator detecting unknown certs
- [x] VPN monitor detecting TCP fallback
- [x] API abuse detector catching rate limits
- [x] Server hopping detector finding rapid reconnections
- [x] Telegram alerts for HIGH/CRITICAL threats
- [x] Daemon running as background service
- [x] Tested against real attack logs
- [x] Protection running 24/7

## Next Steps

Once basic protection is running:

### Week 2-3: Carrier Compromise Detector
- Localhost routing detection
- eSIM profile monitoring
- DNS tampering detection

### Week 4: iOS Backup Analyzer
- Profile extraction from backups
- Differential analysis across backups
- Persistence tracking

### Month 2: Advanced Features
- Web dashboard
- Database storage
- ML-based anomaly detection

## Getting Help

### Use Copilot Prompts
Reference: `GitHub_Copilot_Implementation_Prompts.md`

### Check Context
Reference: `CONTEXT.md` for attack details and patterns

### Review Fixtures
Directory: `tests/fixtures/` for real attack examples

### Test Coverage
```bash
pytest --cov=src/privaseeai_security --cov-report=html
open htmlcov/index.html
```

## Critical Reminders

1. **Test with fixtures first** before running on real logs
2. **Start with one monitor** (VPN integrity) and add incrementally  
3. **Verify alerts work** before deploying as service
4. **Keep logs** for forensic analysis
5. **Update known-good values** as you learn more about your setup

## Emergency Contacts

If you detect active compromise:
1. ✅ Telegram alert will notify you
2. ✅ Check /tmp/privaseeai-security.log for details
3. ✅ Disconnect from network immediately
4. ✅ Review threat indicators
5. ✅ Follow incident response procedures

---

**You're building real protection against real attacks. Stay focused on the immediate threat first, then expand functionality.**

Good luck! 🛡️
