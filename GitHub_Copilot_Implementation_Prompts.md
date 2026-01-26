# GitHub Copilot Implementation Prompts for PrivaseeAI.Security

## Strategy for Using This Document

**❌ DON'T:** Paste the entire 20+ page assessment to Copilot
**✅ DO:** Use these focused, actionable prompts in sequence

Each prompt is designed to:
- Be specific and actionable
- Include context Copilot needs
- Reference existing code patterns
- Specify expected outputs
- Include test requirements

---

## Phase 0: Emergency Response (Week 1-2)

### Day 1-2: VPN Certificate Validator

#### Prompt 1.1: Create Certificate Validator Module Structure
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
```

#### Prompt 1.2: Add Certificate Extraction from Logs
```
Add method to CertificateValidator class to extract certificate info from log strings.

Input example from WireGuard log:
"Certificate with features saved | certificateFingerprint: '6a1e93785520dade', validUntil: '2026-01-27 04:27:11 +0000', refreshTime: '2026-01-26 22:27:11 +0000'"

The method should:
- Parse certificate fingerprint, validUntil, and refreshTime from log entries
- Handle multiple log formats (JSON and text)
- Return structured CertificateInfo dataclass
- Include error handling for malformed logs

Follow the logging patterns in src/privaseeai_security/logger.py
```

#### Prompt 1.3: Write Certificate Validator Tests
```
Create tests/unit/test_cert_validator.py with pytest tests for CertificateValidator.

Test cases needed:
1. test_validate_known_good_certificate() - ProtonVPN fingerprint '6a1e93785520dade' should pass
2. test_reject_unknown_certificate() - Unknown fingerprint should return HIGH threat
3. test_detect_self_signed_certificate() - Self-signed certs should return CRITICAL
4. test_extract_cert_from_wireguard_log() - Parse real WireGuard log line
5. test_extract_cert_from_protonvpn_json() - Parse ProtonVPN app JSON log
6. test_validate_certificate_expiry() - Detect suspiciously short validity periods
7. test_certificate_chain_validation() - Validate full certificate chain

Use pytest fixtures and follow the pattern in tests/unit/test_crypto.py
Mock OpenSSL calls where appropriate.
Aim for 95%+ coverage.
```

---

### Day 3-4: VPN Integrity Monitor

#### Prompt 2.1: Create VPN Integrity Monitor Base
```
Create src/privaseeai_security/monitors/vpn_integrity.py with VPNIntegrityMonitor class.

The monitor should:
- Track VPN connection state changes
- Monitor transport protocol (TCP vs UDP) 
- Detect API rate limiting from VPN provider logs
- Track server hopping patterns
- Use the CertificateValidator for cert validation

Real-world detection targets based on actual attack:
1. WireGuard log shows "socketType value: tcp" when UDP is expected
2. ProtonVPN app log shows "error":"cooldown(TIMESTAMP)" indicating rate limiting
3. Multiple DNS64 server mappings in short time window (4 servers in 7 minutes)

Initialize with Config from src/privaseeai_security/config.py
Use logger from src/privaseeai_security/logger.py
Return ThreatDetection dataclass with severity, type, and indicators
```

#### Prompt 2.2: Add Transport Protocol Monitor
```
Add analyze_transport_protocol() method to VPNIntegrityMonitor class.

This method should:
- Parse WireGuard logs for "socketType value: tcp" or "socketType value: udp"
- Track expected vs actual transport protocol
- Alert when UDP fails and falls back to TCP (indicates UDP blocking)
- Maintain protocol history over time
- Return ThreatLevel.MEDIUM when unexpected TCP fallback occurs

Input format example:
"2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"

Expected behavior:
- If protocol is 'udp': Return ThreatLevel.NONE
- If protocol is 'tcp' and expected is 'udp': Return ThreatLevel.MEDIUM with attack_type='TRANSPORT_MANIPULATION'
- Track protocol switches and alert on patterns
```

#### Prompt 2.3: Add API Rate Limit Detector
```
Add detect_api_rate_limiting() method to VPNIntegrityMonitor class.

Detection logic for ProtonVPN API abuse:
- Parse log entries for API error responses
- Look for "cooldown" errors with future timestamps
- Track API request frequency per endpoint
- Calculate time until cooldown expires
- Alert on rate limiting as indicator of tracking attempts

Real example to detect:
'ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}'

The method should:
- Parse the cooldown timestamp
- Calculate remaining cooldown time
- Return ThreatLevel.HIGH for location API rate limits
- Include attack_type='API_TRACKING' with details about potential location tracking
- Track which APIs are being rate limited
```

#### Prompt 2.4: Add Server Hopping Analyzer
```
Add analyze_server_hopping() method to VPNIntegrityMonitor.

Track VPN server connection patterns to detect forced disconnections:
- Parse WireGuard logs for "DNS64: mapped X.X.X.X" server IPs
- Track connection timestamps and server IPs
- Calculate servers per time window
- Distinguish legitimate load balancing from attack patterns

Detection rules:
- 4+ different servers in under 10 minutes = ThreatLevel.MEDIUM
- Rapid reconnections (< 2 minutes apart) = ThreatLevel.MEDIUM  
- Correlate with transport protocol changes
- Check for "bouncing" feature state in ProtonVPN logs

Return ThreatDetection with:
- attack_type='FORCED_RECONNECTION' or 'CONNECTION_DISRUPTION'
- indicators: list of server IPs and timestamps
- time_window: duration of hopping pattern
```

#### Prompt 2.5: Write VPN Integrity Monitor Tests
```
Create tests/integration/test_vpn_integrity_monitor.py

Test real-world attack patterns from actual logs:

1. test_detect_tcp_fallback_attack()
   - Input: WireGuard log with "socketType value: tcp"
   - Expected: ThreatLevel.MEDIUM, attack_type='TRANSPORT_MANIPULATION'

2. test_detect_api_cooldown_tracking()
   - Input: ProtonVPN log with cooldown error
   - Expected: ThreatLevel.HIGH, attack_type='API_TRACKING'

3. test_detect_rapid_server_hopping()
   - Input: 4 server connections in 7 minutes
   - Expected: ThreatLevel.MEDIUM, attack_type='FORCED_RECONNECTION'

4. test_validate_certificate_from_logs()
   - Input: Log with certificateFingerprint '6a1e93785520dade'
   - Expected: ThreatLevel.NONE (known-good cert)

5. test_end_to_end_attack_detection()
   - Input: Complete log sequence from real attack
   - Expected: Multiple threat detections with proper severity

Use pytest fixtures to load real log files from tests/fixtures/
Follow integration test patterns from tests/integration/test_backup_monitor.py
```

---

### Day 5: API Abuse Monitor

#### Prompt 3.1: Create API Abuse Monitor
```
Create src/privaseeai_security/monitors/api_abuse.py with APIAbuseMonitor class.

Monitor application API usage patterns for abuse and tracking:
- Track API request frequency per application
- Detect rate limiting responses
- Identify background API activity during device idle
- Monitor location API usage patterns

Key methods:
1. track_api_request() - Record API call with timestamp, endpoint, app
2. analyze_request_patterns() - Detect anomalous request patterns
3. detect_location_tracking() - Identify excessive location API calls
4. check_rate_limit_responses() - Parse rate limit errors from app logs

Use Config and Logger from existing modules.
Return APIThreatDetection dataclass with app_identifier, endpoint, threat_level.
```

#### Prompt 3.2: Add Request Pattern Analyzer
```
Add analyze_request_patterns() method to APIAbuseMonitor.

Detection logic:
- Calculate request frequency: requests per minute/hour
- Identify burst patterns (many requests in short time)
- Detect background requests (activity when device should be idle)
- Compare against baseline normal behavior

Thresholds:
- Location API: > 10 requests/hour = suspicious
- Any API with rate limit response = HIGH threat
- Background requests during sleep hours (11pm-6am) = MEDIUM threat

Return analysis with:
- is_suspicious: bool
- request_rate: float (requests/hour)
- pattern_type: 'BURST' | 'BACKGROUND' | 'RATE_LIMITED'
- threat_level: ThreatLevel enum
```

#### Prompt 3.3: Write API Abuse Monitor Tests
```
Create tests/unit/test_api_abuse.py

Test cases:
1. test_track_api_requests() - Verify request logging
2. test_detect_burst_pattern() - Many requests in short time
3. test_detect_location_tracking() - Excessive location API calls
4. test_identify_rate_limiting() - Parse rate limit errors
5. test_background_activity_detection() - Requests during idle hours
6. test_calculate_request_frequency() - Requests per time window
7. test_compare_against_baseline() - Deviation from normal

Use pytest and follow patterns in tests/unit/test_config.py
Mock datetime for testing time-based logic.
```

---

### Day 6-7: Integration & Alerting

#### Prompt 4.1: Create Alert System
```
Create src/privaseeai_security/alerting/telegram.py for real-time alerts.

Requirements:
- TelegramAlerter class using python-telegram-bot library
- send_threat_alert() method accepting ThreatDetection objects
- Format alerts with emoji severity indicators (🟢🟡🟠🔴)
- Include threat details: type, severity, indicators, timestamp
- Support alert throttling to prevent spam
- Configuration via environment variables (bot token, chat ID)

Alert format example:
```
🔴 CRITICAL THREAT DETECTED

Type: MITM_CERTIFICATE
Severity: CRITICAL
Time: 2026-01-26 04:30:15 UTC

Details:
Unknown certificate fingerprint detected
Expected: 6a1e93785520dade
Found: abc123def456

Recommended action: Disconnect from network immediately
```

Follow config pattern from src/privaseeai_security/config.py
```

#### Prompt 4.2: Create Unified Monitoring Daemon
```
Update src/privaseeai_security/__main__.py to create unified monitoring daemon.

The daemon should:
- Initialize VPNIntegrityMonitor, APIAbuseMonitor
- Watch log directories for VPN and app logs
- Process new log entries in real-time
- Run threat detection on each log entry
- Send alerts via Telegram for HIGH and CRITICAL threats
- Maintain running state and graceful shutdown

Main loop:
1. Watch for new log entries using FileWatcher
2. Route logs to appropriate monitor (VPN or API)
3. Collect threat detections
4. Send alerts for actionable threats
5. Log all detections for forensic analysis

Replace the placeholder while loop with actual monitoring.
Use existing Config, Logger, FileWatcher from current implementation.
```

#### Prompt 4.3: Create End-to-End Test with Real Logs
```
Create tests/integration/test_real_attack_detection.py

This test should:
- Load actual ProtonVPN and WireGuard logs from tests/fixtures/real_attack_logs/
- Run the complete monitoring system against real log data
- Verify all expected threats are detected
- Validate threat severity and details
- Ensure no false positives

Expected detections from real attack logs:
1. TCP fallback (WireGuard forced to TCP)
2. API rate limiting (50-minute cooldown)
3. Server hopping (4 servers in 7 minutes)
4. Certificate validation (should pass for known-good cert)

Test should:
- Load logs from fixture files
- Initialize all monitors
- Process logs through the system
- Assert threat_count == 3 (TCP, rate limit, server hopping)
- Assert certificate validation passes
- Verify alert formatting

This is a critical integration test proving the system works against real attacks.
```

---

## Phase 1: Core Security Monitoring (Weeks 3-4)

### Week 3: Carrier Compromise Detector

#### Prompt 5.1: Create Carrier Compromise Detector
```
Create src/privaseeai_security/monitors/carrier_detection.py with CarrierCompromiseDetector class.

This monitor detects carrier-level attacks:
1. eSIM profile manipulation
2. Localhost routing through fake VPN profiles
3. DNS tampering
4. Network interface anomalies

Key methods:
- monitor_esim_profiles() - Track eSIM profile changes
- detect_localhost_routing() - Find routes to 127.0.0.1
- analyze_dns_resolution() - Validate DNS responses
- track_network_interfaces() - Monitor TUN/TAP interfaces

Platform: iOS focused but should be extensible
Use subprocess to call networksetup and scutil on macOS for network inspection
Parse iOS backup files for VPN/MDM profiles

Follow the monitor pattern from VPNIntegrityMonitor.
```

#### Prompt 5.2: Add eSIM Profile Monitor
```
Add monitor_esim_profiles() method to CarrierCompromiseDetector.

Detection logic:
- Read iOS backup files for carrier profiles
- Track eSIM profile additions/modifications
- Compare profiles across backup snapshots
- Detect unauthorized carrier profiles
- Flag profiles that persist across factory resets

File locations in iOS backup:
- ~/Library/Application Support/MobileSync/Backup/[DEVICE_ID]/
- Look for .plist files containing CarrierBundle or eSIM data

Parse using plistlib (Python standard library)
Return ThreatLevel.CRITICAL for unauthorized profiles
Include profile details in threat indicators
```

#### Prompt 5.3: Add Localhost Routing Detector
```
Add detect_localhost_routing() method to CarrierCompromiseDetector.

Detect fake VPN profiles routing traffic to localhost (127.0.0.1):
- Parse VPN configuration profiles from iOS backups
- Check for routes pointing to 127.0.0.1 or ::1
- Detect suspicious TUN/TAP interface configurations
- Identify VPN profiles with no remote endpoint

Profile locations:
- /Library/Managed Preferences/ (MDM)
- ~/Library/Preferences/com.apple.networkextension.plist

Suspicious indicators:
- VPN profile with ServerAddress = "127.0.0.1"
- Routes directing traffic to localhost
- VPN profiles created outside user installation

Return ThreatLevel.CRITICAL for localhost routing
This is a key indicator of the specific attack being experienced
```

#### Prompt 5.4: Write Carrier Detector Tests
```
Create tests/unit/test_carrier_detection.py

Test cases:
1. test_detect_unauthorized_esim_profile()
2. test_identify_localhost_routing_in_vpn_profile()
3. test_parse_ios_carrier_bundle()
4. test_track_profile_across_backups()
5. test_detect_dns_tampering()
6. test_monitor_network_interface_changes()
7. test_validate_carrier_profile_signature()

Use pytest fixtures with sample iOS plist files
Mock filesystem access and subprocess calls
Test with sanitized versions of real attack profile data
```

---

### Week 4: iOS Backup Analyzer Enhancement

#### Prompt 6.1: Enhance Device Info Extractor
```
Enhance src/privaseeai_security/device_info.py with real iOS backup parsing.

Add libimobiledevice integration:
- Use pymobiledevice3 library for iOS 17+ support
- Extract Info.plist from backup
- Parse Status.plist for backup metadata
- Read Manifest.db (SQLite) for file listings

New methods:
- get_installed_apps() - List all installed applications
- extract_vpn_profiles() - Get VPN configuration profiles
- get_mdm_profiles() - Extract MDM profiles
- analyze_network_configuration() - Parse network settings

Use SQLite to query Manifest.db:
"SELECT fileID, domain, relativePath FROM Files WHERE domain = 'SystemPreferencesDomain'"

Follow existing DeviceInfoExtractor class structure.
Add proper error handling for encrypted backups.
```

#### Prompt 6.2: Add Profile Extraction
```
Add extract_security_profiles() method to DeviceInfoExtractor.

Extract and analyze security-relevant profiles:
- VPN profiles (IPSec, IKEv2, WireGuard)
- MDM profiles
- Certificate profiles
- Configuration profiles

For each profile:
- Parse plist structure
- Extract profile identifier, name, organization
- Check for suspicious attributes (localhost endpoints, unsigned profiles)
- Validate digital signatures
- Compare against known-good profiles

Return list of ProfileInfo dataclasses with:
- profile_id: str
- profile_type: 'VPN' | 'MDM' | 'Certificate'
- is_signed: bool
- organization: str
- suspicious_indicators: List[str]
- threat_level: ThreatLevel

Use plistlib to parse .plist files from backup
```

#### Prompt 6.3: Write Backup Analyzer Tests
```
Enhance tests/unit/test_device_info.py with real backup analysis tests.

New test cases:
1. test_parse_manifest_database() - Query Manifest.db SQLite
2. test_extract_vpn_profiles() - Parse VPN configurations
3. test_detect_unsigned_profile() - Flag unsigned profiles
4. test_validate_profile_signature() - Check digital signatures
5. test_extract_network_configuration() - Parse network settings
6. test_compare_backups_for_changes() - Differential analysis
7. test_detect_persistent_profile() - Profile surviving reset

Create test fixtures with sample iOS backup structure
Mock pymobiledevice3 calls for isolated testing
```

---

## Phase 2: Update Requirements (Critical)

#### Prompt 7.1: Create Complete Requirements File
```
Update requirements.txt with all production dependencies.

Categories needed:

# Core Framework
fastapi>=0.104.1
uvicorn[standard]>=0.24.0
pydantic>=2.5.0

# iOS Device Communication
pymobiledevice3>=2.0.0
# Note: libimobiledevice is system package (brew install libimobiledevice)

# Security & Crypto
cryptography>=41.0.0
pyOpenSSL>=23.3.0
pycryptodome>=3.19.0

# Network Analysis
scapy>=2.5.0
dnspython>=2.4.0

# Database
sqlalchemy>=2.0.23
asyncpg>=0.29.0
redis>=5.0.1

# Background Tasks
celery>=5.3.4
flower>=2.0.1

# Monitoring & Metrics
prometheus-client>=0.19.0
structlog>=23.2.0

# Alerting
python-telegram-bot>=20.7
sendgrid>=6.11.0

# Utilities
python-dotenv>=1.0.0
PyYAML>=6.0.1
plistlib (stdlib)

Pin versions to ensure reproducibility.
Group by functionality with comments.
```

---

## Pro Tips for Using These Prompts

### 1. **Use Prompts in Order**
Each builds on the previous one. Don't skip ahead.

### 2. **Iterate on Each Prompt**
```
First pass: Let Copilot generate
Review: Check against requirements
Second pass: Refine with specific feedback
Test: Verify with pytest
```

### 3. **Reference Existing Code**
Always mention:
- "Follow the pattern in [existing_file.py]"
- "Use the same style as [existing_class]"
- "Follow test patterns from tests/unit/test_crypto.py"

### 4. **Be Specific About Real Data**
Include actual examples:
- Real log lines
- Actual certificate fingerprints
- True timestamps from your attack

### 5. **Ask for Tests Separately**
Implementation prompt → Test prompt
This ensures better test coverage

### 6. **Use Multi-Step Prompts for Complex Features**
Break VPNIntegrityMonitor into:
- Base structure
- Transport monitoring
- API detection
- Server hopping
- Integration

### 7. **Validate Each Step**
After each prompt:
```bash
pytest tests/unit/test_[new_module].py
make lint
make type-check
```

---

## Advanced Techniques

### Technique 1: Context Files
Create a `CONTEXT.md` in your repo:
```markdown
# Project Context for GitHub Copilot

## Real Attack Being Addressed
[Brief summary of your carrier-level attack]

## Log Format Examples
[Your actual WireGuard and ProtonVPN log samples]

## Known-Good Values
- Certificate: 6a1e93785520dade
- Expected protocol: UDP
- Trusted servers: [list]

## Code Style
- Follow patterns in src/privaseeai_security/
- Use Config, Logger from existing modules
- All classes need comprehensive docstrings
- Type hints required
```

Reference this in prompts: "See CONTEXT.md for attack details"

### Technique 2: Incremental Refinement
```
Prompt: "Create VPNIntegrityMonitor base class"
[Copilot generates]

Follow-up: "Add docstrings explaining MITM detection"
[Copilot adds docs]

Follow-up: "Add type hints to all methods"
[Copilot adds hints]

Follow-up: "Add error handling for malformed logs"
[Copilot adds try/except]
```

### Technique 3: Test-Driven Prompts
```
1. "Create test_vpn_monitor.py with test stubs for VPNIntegrityMonitor"
2. Review test expectations
3. "Implement VPNIntegrityMonitor to pass these tests"
```

### Technique 4: Example-Driven
```
"Create parse_wireguard_log() method.

Input example:
'2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp'

Expected output:
{
    'timestamp': datetime(2026, 1, 26, 4, 24, 55),
    'level': 'INFO',
    'component': 'PROTOCOL',
    'socket_type': 'tcp'
}

Handle malformed logs gracefully."
```

---

## What NOT to Give Copilot

❌ **Don't paste:**
- Full 20-page assessment
- Complete architecture diagrams
- Entire specification documents
- Long background context

❌ **Why not?**
- Context window overflow
- Diluted focus
- Copilot works best with focused, actionable prompts
- Large context → generic suggestions

✅ **Instead, give:**
- Specific method signatures
- Real examples (log lines, data formats)
- Clear requirements (bullet points)
- References to existing code patterns
- Expected input/output

---

## Sample Session Flow

Here's how to use these prompts in practice:

### Session 1: VPN Certificate Validator
```bash
# 1. Start VS Code with Copilot
# 2. Create new file: src/privaseeai_security/crypto/cert_validator.py

# 3. Use Prompt 1.1 in chat
# Copilot generates base class

# 4. Review, then use Prompt 1.2
# Adds log parsing

# 5. Create test file: tests/unit/test_cert_validator.py
# Use Prompt 1.3

# 6. Run tests
pytest tests/unit/test_cert_validator.py

# 7. Fix any failures
# Use follow-up prompts: "Fix test_validate_known_good_certificate to handle..."

# 8. Commit
git add src/privaseeai_security/crypto/cert_validator.py tests/unit/test_cert_validator.py
git commit -m "feat: add VPN certificate validator"
```

### Session 2: VPN Integrity Monitor
```bash
# Same pattern, use Prompts 2.1-2.5
# Each prompt builds on the last
# Test after each addition
```

---

## Tracking Progress

Use this checklist:

```markdown
## Week 1 Progress

### Day 1-2: Certificate Validator
- [ ] Prompt 1.1: Base CertificateValidator class
- [ ] Prompt 1.2: Log parsing
- [ ] Prompt 1.3: Tests (95%+ coverage)
- [ ] All tests passing
- [ ] Code review & refactor

### Day 3-4: VPN Integrity Monitor  
- [ ] Prompt 2.1: Base VPNIntegrityMonitor
- [ ] Prompt 2.2: Transport protocol monitor
- [ ] Prompt 2.3: API rate limit detector
- [ ] Prompt 2.4: Server hopping analyzer
- [ ] Prompt 2.5: Integration tests
- [ ] Test with real logs

### Day 5: API Abuse Monitor
- [ ] Prompt 3.1: Base APIAbuseMonitor
- [ ] Prompt 3.2: Request pattern analyzer
- [ ] Prompt 3.3: Unit tests
- [ ] Integration with VPN monitor

### Day 6-7: Integration & Alerting
- [ ] Prompt 4.1: Telegram alerting
- [ ] Prompt 4.2: Unified daemon
- [ ] Prompt 4.3: End-to-end tests
- [ ] Deploy and test on real device
```

---

## Getting Help from Copilot

### When Copilot suggests something unexpected:
```
"That implementation uses [X], but I need [Y] because [reason].
Please revise to use [Y] following the pattern in [existing_file.py]"
```

### When tests fail:
```
"The test test_[name] is failing with error: [error message]
Fix the implementation to handle [edge case]"
```

### When code quality is low:
```
"Refactor this to:
- Add comprehensive docstrings
- Include type hints
- Handle errors gracefully
- Follow PEP 8 style
Reference the code style in src/privaseeai_security/config.py"
```

---

## Final Recommendations

### ✅ Best Practices:
1. Use prompts sequentially
2. Test after each prompt
3. Reference existing code patterns
4. Include real examples
5. Ask for tests separately
6. Iterate on suggestions

### ✅ Quality Checks:
After each Copilot generation:
```bash
# Run tests
pytest

# Check coverage
pytest --cov

# Lint code
make lint

# Type check
make type-check

# Format code
make format
```

### ✅ Version Control:
Commit after each working feature:
```bash
git add [files]
git commit -m "feat: [description]"
git push
```

---

**Ready to Start?**

Begin with Prompt 1.1 (Certificate Validator) and work through sequentially.

Each prompt is designed to produce working, tested code that builds toward your complete security monitoring system.

Good luck! 🚀
