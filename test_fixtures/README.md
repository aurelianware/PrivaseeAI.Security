# Test Fixtures - Real Attack Data

This directory contains **sanitized samples from actual cybersecurity attacks** being investigated. These fixtures are used for testing threat detection logic.

## ⚠️ Security Notice

All sensitive information has been removed or anonymized:
- Device identifiers replaced with placeholders
- Account information removed
- Specific paths generalized
- Personal data sanitized

## Directory Structure

```
test_fixtures/
├── attack_logs/              # Log files from real attacks
│   ├── wireguard_tcp_fallback.log
│   ├── protonvpn_api_cooldown.json
│   ├── server_hopping.log
│   └── certificate_refresh.log
├── ios_backups/              # Sample iOS backup structures
│   └── profiles/
│       ├── malicious_vpn_localhost.plist
│       └── legitimate_protonvpn.plist
└── certificates/             # Certificate samples (future)
```

## Log File Descriptions

### wireguard_tcp_fallback.log
**Attack Type:** Transport Protocol Manipulation
**Threat Level:** MEDIUM

Demonstrates WireGuard being forced to use TCP instead of UDP, indicating UDP traffic is being blocked at network level.

**Key Indicators:**
- `New socketType value: tcp` (should be udp)
- `TCP dial result: <nil>`
- Interface still connects but using wrong protocol

**Expected Detection:**
```python
ThreatDetection(
    threat_level=ThreatLevel.MEDIUM,
    attack_type="TRANSPORT_MANIPULATION",
    indicators=["UDP_BLOCKED", "TCP_FALLBACK"]
)
```

### protonvpn_api_cooldown.json
**Attack Type:** API Abuse for Location Tracking
**Threat Level:** HIGH

Shows excessive API polling resulting in rate limiting, indicating possible location tracking attempt.

**Key Indicators:**
- `"error":"cooldown(2026-01-26 05:24:44 +0000)"` 
- 50-minute cooldown period
- Location API specifically targeted
- `"bouncing": "5"` feature enabled

**Expected Detection:**
```python
ThreatDetection(
    threat_level=ThreatLevel.HIGH,
    attack_type="API_TRACKING",
    indicators=["RATE_LIMIT", "LOCATION_API", "TRACKING_ATTEMPT"]
)
```

### server_hopping.log
**Attack Type:** Forced Disconnection / Connection Disruption
**Threat Level:** MEDIUM

Demonstrates rapid switching between VPN servers (4 servers in 7 minutes), suggesting forced disconnections or connection interference.

**Server Sequence:**
1. 04:24:55 - 185.159.158.192
2. 04:25:08 - 62.169.136.127
3. 04:27:10 - 79.135.104.47
4. 04:27:21 - 185.159.156.121

**Key Indicators:**
- Multiple `DNS64: mapped` entries in short time
- `Reason: userInitiated` but pattern suggests forced
- Connection stability issues

**Expected Detection:**
```python
ThreatDetection(
    threat_level=ThreatLevel.MEDIUM,
    attack_type="FORCED_RECONNECTION",
    indicators=["RAPID_SWITCHING", "CONNECTION_DISRUPTION"],
    details="4 servers in 7 minutes"
)
```

### certificate_refresh.log
**Attack Type:** Certificate Feature Mismatch (Low Risk)
**Threat Level:** LOW

Shows certificate refresh triggered by feature mismatch, requiring validation that the certificate fingerprint matches known-good values.

**Key Indicators:**
- `unsatisfiedFeatures([netshield])`
- Certificate fingerprint: `6a1e93785520dade`
- Successfully refreshed

**Expected Detection:**
```python
# Should PASS validation - known-good cert
ThreatDetection(
    threat_level=ThreatLevel.NONE,
    details="Certificate validated successfully"
)
```

## Profile File Descriptions

### malicious_vpn_localhost.plist
**Attack Type:** Localhost Routing / Traffic Interception
**Threat Level:** CRITICAL

Fake VPN profile that routes traffic to localhost (127.0.0.1) instead of legitimate VPN server.

**Key Indicators:**
- `<key>RemoteAddress</key><string>127.0.0.1</string>`
- Generic display name ("Corporate VPN")
- No payload organization specified
- Always-on with OnDemand enabled

**Expected Detection:**
```python
ThreatDetection(
    threat_level=ThreatLevel.CRITICAL,
    attack_type="LOCALHOST_ROUTING",
    indicators=["FAKE_VPN_PROFILE", "TRAFFIC_INTERCEPTION", "LOCALHOST_ENDPOINT"]
)
```

### legitimate_protonvpn.plist
**Attack Type:** None (legitimate profile for comparison)
**Threat Level:** NONE

Valid ProtonVPN configuration profile for baseline comparison.

**Legitimate Characteristics:**
- Real server IP: `185.159.158.192`
- ProtonVPN organization specified
- Certificate-based authentication
- Known certificate UUID: `6a1e93785520dade`

**Expected Detection:**
```python
# Should PASS validation
ThreatDetection(
    threat_level=ThreatLevel.NONE,
    details="Legitimate ProtonVPN profile"
)
```

## Usage in Tests

### Unit Tests
```python
import pytest
from pathlib import Path

@pytest.fixture
def attack_logs():
    """Provide path to attack log fixtures."""
    return Path(__file__).parent.parent / "fixtures" / "attack_logs"

def test_detect_tcp_fallback(attack_logs):
    log_file = attack_logs / "wireguard_tcp_fallback.log"
    monitor = VPNIntegrityMonitor()
    
    result = monitor.analyze_log_file(log_file)
    
    assert result.threat_level == ThreatLevel.MEDIUM
    assert "TCP_FALLBACK" in result.indicators
```

### Integration Tests
```python
def test_end_to_end_attack_detection():
    """Test complete attack detection pipeline with real data."""
    fixtures = Path("tests/fixtures")
    
    # Test all attack types
    attacks = [
        ("attack_logs/wireguard_tcp_fallback.log", ThreatLevel.MEDIUM),
        ("attack_logs/protonvpn_api_cooldown.json", ThreatLevel.HIGH),
        ("attack_logs/server_hopping.log", ThreatLevel.MEDIUM),
        ("ios_backups/profiles/malicious_vpn_localhost.plist", ThreatLevel.CRITICAL),
    ]
    
    detector = ThreatDetector()
    
    for log_path, expected_level in attacks:
        result = detector.analyze(fixtures / log_path)
        assert result.threat_level == expected_level
```

## Updating Fixtures

When adding new fixtures:

1. **Sanitize all sensitive data**
   - Remove device IDs
   - Remove account information
   - Remove personal identifiers
   - Generalize file paths

2. **Document the attack pattern**
   - Add description above
   - Specify threat level
   - List key indicators
   - Show expected detection

3. **Create corresponding test**
   - Unit test for specific detection
   - Integration test for full flow
   - Verify no false positives

4. **Update this README**
   - Add to directory listing
   - Document the new fixture
   - Explain detection logic

## Attack Timeline Context

These logs represent a **7-minute attack window** from 04:24:55 to 04:27:22 UTC on January 26, 2026.

**Attack Sequence:**
1. 04:24:55 - TCP fallback detected (UDP blocked)
2. 04:25:08 - First forced reconnection
3. 04:27:10 - Second forced reconnection  
4. 04:27:21 - Third forced reconnection
5. 04:35:39 - API rate limiting detected (tracking attempt)

All of these events occurred during **active VPN usage**, not during connection/disconnection cycles.

## Known-Good Baselines

For comparison and validation:

### Expected Transport
```
Protocol: UDP
Port: 51820
Fallback: None (should never use TCP)
```

### Expected API Behavior
```
Location Requests: < 5 per hour
Rate Limits: Should never trigger
Background Activity: Minimal
```

### Expected Server Behavior
```
Server Changes: < 1 per hour (load balancing)
Reconnections: User-initiated only
```

### Known-Good Certificate
```
Fingerprint: 6a1e93785520dade
Issuer: ProtonVPN CA
Valid: 24 hours typical
```

## Related Documentation

- **CONTEXT.md** - Full project context including attack details
- **GitHub_Copilot_Implementation_Prompts.md** - Implementation guide
- **privaseeAI_iOS_Threat_Detection_Spec.md** - Technical specification

## Security Considerations

These fixtures contain **real attack patterns** and should be:
- ✅ Used for testing and development
- ✅ Shared with security researchers
- ✅ Referenced in threat intelligence

But should NOT be:
- ❌ Used to reproduce attacks
- ❌ Shared outside security context
- ❌ Used for malicious purposes

## Questions?

If you're implementing detection logic and have questions about these fixtures, refer to:
1. This README for fixture-specific details
2. CONTEXT.md for full attack context
3. The implementation prompts for step-by-step guidance

---

**Last Updated:** January 26, 2026  
**Attack Source:** Real carrier-level compromise investigation  
**Status:** Active defense development in progress
