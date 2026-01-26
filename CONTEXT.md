# CONTEXT.md - Project Context for GitHub Copilot

## Project Overview

**PrivaseeAI.Security** is an iOS threat detection and monitoring system that provides real-time security analysis through multi-layer behavioral monitoring, continuous backup analysis, and network traffic inspection.

**Current Status:** Early implementation phase - testing infrastructure complete (98% coverage), now building core security monitoring features.

---

## Real-World Attack Being Addressed

This project is being developed in response to an **active, sophisticated carrier-level compromise** with the following characteristics:

### Attack Profile
- **Attack Type:** Carrier-level compromise with device persistence
- **Target:** iPhone running iOS 18.2
- **Persistence:** Survives factory resets and device replacements
- **Attack Vectors:** 
  - eSIM/carrier manipulation
  - VPN traffic interception via fake profiles
  - Localhost routing hijacking
  - API abuse for location tracking
  - DNS tampering

### Observed Attack Indicators

#### 1. VPN Integrity Compromise
**WireGuard forced to TCP transport (UDP blocked):**
```log
2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp
```
- Expected: `udp` (WireGuard's native protocol)
- Actual: `tcp` (indicates UDP traffic is being blocked)
- **Threat Level:** MEDIUM - Indicates network-level traffic manipulation

#### 2. API Rate Limiting (Location Tracking)
**ProtonVPN API cooldown triggered:**
```log
2026-01-26T04:35:39.551Z | ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}
```
- Cooldown: 50 minutes (from 04:35 to 05:24)
- Indicates excessive location API polling
- **Threat Level:** HIGH - Suggests active location tracking via API abuse

#### 3. Rapid Server Switching Pattern
**Multiple VPN servers in short time:**
```log
04:24:55 - Server: 185.159.158.192
04:25:08 - Server: 62.169.136.127
04:27:10 - Server: 79.135.104.47
04:27:21 - Server: 185.159.156.121
```
- 4 different servers in 7 minutes
- With `"bouncing": "5"` feature enabled
- **Threat Level:** MEDIUM - May indicate forced disconnections

#### 4. Certificate Refresh Anomaly
**Unexpected certificate feature mismatch:**
```log
INFO | USER_CERT | Stored features do not satisfy required features | {"reason":"unsatisfiedFeatures([netshield])"}
```
- Triggered certificate renewal
- Known-good fingerprint: `6a1e93785520dade`
- **Threat Level:** LOW - But requires validation

#### 5. Localhost Routing via Fake VPN Profiles
**Attack mechanism:**
- Malicious VPN configuration profiles installed
- Routes traffic to `127.0.0.1` instead of legitimate VPN server
- Traffic intercepted locally before reaching actual VPN
- **Threat Level:** CRITICAL - Core attack mechanism

---

## Known-Good Baseline Values

### ProtonVPN Configuration
```yaml
Certificate:
  fingerprint: "6a1e93785520dade"
  valid_until: "2026-01-27 04:27:11 +0000"
  issuer: "ProtonVPN CA"

Expected Transport:
  protocol: "udp"
  fallback: "tcp" (only if UDP fails)

Features:
  netshield: "off"
  vpn_accelerator: true
  nat_type: "strictNAT"
  port_forwarding: false

API Behavior:
  location_requests_per_hour: < 5 (normal)
  rate_limit_threshold: 10 requests/hour (suspicious)
```

### WireGuard Configuration
```yaml
Transport:
  primary: "udp"
  port: 51820
  fallback_tcp: false (should not use TCP)

Interface:
  name: "utun4"
  mtu: 1500

Keepalive:
  interval: 25 seconds
  persistent: true
```

### Network Configuration
```yaml
DNS:
  primary: "NextDNS"
  expected_servers: 
    - "45.90.28.0"
    - "45.90.30.0"
  
VPN Endpoints:
  trusted_ips:
    - "185.159.158.192"
    - "62.169.136.127"
    - "79.135.104.47"
    - "185.159.156.121"
```

---

## Log Format Examples

### WireGuard Log Format
```
TIMESTAMP | LEVEL | COMPONENT | MESSAGE
2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp
```

**Components:**
- `PROTOCOL` - Protocol-level events
- `USER_CERT` - Certificate operations
- `LOCAL_AGENT` - Local agent messages

**Levels:** `INFO`, `DEBUG`, `WARN`, `ERROR`

### ProtonVPN App Log Format (JSON)
```json
{
  "timestamp": "2026-01-26T04:35:39.551Z",
  "level": "ERROR",
  "component": "API",
  "message": "User location request failed",
  "error": "cooldown(2026-01-26 05:24:44 +0000)"
}
```

### iOS System Log Format
```
[Timestamp] [Process] [Message]
2026-01-26 04:24:55 +0000 CommCenter[123] Carrier bundle update: T-Mobile
```

---

## Project Structure & Patterns

### Directory Organization
```
src/privaseeai_security/
├── __init__.py              # Package initialization
├── __main__.py              # Entry point and daemon
├── config.py                # Configuration management ✅
├── logger.py                # Logging utilities ✅
├── crypto.py                # Cryptographic operations ✅
├── device_info.py           # iOS device info (stub)
├── file_watcher.py          # File monitoring ✅
├── backup_monitor.py        # Backup monitoring (stub)
├── monitors/                # NEW: Threat monitors
│   ├── vpn_integrity.py    # VPN monitoring
│   ├── carrier_detection.py # Carrier attacks
│   ├── api_abuse.py        # API tracking
│   └── persistent_threat.py # Persistence detection
├── analyzers/               # NEW: Analysis modules
│   ├── backup_analyzer.py
│   ├── cert_validator.py
│   └── network_analyzer.py
├── collectors/              # NEW: Data collectors
│   ├── ios_logs.py
│   ├── vpn_logs.py
│   └── network_traffic.py
└── alerting/                # NEW: Alert system
    ├── telegram.py
    └── email.py
```

### Code Style Guidelines

#### 1. Configuration Pattern
```python
from privaseeai_security.config import Config

class MyMonitor:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.some_value = self.config.get("key", default_value)
```

#### 2. Logging Pattern
```python
from privaseeai_security.logger import get_logger

class MyMonitor:
    def __init__(self):
        self.logger = get_logger(__name__)
        
    def do_something(self):
        self.logger.info("Action performed", extra={"key": "value"})
        self.logger.error("Error occurred", exc_info=True)
```

#### 3. Exception Handling
```python
class MyMonitorError(Exception):
    """Specific error for this monitor."""
    pass

def analyze(self):
    try:
        # Operations
        pass
    except ValueError as e:
        self.logger.warning(f"Invalid value: {e}")
        raise MyMonitorError(f"Analysis failed: {e}") from e
```

#### 4. Dataclass Results
```python
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

class ThreatLevel(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatDetection:
    """Result of threat analysis."""
    threat_level: ThreatLevel
    attack_type: str
    indicators: List[str]
    timestamp: str
    details: Optional[str] = None
```

#### 5. Type Hints (Required)
```python
from typing import List, Optional, Dict, Any
from pathlib import Path

def analyze_log(
    log_path: Path,
    patterns: List[str],
    config: Optional[Dict[str, Any]] = None
) -> ThreatDetection:
    """Analyze log file for threats."""
    pass
```

#### 6. Docstring Format (Google Style)
```python
def detect_threat(self, data: bytes) -> ThreatDetection:
    """Detect threats in binary data.
    
    Args:
        data: Binary data to analyze
        
    Returns:
        ThreatDetection object with analysis results
        
    Raises:
        AnalysisError: If data cannot be parsed
        
    Example:
        >>> detector = ThreatDetector()
        >>> result = detector.detect_threat(b"data")
        >>> print(result.threat_level)
    """
```

---

## Testing Patterns

### Unit Test Structure
```python
# tests/unit/test_my_module.py
import pytest
from privaseeai_security.my_module import MyClass

class TestMyClass:
    """Test suite for MyClass."""
    
    @pytest.fixture
    def instance(self):
        """Create test instance."""
        return MyClass()
    
    def test_basic_functionality(self, instance):
        """Test basic operation."""
        result = instance.do_something()
        assert result is not None
        assert result.value == "expected"
    
    def test_error_handling(self, instance):
        """Test error conditions."""
        with pytest.raises(ValueError):
            instance.invalid_operation()
```

### Integration Test Structure
```python
# tests/integration/test_real_attack.py
import pytest
from pathlib import Path

@pytest.fixture
def attack_logs():
    """Load real attack log samples."""
    return Path("tests/fixtures/attack_logs")

def test_detect_tcp_fallback(attack_logs):
    """Verify detection of TCP fallback attack."""
    log_file = attack_logs / "wireguard_tcp_fallback.log"
    monitor = VPNIntegrityMonitor()
    
    result = monitor.analyze_log_file(log_file)
    
    assert result.threat_level == ThreatLevel.MEDIUM
    assert result.attack_type == "TRANSPORT_MANIPULATION"
    assert "tcp" in result.indicators
```

### Test Fixtures Location
```
tests/fixtures/
├── attack_logs/              # Real attack log samples (sanitized)
│   ├── wireguard_tcp_fallback.log
│   ├── protonvpn_api_cooldown.json
│   └── server_hopping.log
├── ios_backups/              # Sample iOS backup structures
│   ├── Info.plist
│   ├── Manifest.db
│   └── profiles/
└── certificates/             # Test certificates
    ├── known_good.pem
    └── suspicious.pem
```

---

## Critical Implementation Requirements

### Security Requirements
1. **Never log sensitive data** (passwords, keys, tokens)
2. **Validate all inputs** before processing
3. **Use constant-time comparisons** for secrets
4. **Encrypt stored data** using crypto module
5. **Rate limit API calls** to external services

### Performance Requirements
1. **Non-blocking I/O** for file watching
2. **Async operations** for network calls
3. **Efficient log parsing** (stream processing, not load-all)
4. **Minimal memory footprint** (process logs incrementally)
5. **Background processing** for heavy analysis (use Celery)

### Compatibility Requirements
1. **Python 3.11+** minimum
2. **iOS 17+** primary target (iOS 15+ compatibility)
3. **macOS 13+** for development/deployment
4. **Linux support** for server deployment

---

## Dependencies & Libraries

### Core Dependencies (requirements.txt)
```python
# Security & Crypto
cryptography>=41.0.0
pyOpenSSL>=23.3.0

# iOS Device
pymobiledevice3>=2.0.0

# Network
scapy>=2.5.0
dnspython>=2.4.0

# Alerting
python-telegram-bot>=20.7

# Database (future)
sqlalchemy>=2.0.23
redis>=5.0.1
```

### Development Dependencies (requirements-dev.txt)
```python
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-asyncio>=0.21.0
black>=23.7.0
mypy>=1.5.0
```

---

## Common Patterns to Follow

### 1. Monitor Base Class Pattern
```python
from abc import ABC, abstractmethod
from privaseeai_security.config import Config
from privaseeai_security.logger import get_logger

class BaseMonitor(ABC):
    """Base class for all monitors."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = get_logger(self.__class__.__name__)
        self._running = False
    
    @abstractmethod
    def start(self) -> None:
        """Start monitoring."""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring."""
        pass
    
    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._running
```

### 2. Log Parsing Pattern
```python
import re
from datetime import datetime
from typing import Dict, Any

def parse_wireguard_log(line: str) -> Dict[str, Any]:
    """Parse WireGuard log line.
    
    Format: TIMESTAMP | LEVEL | COMPONENT | MESSAGE
    """
    pattern = r"(\S+) \| (\w+) \| (\w+) \| (.+)"
    match = re.match(pattern, line)
    
    if not match:
        return {}
    
    return {
        "timestamp": datetime.fromisoformat(match.group(1).replace('Z', '+00:00')),
        "level": match.group(2),
        "component": match.group(3),
        "message": match.group(4)
    }
```

### 3. Threat Detection Pattern
```python
def analyze_for_threat(self, data: Any) -> Optional[ThreatDetection]:
    """Analyze data for threats.
    
    Returns None if no threat detected.
    """
    # Check for known indicators
    indicators = []
    
    if self._check_indicator_1(data):
        indicators.append("INDICATOR_1")
    
    if self._check_indicator_2(data):
        indicators.append("INDICATOR_2")
    
    if not indicators:
        return None
    
    # Determine threat level
    threat_level = self._calculate_threat_level(indicators)
    
    return ThreatDetection(
        threat_level=threat_level,
        attack_type=self._classify_attack(indicators),
        indicators=indicators,
        timestamp=datetime.utcnow().isoformat(),
        details=self._get_details(data, indicators)
    )
```

---

## Environment Variables

### Required Configuration
```bash
# .env file format

# Monitoring
BACKUP_DIRECTORY="/Users/mark/Library/Application Support/MobileSync/Backup"
WATCH_INTERVAL=5
LOG_LEVEL="INFO"

# Alerting
TELEGRAM_BOT_TOKEN="your_token_here"
TELEGRAM_CHAT_ID="your_chat_id"

# VPN Monitoring
VPN_PROVIDER="protonvpn"
EXPECTED_TRANSPORT="udp"
TRUSTED_CERT_FINGERPRINT="6a1e93785520dade"

# Database (future)
DATABASE_URL="postgresql://localhost/privaseeai"
REDIS_URL="redis://localhost:6379/0"

# Features
ENABLE_VPN_MONITORING=true
ENABLE_CARRIER_DETECTION=true
ENABLE_API_ABUSE_MONITORING=true
```

---

## Debugging Tips

### Enable Debug Logging
```python
# Set in config or environment
LOG_LEVEL=DEBUG

# In code
self.logger.debug("Detailed information", extra={
    "variable": value,
    "context": context
})
```

### Test with Sample Logs
```bash
# Use fixture logs for testing
pytest tests/integration/test_vpn_monitor.py -v

# Run monitor against real logs
python -m privaseeai_security --log-file /path/to/real.log --dry-run
```

### Verify Detection Logic
```python
# Create minimal test case
def test_my_detection():
    monitor = MyMonitor()
    
    # Use exact log line from real attack
    log_line = "2026-01-26T04:24:55.103672Z | INFO | PROTOCOL | New socketType value: tcp"
    
    result = monitor.parse_log(log_line)
    
    # Verify detection
    assert result.threat_level == ThreatLevel.MEDIUM
    print(f"Detection successful: {result}")
```

---

## Priority Detection Rules

### Rule 1: TCP Fallback Detection
```python
if log_contains("socketType value: tcp") and expected_protocol == "udp":
    return ThreatDetection(
        threat_level=ThreatLevel.MEDIUM,
        attack_type="TRANSPORT_MANIPULATION",
        indicators=["UDP_BLOCKED", "TCP_FALLBACK"]
    )
```

### Rule 2: API Rate Limiting Detection
```python
if log_contains("cooldown") and "location" in api_endpoint:
    return ThreatDetection(
        threat_level=ThreatLevel.HIGH,
        attack_type="API_TRACKING",
        indicators=["RATE_LIMIT", "LOCATION_API", "TRACKING_ATTEMPT"]
    )
```

### Rule 3: Rapid Server Switching
```python
if server_count > 3 and time_window < timedelta(minutes=10):
    return ThreatDetection(
        threat_level=ThreatLevel.MEDIUM,
        attack_type="FORCED_RECONNECTION",
        indicators=["RAPID_SWITCHING", "CONNECTION_DISRUPTION"]
    )
```

### Rule 4: Unknown Certificate
```python
if cert_fingerprint not in trusted_fingerprints:
    return ThreatDetection(
        threat_level=ThreatLevel.CRITICAL,
        attack_type="MITM_CERTIFICATE",
        indicators=["UNKNOWN_CERT", cert_fingerprint]
    )
```

### Rule 5: Localhost Routing
```python
if vpn_endpoint == "127.0.0.1" or vpn_endpoint == "::1":
    return ThreatDetection(
        threat_level=ThreatLevel.CRITICAL,
        attack_type="LOCALHOST_ROUTING",
        indicators=["FAKE_VPN_PROFILE", "TRAFFIC_INTERCEPTION"]
    )
```

---

## References

### Existing Working Modules
- `src/privaseeai_security/config.py` - Configuration management pattern
- `src/privaseeai_security/logger.py` - Logging setup and usage
- `src/privaseeai_security/crypto.py` - Cryptographic operations
- `src/privaseeai_security/file_watcher.py` - File monitoring pattern
- `tests/unit/test_config.py` - Unit test examples
- `tests/integration/test_backup_monitor.py` - Integration test examples

### Documentation
- `README.md` - Project overview and usage
- `privaseeAI_iOS_Threat_Detection_Spec.md` - Complete technical specification
- `SECURITY.md` - Security policy and vulnerability reporting
- `CONTRIBUTING.md` - Contribution guidelines

---

## Quick Reference Commands

```bash
# Setup
pip install -r requirements-dev.txt
pip install -e .

# Testing
make test                 # Run all tests
make test-unit           # Unit tests only
make test-coverage       # With coverage report
pytest -v -k "test_vpn"  # Specific test

# Code Quality
make lint                # Run linters
make format              # Format code
make type-check          # Type checking

# Running
python -m privaseeai_security                    # Start daemon
python -m privaseeai_security --config custom.env # Custom config
```

---

**Note for GitHub Copilot:**

When generating code:
1. **Always follow these patterns** - Check CONTEXT.md first
2. **Use existing modules** - Import from privaseeai_security.*
3. **Include type hints** - Required for all functions/methods
4. **Add docstrings** - Google style format
5. **Write tests** - Every module needs unit tests
6. **Handle errors** - Comprehensive error handling
7. **Log appropriately** - Use self.logger, not print()

This project detects **real, active attacks** - the detection logic must be precise and reliable.
