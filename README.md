# PrivaseeAI.Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code](https://img.shields.io/badge/Code-7,469%20lines-blue)]()
[![Tests](https://img.shields.io/badge/Tests-312%20passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-73%25-yellow)]()

**Real-Time iOS Threat Detection & Monitoring System**

PrivaseeAI.Security is a privacy-preserving iOS threat detection system that provides continuous security monitoring through VPN integrity checks, backup analysis, and behavioral pattern detection. Built in response to a real carrier-level attack, its detection rules were derived from that incident's logs.

> **Status:** v0.3.0-alpha - active development | 7,469 lines of Python | 312 tests passing, 10 skipped | 73% coverage
>
> Not production ready. Alert delivery and the AES helper work, but the web dashboard
> is an unwired prototype, the persistence layer is not connected to any monitor, and
> two of the three orchestrator monitor loops do no detection. See
> [`ASSESSMENT.md`](ASSESSMENT.md) for a verified capability-by-capability breakdown.

## 🎯 Overview

Unlike traditional periodic scans, PrivaseeAI.Security provides **continuous real-time monitoring** with instant alerts when threats are detected. All analysis happens locally on your machine, ensuring complete privacy and data sovereignty.

### What Makes This Different

- ✅ **Incident-Derived:** Rules written against a real carrier-level attack
  (January 26, 2026) — real provenance, but one incident, and false positives
  are not yet measured
- ⚠️ **Continuous Monitoring:** `privasee start` currently runs carrier checks only;
  the VPN and API monitor loops are not yet wired to a live input
- ✅ **Privacy-First:** analysis is 100% local, no cloud dependencies
- ⚠️ **Alpha:** 7,469 lines of code, 312 tests passing, 73% coverage — not production ready
- ✅ **Open Source:** Apache 2.0 license, full transparency

## ✨ Current Features (v0.3.0-alpha)

### 🛡️ Real-Time Threat Detection

**VPN Integrity Monitor** (386 lines)
- Detects TCP fallback when UDP is blocked
- Tracks API rate limiting and cooldown periods
- Identifies server hopping patterns (4+ servers in <10 min)
- Validates certificates against known-good fingerprints
- 14 integration tests covering real attack scenarios

**API Abuse Monitor** (397 lines)
- Location tracking detection via API abuse
- Rate limit identification and analysis
- Burst pattern detection
- Background activity monitoring
- 19 unit tests validating all detection rules

**Carrier Compromise Detector** (790 lines)
- Localhost routing detection in VPN profiles
- eSIM profile monitoring
- DNS tampering identification
- Cross-backup persistence tracking
- 28 comprehensive unit tests

**Certificate Validator** (295 lines)
- Known-good fingerprint database (ProtonVPN baseline)
- Certificate chain validation
- Expiry date checking
- Self-signed certificate detection
- 8 unit tests ensuring accuracy

**Telegram Alerting** (300 lines)
- Real-time notifications for CRITICAL/HIGH threats
- Severity-based filtering
- Automatic threat deduplication
- Custom message formatting
- Alert throttling to prevent spam

### 🚀 System Architecture

**Orchestrator** (374 lines)
- Concurrent monitoring using asyncio
- Multi-monitor coordination
- Smart threat aggregation
- Automatic deduplication
- Graceful shutdown handling

**CLI Interface** (319 lines)
```bash
privasee start      # Start continuous monitoring
privasee scan       # One-time security scan
privasee status     # Check system health
privasee config     # View configuration
privasee alerts     # Show recent threats
privasee dashboard  # Launch web dashboard (NEW in v0.3.0)
```

**Rich console output with tables and color-coded severity indicators**

### 🔧 Infrastructure

- **Configuration System** (180 lines) - YAML support, environment variables, validation
- **Device Info Extractor** (796 lines) - iOS backup parsing, profile extraction
- **File Watcher** (97 lines) - Real-time directory monitoring
- **Logger** (97 lines) - JSON/text formatting, structured logging
- **Crypto Module** (123 lines) - AES-256 encryption, SHA hashing

### 📊 Test Coverage

**322 Tests - 312 passing, 10 skipped, 73% line coverage**
```
tests/
├── unit/ (~250 tests)
│   ├── VPN integrity, API abuse, carrier detection
│   ├── Certificate validation, crypto operations
│   └── Configuration, logging, file watching
│
└── integration/ (~51 tests)
    ├── Backup monitoring workflow
    ├── Real attack pattern detection
    └── End-to-end monitoring scenarios
```

Many tests use **real attack logs** from the January 26, 2026 incident as fixtures.
That provenance is a genuine strength — the rules were written against traffic that
actually happened, not invented scenarios.

It is not the same as validation. The rules were derived from **one** incident, and
the suite overwhelmingly tests that detection *fires* rather than that it stays quiet:
roughly **4% of tests exercise benign input**. Until that gap closes, treat the
false-positive rate as unmeasured. `ASSESSMENT.md` §3 grades every rule individually
and §4 specifies the negative-test suite that would close it.

### 🔒 Privacy-First Design

- **100% Local Processing** - All analysis on your machine
- **No Cloud Dependencies** - Fully self-hosted, no external services
- **Data Sovereignty** - You control all security data
- **Encrypted Backups Supported** - Works with both encrypted and unencrypted iOS backups
- **Open Source** - Full code transparency, audit the security yourself

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│              PrivaseeAI Security CLI                     │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Threat Orchestrator (asyncio)             │  │
│  └────┬─────────────┬──────────────┬─────────────┬──┘  │
│       │             │              │             │      │
│  ┌────▼──────┐ ┌───▼────────┐ ┌──▼─────────┐ ┌─▼────┐ │
│  │    VPN    │ │    API     │ │  Carrier   │ │Backup│ │
│  │ Integrity │ │   Abuse    │ │Compromise  │ │ Mon  │ │
│  │  Monitor  │ │  Monitor   │ │  Detector  │ │itor  │ │
│  └────┬──────┘ └────┬───────┘ └──┬─────────┘ └─┬────┘ │
│       │             │             │              │      │
│       └─────────────┴─────────────┴──────────────┘      │
│                            │                             │
│                   ┌────────▼────────┐                   │
│                   │ Threat Aggregator│                   │
│                   │  & Deduplication │                   │
│                   └────────┬────────┘                   │
│                            │                             │
│                   ┌────────▼────────┐                   │
│                   │     Telegram     │                   │
│                   │     Alerter      │                   │
│                   └──────────────────┘                   │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** (required)
- **macOS** with iOS device backup capability
- **iPhone** with iOS 14+ (tested on iPhone 16 Pro, iOS 18.2)
- **Telegram Bot** (optional, for alerts)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# 2. Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install package in development mode
pip install -e .

# 5. Verify installation
privasee --help
```

### Basic Usage

```bash
# Start continuous monitoring
privasee start

# Run one-time scan
privasee scan

# Check system status
privasee status

# View configuration
privasee config

# View recent alerts
privasee alerts

# Launch web dashboard
privasee dashboard
# Visit http://localhost:8000
```

### Optional: Telegram Alerts

```bash
# 1. Create bot with @BotFather on Telegram
# 2. Get your bot token and chat ID
# 3. Configure alerts

export TELEGRAM_BOT_TOKEN="your_token_here"
export TELEGRAM_CHAT_ID="your_chat_id"

# Or add to .env file
echo "TELEGRAM_BOT_TOKEN=your_token" >> .env
echo "TELEGRAM_CHAT_ID=your_chat_id" >> .env
```

## 📖 Documentation

### Getting Started
- **[ROADMAP.md](ROADMAP.md)** - Development timeline and completed features
- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete non-technical walkthrough (657 lines)
- **[QUICK_START.md](QUICK_START.md)** - Fast-track setup guide

### Advanced Usage
- **[iOS_DEVICE_TESTING_GUIDE.md](iOS_DEVICE_TESTING_GUIDE.md)** - Live device monitoring setup
- **[ORCHESTRATOR_GUIDE.md](ORCHESTRATOR_GUIDE.md)** - CLI usage and architecture
- **[Technical Specification](privaseeAI_iOS_Threat_Detection_Spec.md)** - Complete technical spec (54KB)

### Development
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute
- **[SECURITY.md](SECURITY.md)** - Security policy and vulnerability reporting
- **[TESTING_SUMMARY.md](TESTING_SUMMARY.md)** - Test infrastructure overview
- **[.github/SOCIAL_PREVIEW_SETUP.md](.github/SOCIAL_PREVIEW_SETUP.md)** - Social media preview image setup

## 🎯 Use Cases

### Individual Users
- Monitor your iPhone for sophisticated attacks
- Detect VPN manipulation in real-time
- Identify location tracking attempts
- Verify iOS backup integrity

### Security Professionals
- Forensic analysis of compromised devices
- Threat research and pattern identification
- Security auditing for clients
- Incident response tool

### Privacy Advocates
- Verify carrier-level security
- Monitor for government surveillance
- Detect spyware and tracking
- Maintain digital privacy

## 🔍 Real-World Validation

### Built from Actual Attack

On **January 26, 2026**, the developer's iPhone was compromised at the carrier level. This system was built to detect and prevent such attacks:

**Attack Patterns Detected:**
- ✅ UDP blocking forcing WireGuard to TCP
- ✅ API rate limiting (50-minute cooldown) for location tracking
- ✅ Server hopping (4 servers in 7 minutes)
- ✅ Certificate manipulation attempts
- ✅ DNS64 tampering

**Every detection rule is validated against these real attack logs.**

### Test Validation

- **iPhone 16 Pro** (iOS 18.2) - Full validation
- **iPhone 12+** (iOS 14+) - Expected to work
- **macOS Ventura/Sonoma** - Tested and working

## 🗺️ Roadmap

### ✅ Phase 0-2: MVP Complete (Weeks 1-6)
- Core monitoring system
- CLI interface
- Real-time alerting
- Comprehensive testing
- **Status:** Shipped v0.3.0-alpha

### 🔄 Phase 3: Production Deployment (February 2026)
- Background service (launchd)
- Auto-start on boot
- Log rotation
- Crash recovery
- **Status:** In Progress

### 📅 Phase 4: Persistence Layer (March 2026)
- PostgreSQL + TimescaleDB
- Historical analysis
- Multi-device support (3+ devices)
- Query API

### 📅 Phase 5: Web Dashboard (March-April 2026)
- FastAPI REST API
- React dashboard
- Real-time visualization
- Configuration UI
- PDF reports

### 📅 Phase 6+: Advanced Features (Q2-Q4 2026)
- AI/ML anomaly detection
- SIEM integrations
- Enterprise features
- Mobile apps

**See [ROADMAP.md](ROADMAP.md) for detailed timeline and milestones.**

## 🤝 Contributing

We welcome contributions! This project needs:

**High Priority:**
- 🔴 Beta testers with iPhones (iOS 14+)
- 🔴 Python developers for dashboard
- 🟠 UI/UX designers
- 🟠 Technical writers
- 🟡 Security researchers

**Getting Started:**
1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Check [open issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
3. Look for `good first issue` labels
4. Fork, code, test, submit PR

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| Production Code | 7,469 lines Python |
| Test Code | 5,963 lines |
| Tests | 322 (312 passing, 10 skipped) |
| Line Coverage | 73% (as published by the repo's own coverage workflow) |
| Negative-test coverage | ~4% (see ASSESSMENT.md §4) |
| Test Fixtures | Real attack logs (Jan 26, 2026 incident) |

## 🛡️ Security

**Reporting Vulnerabilities:**
- **DO NOT** open public issues for security vulnerabilities
- Email: security@aurelianware.com
- See [SECURITY.md](SECURITY.md) for responsible disclosure process

**Security Features:**
- All analysis happens locally
- No telemetry or tracking
- Encrypted backup support
- Open source for full auditability

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

**TL;DR:** You can use, modify, and distribute this software commercially or non-commercially, with attribution.

## 🙏 Acknowledgments

**Built on the shoulders of giants:**
- **iOS Security Community** - Threat intelligence and research
- **MVT Project** - Mobile Verification Toolkit indicators
- **Amnesty Tech** - NSO Pegasus research and STIX feeds
- **ProtonVPN** - Certificate fingerprint baseline for validation
- **Real-World Attack** - January 26, 2026 incident that motivated this project

## 📞 Support & Community

- **Issues:** [Report bugs or request features](https://github.com/aurelianware/PrivaseeAI.Security/issues)
- **Discussions:** [Ask questions and share ideas](https://github.com/aurelianware/PrivaseeAI.Security/discussions)
- **Email:** support@aurelianware.com

## ⚠️ Disclaimer

**Legal Notice:** This tool is designed for monitoring YOUR OWN devices for security threats. Unauthorized monitoring of devices you do not own or have explicit permission to monitor may be illegal in your jurisdiction. Always respect privacy laws and obtain proper authorization.

**Use at Your Own Risk:** This software is provided "as is" without warranty. While we strive for accuracy, false positives and false negatives may occur. Always verify threats independently.

## 🌟 Star History

If you find this project useful, please consider:
- ⭐ **Starring the repository** on GitHub
- 🐛 **Reporting issues** you encounter
- 💡 **Suggesting features** you'd like to see
- 🤝 **Contributing code** or documentation
- 📢 **Sharing** with others who might benefit

---

**Built with 🛡️ by privacy advocates, for privacy advocates.**

**Status:** v0.3.0-alpha | active development | 312 tests passing | see [`ASSESSMENT.md`](ASSESSMENT.md)

[Get Started](#-quick-start) | [Documentation](#-documentation) | [Contribute](#-contributing) | [Roadmap](ROADMAP.md)
