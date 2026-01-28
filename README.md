# PrivaseeAI.Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Report%20Vulnerabilities-red.svg)](SECURITY.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Test Suite](https://github.com/aurelianware/PrivaseeAI.Security/actions/workflows/test.yml/badge.svg)](https://github.com/aurelianware/PrivaseeAI.Security/actions/workflows/test.yml)
[![Code Quality](https://github.com/aurelianware/PrivaseeAI.Security/actions/workflows/code-quality.yml/badge.svg)](https://github.com/aurelianware/PrivaseeAI.Security/actions/workflows/code-quality.yml)

**Real-Time iOS Threat Detection & Monitoring System**

PrivaseeAI.Security is a privacy-preserving iOS threat detection system that provides continuous security monitoring through VPN integrity checks, backup analysis, and behavioral pattern detection. All analysis happens locally on your machine, ensuring complete privacy and data sovereignty.

## 🎯 Overview

PrivaseeAI.Security monitors your iOS device for sophisticated attacks including VPN manipulation, carrier compromise, and API abuse. Unlike traditional periodic scans, it provides continuous real-time monitoring with instant Telegram alerts when threats are detected.

## ✨ Current Features (MVP v0.1.0)

### 🛡️ Real-Time Threat Detection
- **VPN Integrity Monitoring**: Detects TCP fallback, forced reconnections, and server hopping
- **API Abuse Detection**: Identifies rate limiting and location tracking attempts
- **Carrier Compromise Detection**: Scans iOS backups for suspicious profiles and configurations
- **Certificate Validation**: Verifies VPN certificates against known-good fingerprints

### 🚀 Continuous Monitoring
- **Concurrent Multi-Monitor System**: All monitors run simultaneously using asyncio
- **Incremental Backup Analysis**: Automatically scans new iOS backups as they're created
- **Live VPN Log Monitoring**: Real-time analysis of WireGuard and ProtonVPN logs
- **Threat Aggregation**: Deduplicates and prioritizes threats from all sources

### 📱 Alert System
- **Telegram Integration**: Instant alerts for CRITICAL and HIGH severity threats
- **Detailed Threat Reports**: Complete context including indicators and timestamps
- **Configurable Thresholds**: Customize what triggers alerts

### 🔧 Easy to Use
- **Simple CLI**: `privasee start`, `privasee scan`, `privasee config`
- **Auto-Configuration**: Automatically detects iOS backup locations
- **YAML Configuration**: Easy to customize and manage
- **Comprehensive Logging**: Full audit trail of all detections

### 🔒 Privacy-First Design
- **100% Local Processing**: All analysis happens on your machine
- **No Cloud Dependencies**: Fully self-hosted, no external services required
- **Encrypted Backups Supported**: Works with both encrypted and unencrypted iOS backups
- **Data Sovereignty**: You control all your security data

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

For detailed documentation, see:
- [Orchestrator Guide](ORCHESTRATOR_GUIDE.md) - How to use the CLI
- [iOS Testing Guide](iOS_DEVICE_TESTING_GUIDE.md) - Live device monitoring setup
- [Technical Specification](privaseeAI_iOS_Threat_Detection_Spec.md) - Attack patterns and detection logic

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** (required)
- **macOS** with iOS device backup capability
- **Telegram Bot** (optional, for alerts)

### Installation

```bash
# Clone the repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# Install dependencies
pip install -r requirements.txt

# Install CLI tool
pip install -e .

# Verify installation
privasee --version
```

### Basic Usage

```bash
# Check configuration and system status
privasee config

# Run a one-time security scan
privasee scan

# Start continuous monitoring (Ctrl+C to stop)
privasee start

# Start with custom interval (seconds)
privasee start --interval 120

# Start without Telegram alerts
privasee start --no-telegram
```

### Configure Telegram Alerts (Optional)

```bash
# 1. Create bot with @BotFather on Telegram
# 2. Get your bot token
# 3. Message your bot, then get chat ID from:
curl https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates

# 4. Add to your shell config (~/.zshrc or ~/.bashrc):
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"

# 5. Reload and verify
source ~/.zshrc
privasee config  # Should show "Telegram Configured: ✅ Yes"
```

### What Gets Monitored

**Automatic:**
- iOS backups in `~/Library/Application Support/MobileSync/Backup`
- VPN logs (if configured)
- Suspicious patterns and configurations

**Manual Setup (for live monitoring):**
- See [iOS Device Testing Guide](iOS_DEVICE_TESTING_GUIDE.md) for live VPN log monitoring
cd PrivaseeAI.Security

# Copy and configure environment variables (optional for development)
cp .env.example .env

# Start all services with Docker Compose
docker compose up -d

# Check service status
docker compose ps

# View logs
docker compose logs -f
```

Your infrastructure services will be available at:
- TimescaleDB: localhost:5432
- Redis: localhost:6379

> **Note**: The application runs as a background monitoring service and does not currently expose an HTTP API. A web interface will be added in future releases.

For detailed Docker usage, see [Docker Documentation](docs/docker.md).

#### Option 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
# (Coming in future releases)

# Start the service
# (Coming in future releases)
```

### Basic Usage## 🔍 Example Output

```bash
$ privasee scan

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ PrivaseeAI Security Scan       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

🔍 Scanning iOS backups...
📁 Found backup: 00008030-001234567890001E

Threats Detected:
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Severity  ┃ Type       ┃ Count   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━┩
│ CRITICAL  │ VPN_MITM   │ 0       │
│ HIGH      │ CARRIER    │ 2       │
│ MEDIUM    │ API_ABUSE  │ 1       │
└───────────┴────────────┴─────────┘

✅ Scan complete
```

```bash
$ privasee start

🚀 Starting PrivaseeAI Security Orchestrator
Running initial backup scan...
Initial scan complete: 2 carrier threats found

✅ Monitoring started successfully
Press Ctrl+C to stop

[2026-01-28 15:30:45] 🔴 CRITICAL: TRANSPORT_MANIPULATION detected
[2026-01-28 15:30:45] 📱 Telegram alert sent
```

## 🔧 Technology Stack

### Core
- **Python 3.11+**: Main implementation language
- **asyncio**: Concurrent monitor execution
- **click**: CLI framework
- **rich**: Terminal UI and formatting
- **PyYAML**: Configuration management

### iOS Integration  
- **libimobiledevice**: iOS device communication (optional, for live logs)
- **plistlib**: iOS backup plist parsing

### Security
- **cryptography**: Certificate validation and encryption
- **python-telegram-bot**: Alert notifications

### Testing
- **pytest**: Test framework (192 tests, 71% coverage)
- **pytest-asyncio**: Async test support
- **pytest-cov**: Coverage reporting

## 🗺️ Roadmap

### Planned Features (Future Releases)

**Enhanced Detection:**
- ML-based anomaly detection for behavioral patterns
- STIX/TAXII threat intelligence integration
- Network traffic analysis and packet inspection
- USB connection tracking and monitoring

**Infrastructure:**
- PostgreSQL + TimescaleDB for historical data
- FastAPI REST API for remote monitoring
- Redis for real-time event streaming
- Prometheus/Grafana dashboards

**Advanced Analysis:**
- PyTorch models for pattern recognition
- Vector database for threat correlation
- Forensic evidence collection and reporting
- Multi-device fleet management

See [ROADMAP.md](ROADMAP.md) for detailed timeline and priorities.

## 📚 Documentation

- **[Orchestrator Guide](ORCHESTRATOR_GUIDE.md)** - Complete CLI usage and configuration
- **[iOS Device Testing Guide](iOS_DEVICE_TESTING_GUIDE.md)** - Live VPN log monitoring setup
- **[Quick Start Guide](QUICK_START.md)** - Week-by-week implementation guide
- **[Technical Specification](privaseeAI_iOS_Threat_Detection_Spec.md)** - Attack patterns and detection rules
- **[Contributing Guidelines](CONTRIBUTING.md)** - How to contribute
- **[Security Policy](SECURITY.md)** - Vulnerability reporting
- **[Roadmap](ROADMAP.md)** - Future plans and timeline

## 🤝 Contributing

We welcome contributions from the community! Whether you're fixing bugs, adding features, improving documentation, or spreading the word, your help is appreciated.

Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before getting started.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our coding standards
4. Write or update tests as needed
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 🔒 Security

Security is our top priority. If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) for responsible disclosure.

**Do not** report security vulnerabilities through public GitHub issues.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [privaseeAI](https://github.com/aurelianware/privaseeAI) - The main PrivaseeAI platform
- [CloudHealthOffice](https://github.com/aurelianware/cloudhealthoffice) - Cloud health monitoring companion

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for security contact
- **Discussions**: [GitHub Discussions](https://github.com/aurelianware/PrivaseeAI.Security/discussions)

## 🙏 Acknowledgments

This project builds upon the foundation of privacy-focused security tools and threat detection research. Special thanks to the open-source community for tools like libimobiledevice and the iOS security research community.

---

**Status**: MVP v0.1.0 - Functional and ready for testing. See [Roadmap](#-roadmap) for planned enhancements.
