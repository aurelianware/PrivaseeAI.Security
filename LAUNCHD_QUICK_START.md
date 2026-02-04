# Quick Start: launchd Service

This is a quick reference for installing and running PrivaseeAI Security as a macOS background service.

## Files Created

1. **com.privaseeai.security.plist** - launchd configuration file
2. **LAUNCHD_SERVICE_GUIDE.md** - Complete installation and management guide
3. **src/privaseeai_security/daemon.py** - Alternative daemon entry point
4. **Orchestrator daemon mode** - Added `__main__` block to orchestrator.py

## Quick Installation

```bash
# 1. Install the package
pip install -e .

# 2. Create required directories
sudo mkdir -p /var/log/privaseeai /opt/privaseeai
sudo chown $(whoami):staff /var/log/privaseeai /opt/privaseeai
chmod 700 /var/log/privaseeai

# 3. Install the service
cp com.privaseeai.security.plist ~/Library/LaunchAgents/

# 4. Load and start
launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist

# 5. Verify it's running
launchctl list | grep com.privaseeai.security
tail -f /var/log/privaseeai/security.log
```

## Service Features

✅ **Auto-start on boot** - Runs automatically when you log in  
✅ **Auto-restart on crash** - Keeps running with 60-second minimum restart delay  
✅ **Centralized logging** - All output goes to `/var/log/privaseeai/security.log`  
✅ **User agent** - Runs as your user, not as root  
✅ **Python module execution** - Runs via `python -m privaseeai_security.orchestrator`

## Quick Commands

```bash
# Status
launchctl list | grep com.privaseeai.security

# Logs
tail -f /var/log/privaseeai/security.log

# Restart
launchctl stop com.privaseeai.security

# Unload
launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist
```

## Test the Service

```bash
# Run the complete test suite
python3 -m pytest tests/unit/test_launchd_service.py -v

# Test running orchestrator manually
python3 -m privaseeai_security.orchestrator
# Press Ctrl+C to stop
```

## For Full Documentation

See **LAUNCHD_SERVICE_GUIDE.md** for:
- Detailed installation steps
- Configuration options
- Troubleshooting guide
- Advanced customization
- Security considerations
