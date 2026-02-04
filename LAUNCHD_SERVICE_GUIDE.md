# PrivaseeAI Security - launchd Service Installation Guide

This guide explains how to install, configure, and manage the PrivaseeAI Security background service using macOS launchd.

## Overview

The `com.privaseeai.security.plist` file configures PrivaseeAI Security to run as a persistent background service that:

- ✅ Runs `python -m privaseeai_security.orchestrator` automatically
- ✅ Starts on boot (user agent)
- ✅ Auto-restarts if crashed (with exponential backoff via ThrottleInterval)
- ✅ Logs to `/var/log/privaseeai/security.log`
- ✅ Runs from `/opt/privaseeai` working directory
- ✅ Executes as the current user
- ✅ Prevents rapid restart loops with 60-second throttle

## Prerequisites

1. **Python 3.11+** installed at `/usr/bin/python3`
2. **PrivaseeAI Security** installed as a Python package
3. **Proper permissions** to write to `/var/log/privaseeai/`

## Installation Steps

### 1. Install PrivaseeAI Security Package

First, ensure the package is installed in your Python environment:

```bash
# From the repository root
pip install -e .

# Verify installation
python3 -m privaseeai_security --version
```

### 2. Create Required Directories

Create the log directory with proper permissions:

```bash
# Create log directory
sudo mkdir -p /var/log/privaseeai

# Set ownership to current user
sudo chown $(whoami):staff /var/log/privaseeai

# Set appropriate permissions
chmod 755 /var/log/privaseeai
```

### 3. Set Up Working Directory

Create and configure the working directory:

```bash
# Create working directory
sudo mkdir -p /opt/privaseeai

# Set ownership to current user
sudo chown $(whoami):staff /opt/privaseeai

# Copy or link your configuration files
# (Optional - adjust based on your setup)
# cp config.yaml /opt/privaseeai/
```

### 4. Configure Environment Variables (Optional)

If you need Telegram alerts, set environment variables in the plist or create a configuration file:

```bash
# Option 1: Edit the plist file to add your tokens
# Edit com.privaseeai.security.plist and add to EnvironmentVariables:
#   <key>TELEGRAM_BOT_TOKEN</key>
#   <string>your_bot_token_here</string>
#   <key>TELEGRAM_CHAT_ID</key>
#   <string>your_chat_id_here</string>

# Option 2: Use a .env file in /opt/privaseeai/
cat > /opt/privaseeai/.env << 'EOF'
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
EOF
chmod 600 /opt/privaseeai/.env
```

### 5. Install the launchd Service

Copy the plist file to the user's LaunchAgents directory:

```bash
# Copy plist to LaunchAgents
cp com.privaseeai.security.plist ~/Library/LaunchAgents/

# Verify the file is in place
ls -l ~/Library/LaunchAgents/com.privaseeai.security.plist
```

## Loading and Managing the Service

### Load the Service

Start the service immediately and enable auto-start on boot:

```bash
# Load and start the service
launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist

# Alternative: Bootstrap (recommended on macOS 11+)
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.privaseeai.security.plist
```

### Check Service Status

Verify the service is running:

```bash
# List loaded services and check if ours is running
launchctl list | grep com.privaseeai.security

# Get detailed status
launchctl print gui/$(id -u)/com.privaseeai.security
```

Expected output for running service:
```
12345   0       com.privaseeai.security
```
(PID, exit code, label)

### View Service Logs

Monitor the service logs in real-time:

```bash
# Tail the log file
tail -f /var/log/privaseeai/security.log

# View last 100 lines
tail -n 100 /var/log/privaseeai/security.log

# Search for errors
grep -i error /var/log/privaseeai/security.log
```

### Restart the Service

If you need to restart the service:

```bash
# Stop the service
launchctl stop com.privaseeai.security

# Start the service (it will auto-restart due to KeepAlive)
launchctl start com.privaseeai.security

# Or unload and reload
launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist
launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist
```

### Stop and Unload the Service

To completely stop and disable the service:

```bash
# Unload the service (stops it and disables auto-start)
launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist

# Alternative: Bootout (recommended on macOS 11+)
launchctl bootout gui/$(id -u)/com.privaseeai.security
```

## Testing the Service

### Basic Functionality Test

1. **Load the service:**
   ```bash
   launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist
   ```

2. **Check if it's running:**
   ```bash
   launchctl list | grep com.privaseeai.security
   ps aux | grep "privaseeai_security.orchestrator"
   ```

3. **Verify logs are being written:**
   ```bash
   tail -f /var/log/privaseeai/security.log
   ```
   
   You should see startup messages like:
   ```
   INFO - Starting PrivaseeAI Security Orchestrator daemon...
   INFO - ✅ Orchestrator daemon started
   ```

### Crash Recovery Test

Test the auto-restart functionality:

1. **Find the service PID:**
   ```bash
   launchctl list | grep com.privaseeai.security
   # Note the PID (first column)
   ```

2. **Kill the process:**
   ```bash
   kill -9 <PID>
   ```

3. **Wait 60 seconds (ThrottleInterval), then check:**
   ```bash
   launchctl list | grep com.privaseeai.security
   ```
   
   The service should have a new PID, indicating it restarted automatically.

4. **Check logs for restart:**
   ```bash
   grep -A 5 "Orchestrator daemon started" /var/log/privaseeai/security.log | tail -20
   ```

### Boot Persistence Test

Test auto-start on boot:

1. **Reboot your system**
2. **After login, check service status:**
   ```bash
   launchctl list | grep com.privaseeai.security
   tail /var/log/privaseeai/security.log
   ```

### Manual Invocation Test

Test running the orchestrator manually (without launchd):

```bash
# Run directly
cd /opt/privaseeai
python3 -m privaseeai_security.orchestrator

# Should start and show logs in terminal
# Press Ctrl+C to stop
```

## Troubleshooting

### Service Won't Start

1. **Check Python installation:**
   ```bash
   which python3
   /usr/bin/python3 --version  # Should be 3.11+
   ```

2. **Verify package installation:**
   ```bash
   python3 -c "import privaseeai_security; print(privaseeai_security.__version__)"
   ```

3. **Check permissions:**
   ```bash
   ls -la /var/log/privaseeai/
   ls -la /opt/privaseeai/
   ```

4. **View system logs:**
   ```bash
   log show --predicate 'process == "launchd"' --last 5m | grep privaseeai
   ```

### Service Crashes Immediately

1. **Check error logs:**
   ```bash
   tail -50 /var/log/privaseeai/security.log
   ```

2. **Test manual execution:**
   ```bash
   cd /opt/privaseeai
   python3 -m privaseeai_security.orchestrator
   ```

3. **Check for missing dependencies:**
   ```bash
   python3 -c "from privaseeai_security.orchestrator import ThreatOrchestrator"
   ```

### Logs Not Appearing

1. **Verify log directory permissions:**
   ```bash
   ls -la /var/log/privaseeai/
   ```

2. **Check if process can write:**
   ```bash
   sudo -u $(whoami) touch /var/log/privaseeai/test.log
   rm /var/log/privaseeai/test.log
   ```

3. **Ensure PYTHONUNBUFFERED is set** (already in plist)

## Configuration Reference

### Key launchd Properties

- **Label**: `com.privaseeai.security` - Unique service identifier
- **RunAtLoad**: `true` - Start on boot/load
- **KeepAlive**: Configured to restart on any exit
- **ThrottleInterval**: `60` seconds - Prevents rapid restart loops
- **WorkingDirectory**: `/opt/privaseeai` - Where service runs from
- **StandardOutPath/StandardErrorPath**: `/var/log/privaseeai/security.log` - Log location
- **LimitLoadToSessionType**: `Aqua` - User agent (not system daemon)

### Environment Variables

The plist includes:
- `PATH`: Standard system PATH
- `PYTHONUNBUFFERED`: `1` - Force unbuffered output for immediate logs

## Advanced Configuration

### Custom Python Interpreter

If you use a virtual environment:

1. **Edit the plist file:**
   ```xml
   <key>ProgramArguments</key>
   <array>
       <string>/path/to/your/venv/bin/python3</string>
       <string>-m</string>
       <string>privaseeai_security.orchestrator</string>
   </array>
   ```

2. **Reload the service:**
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist
   launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist
   ```

### Custom Backup Path

Modify the plist to pass backup path as environment variable:

```xml
<key>EnvironmentVariables</key>
<dict>
    <!-- existing vars -->
    <key>PRIVASEE_BACKUP_PATH</key>
    <string>/path/to/ios/backups</string>
</dict>
```

Then update orchestrator.py to read this environment variable.

### Adjust Throttle Interval

Change crash recovery timing:

```xml
<key>ThrottleInterval</key>
<integer>120</integer>  <!-- Wait 2 minutes instead of 60 seconds -->
```

## Uninstallation

To completely remove the service:

```bash
# 1. Unload the service
launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist

# 2. Remove the plist file
rm ~/Library/LaunchAgents/com.privaseeai.security.plist

# 3. (Optional) Remove log files
sudo rm -rf /var/log/privaseeai/

# 4. (Optional) Remove working directory
sudo rm -rf /opt/privaseeai/
```

## Security Considerations

1. **Never store secrets in the plist file** - Use environment files or macOS Keychain
2. **Limit log file permissions** - Only the service user should read/write logs
3. **Regularly rotate logs** - Use `newsyslog` or similar tools
4. **Monitor for unusual behavior** - Check logs regularly for errors

## Support

For issues or questions:
- Check logs: `/var/log/privaseeai/security.log`
- GitHub Issues: https://github.com/aurelianware/PrivaseeAI.Security/issues
- Documentation: See README.md and USER_GUIDE.md

## Quick Reference Card

```bash
# Install
cp com.privaseeai.security.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.privaseeai.security.plist

# Status
launchctl list | grep com.privaseeai.security

# Logs
tail -f /var/log/privaseeai/security.log

# Restart
launchctl stop com.privaseeai.security

# Uninstall
launchctl unload ~/Library/LaunchAgents/com.privaseeai.security.plist
rm ~/Library/LaunchAgents/com.privaseeai.security.plist
```
