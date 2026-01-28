#!/bin/bash
# VPN Monitor Daemon Control Script

PLIST_FILE="com.privaseeai.vpnmonitor.plist"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$PLIST_FILE"
SOURCE_PLIST="$(cd "$(dirname "$0")" && pwd)/$PLIST_FILE"

case "$1" in
    install)
        echo "Installing VPN Monitor Daemon..."
        
        # Create LaunchAgents directory if it doesn't exist
        mkdir -p "$LAUNCH_AGENTS_DIR"
        
        # Copy plist file
        cp "$SOURCE_PLIST" "$PLIST_PATH"
        echo "✓ Copied $PLIST_FILE to $LAUNCH_AGENTS_DIR"
        
        # Load the daemon
        launchctl load "$PLIST_PATH"
        echo "✓ Daemon loaded and started"
        
        echo ""
        echo "VPN Monitor Daemon is now running!"
        echo "Logs: /tmp/vpn_monitor_daemon.log"
        echo "Alerts: /tmp/vpn_monitor_alerts.txt"
        ;;
        
    uninstall)
        echo "Uninstalling VPN Monitor Daemon..."
        
        # Unload the daemon
        launchctl unload "$PLIST_PATH" 2>/dev/null
        echo "✓ Daemon stopped"
        
        # Remove plist file
        rm -f "$PLIST_PATH"
        echo "✓ Removed $PLIST_FILE from $LAUNCH_AGENTS_DIR"
        
        echo ""
        echo "VPN Monitor Daemon has been uninstalled"
        ;;
        
    start)
        echo "Starting VPN Monitor Daemon..."
        launchctl load "$PLIST_PATH"
        echo "✓ Daemon started"
        ;;
        
    stop)
        echo "Stopping VPN Monitor Daemon..."
        launchctl unload "$PLIST_PATH"
        echo "✓ Daemon stopped"
        ;;
        
    restart)
        echo "Restarting VPN Monitor Daemon..."
        launchctl unload "$PLIST_PATH" 2>/dev/null
        sleep 1
        launchctl load "$PLIST_PATH"
        echo "✓ Daemon restarted"
        ;;
        
    status)
        echo "VPN Monitor Daemon Status:"
        echo ""
        
        if launchctl list | grep -q "com.privaseeai.vpnmonitor"; then
            echo "Status: ✅ RUNNING"
            echo ""
            echo "Recent log entries:"
            tail -20 /tmp/vpn_monitor_daemon.log 2>/dev/null || echo "No log file found"
        else
            echo "Status: ❌ NOT RUNNING"
        fi
        ;;
        
    logs)
        echo "Showing daemon logs (Ctrl+C to exit)..."
        tail -f /tmp/vpn_monitor_daemon.log
        ;;
        
    alerts)
        echo "Recent alerts:"
        if [ -f /tmp/vpn_monitor_alerts.txt ]; then
            tail -50 /tmp/vpn_monitor_alerts.txt
        else
            echo "No alerts yet"
        fi
        ;;
        
    test)
        echo "Running daemon in test mode..."
        cd "$(dirname "$0")"
        source .venv/bin/activate
        python3 vpn_monitor_daemon.py --test --log-dir .
        ;;
        
    *)
        echo "VPN Monitor Daemon Control Script"
        echo ""
        echo "Usage: $0 {install|uninstall|start|stop|restart|status|logs|alerts|test}"
        echo ""
        echo "Commands:"
        echo "  install    - Install and start the daemon"
        echo "  uninstall  - Stop and remove the daemon"
        echo "  start      - Start the daemon"
        echo "  stop       - Stop the daemon"
        echo "  restart    - Restart the daemon"
        echo "  status     - Check daemon status"
        echo "  logs       - Show live daemon logs"
        echo "  alerts     - Show recent alerts"
        echo "  test       - Run a test scan"
        exit 1
        ;;
esac

exit 0
