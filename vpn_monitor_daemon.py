#!/usr/bin/env python3
"""24/7 VPN Security Monitoring Daemon

Continuously monitors VPN logs for security threats and sends real-time alerts.

Features:
- Watches VPN log files for new entries
- Detects TCP fallback, API abuse, server hopping attacks
- Sends Telegram alerts for HIGH and CRITICAL threats
- Runs in background as a daemon
- Auto-restarts on errors

Usage:
    python3 vpn_monitor_daemon.py --log-dir ~/Library/Logs/ --telegram-token YOUR_TOKEN
"""

import sys
import time
import argparse
import signal
from pathlib import Path
from datetime import datetime
from typing import List, Optional
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor
from privaseeai_security.crypto.cert_validator import ThreatLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/vpn_monitor_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class VPNMonitorDaemon:
    """Daemon for continuous VPN security monitoring."""
    
    def __init__(self, log_dirs: List[Path], telegram_token: Optional[str] = None, 
                 telegram_chat_id: Optional[str] = None):
        """Initialize the monitoring daemon.
        
        Args:
            log_dirs: List of directories containing VPN logs
            telegram_token: Telegram bot token for alerts
            telegram_chat_id: Telegram chat ID for alerts
        """
        self.log_dirs = [Path(d) for d in log_dirs]
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.running = False
        self.vpn_monitor = VPNIntegrityMonitor()
        
        # Track which log files we've seen and their positions
        self.log_files: dict[Path, int] = {}
        self.last_scan = datetime.now()
        
        # iPhone monitoring
        self.monitor_iphone = True
        self.last_iphone_log_time = datetime.now()
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def _find_log_files(self) -> List[Path]:
        """Find all VPN log files in watched directories."""
        log_files = []
        patterns = ['*WireGuard*.log', '*Application*.log', '*ProtonVPN*.log', '*vpn*.log']
        
        for log_dir in self.log_dirs:
            if not log_dir.exists():
                logger.warning(f"Log directory not found: {log_dir}")
                continue
            
            for pattern in patterns:
                log_files.extend(log_dir.glob(pattern))
        
        return log_files
    
    def _read_new_lines(self, log_file: Path) -> List[str]:
        """Read new lines from a log file since last check.
        
        Args:
            log_file: Path to log file
            
        Returns:
            List of new log lines
        """
        try:
            # Get current file size
            current_size = log_file.stat().st_size
            
            # Get last known position
            last_position = self.log_files.get(log_file, 0)
            
            # If file shrunk (rotated), start from beginning
            if current_size < last_position:
                last_position = 0
            
            # Read new content
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                self.log_files[log_file] = f.tell()
            
            return new_lines
            
        except Exception as e:
            logger.error(f"Error reading {log_file}: {e}")
            return []
    
    def _analyze_log_lines(self, log_lines: List[str], log_file: Path) -> List:
        """Analyze log lines for threats.
        
        Args:
            log_lines: List of log lines to analyze
            log_file: Source log file
            
        Returns:
            List of ThreatDetection objects
        """
        threats = []
        
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            
            try:
                # Analyze each log entry
                detections = self.vpn_monitor.analyze_log_entry(line)
                
                # Filter out NONE-level detections
                for detection in detections:
                    if detection.threat_level.value != 'NONE':
                        threats.append(detection)
                        
            except Exception as e:
                logger.error(f"Error analyzing log line: {e}")
        
        return threats
    
    def _send_alert(self, threat, log_file: Path):
        """Send alert for detected threat.
        
        Args:
            threat: ThreatDetection object
            log_file: Source log file where threat was detected
        """
        # Format alert message
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }
        
        emoji = severity_emoji.get(threat.threat_level.value, '⚠️')
        
        alert_msg = f"""
{emoji} {threat.threat_level.value} THREAT DETECTED

Type: {threat.attack_type}
Time: {threat.timestamp}
Source: {log_file.name}

Details: {threat.details}

Indicators:
{chr(10).join(f'  • {ind}' for ind in threat.indicators)}

---
PrivaseeAI Security Monitor
        """.strip()
        
        # Log the alert
        logger.warning(f"THREAT DETECTED: {threat.attack_type} - {threat.threat_level.value}")
        logger.warning(alert_msg)
        
        # Send to Telegram if configured
        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram_message(alert_msg)
        
        # Also write to alert file
        alert_file = Path('/tmp/vpn_monitor_alerts.txt')
        with open(alert_file, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"Alert Time: {datetime.now().isoformat()}\n")
            f.write(alert_msg)
            f.write(f"\n{'='*70}\n\n")
    
    def _send_telegram_message(self, message: str):
        """Send message to Telegram.
        
        Args:
            message: Message to send
        """
        try:
            import requests
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=data, timeout=10)
            if response.status_code != 200:
                logger.error(f"Telegram API error: {response.text}")
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
    
    def _check_iphone_logs(self) -> List:
        """Check for VPN-related logs on connected iPhone.
        
        Returns:
            List of threats detected in iPhone logs
        """
        threats = []
        
        try:
            import subprocess
            
            # Check if iPhone is connected
            result = subprocess.run(
                ['python3', '-m', 'pymobiledevice3', 'usbmux', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return threats
            
            # Get recent syslog entries (last 30 seconds)
            syslog_result = subprocess.run(
                ['python3', '-m', 'pymobiledevice3', 'syslog', 'live', '--filter', 'VPN'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if syslog_result.returncode == 0 and syslog_result.stdout:
                log_lines = syslog_result.stdout.strip().split('\n')
                threats = self._analyze_log_lines(log_lines, Path("iPhone-Live"))
                
                if threats:
                    logger.info(f"Detected {len(threats)} threats in iPhone logs")
            
        except Exception as e:
            logger.debug(f"iPhone log check failed: {e}")
        
        return threats
    
    def _scan_once(self):
        """Perform one scan of all log files."""
        log_files = self._find_log_files()
        
        if not log_files:
            logger.debug("No log files found")
            # Still check iPhone even if no Mac log files
        
        total_threats = 0
        
        # Scan Mac log files
        for log_file in log_files:
            # Read new lines
            new_lines = self._read_new_lines(log_file)
            
            if not new_lines:
                continue
            
            logger.debug(f"Processing {len(new_lines)} new lines from {log_file.name}")
            
            # Analyze for threats
            threats = self._analyze_log_lines(new_lines, log_file)
            
            # Send alerts for HIGH and CRITICAL threats
            for threat in threats:
                if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    self._send_alert(threat, log_file)
                    total_threats += 1
        
        # Check iPhone logs if enabled (every 30 seconds to avoid spam)
        if self.monitor_iphone and (datetime.now() - self.last_iphone_log_time).seconds >= 30:
            iphone_threats = self._check_iphone_logs()
            for threat in iphone_threats:
                if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    self._send_alert(threat, Path("iPhone-Connected"))
                    total_threats += 1
            self.last_iphone_log_time = datetime.now()
        
        if total_threats > 0:
            logger.info(f"Scan complete: {total_threats} threats detected")
        
        self.last_scan = datetime.now()
    
    def start(self, scan_interval: int = 10):
        """Start the monitoring daemon.
        
        Args:
            scan_interval: Seconds between scans
        """
        self.running = True
        logger.info("VPN Monitor Daemon started")
        logger.info(f"Watching directories: {[str(d) for d in self.log_dirs]}")
        logger.info(f"Scan interval: {scan_interval} seconds")
        
        if self.telegram_token:
            logger.info("Telegram alerts: ENABLED")
        else:
            logger.info("Telegram alerts: DISABLED (alerts will be logged only)")
        
        # Initial scan
        logger.info("Performing initial scan...")
        self._scan_once()
        
        # Main loop
        try:
            while self.running:
                time.sleep(scan_interval)
                self._scan_once()
                
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            logger.info("VPN Monitor Daemon stopped")
    
    def status(self) -> dict:
        """Get daemon status.
        
        Returns:
            Dictionary with status information
        """
        return {
            'running': self.running,
            'log_dirs': [str(d) for d in self.log_dirs],
            'monitored_files': len(self.log_files),
            'last_scan': self.last_scan.isoformat() if self.last_scan else None,
            'telegram_enabled': bool(self.telegram_token)
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='24/7 VPN Security Monitoring Daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--log-dir',
        action='append',
        help='Directory to watch for VPN logs (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--scan-interval',
        type=int,
        default=10,
        help='Seconds between log scans (default: 10)'
    )
    
    parser.add_argument(
        '--telegram-token',
        help='Telegram bot token for alerts'
    )
    
    parser.add_argument(
        '--telegram-chat-id',
        help='Telegram chat ID for alerts'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test mode: scan once and exit'
    )
    
    args = parser.parse_args()
    
    # Default log directories if none specified
    if not args.log_dir:
        default_dirs = [
            str(Path.home() / 'Library/Logs'),
            '/tmp',
            str(Path.cwd())
        ]
        log_dirs = [Path(d) for d in default_dirs if Path(d).exists()]
    else:
        log_dirs = [Path(d) for d in args.log_dir]
    
    # Create daemon
    daemon = VPNMonitorDaemon(
        log_dirs=log_dirs,
        telegram_token=args.telegram_token,
        telegram_chat_id=args.telegram_chat_id
    )
    
    if args.test:
        # Test mode: scan once and show status
        logger.info("Running in TEST mode (single scan)")
        daemon._scan_once()
        status = daemon.status()
        print("\nDaemon Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")
    else:
        # Normal mode: run continuously
        daemon.start(scan_interval=args.scan_interval)


if __name__ == '__main__':
    main()
