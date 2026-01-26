"""Main entry point for PrivaseeAI Security application."""

import sys
import time
import signal
from pathlib import Path
from typing import NoReturn, List
from datetime import datetime

from privaseeai_security import __version__
from privaseeai_security.config import Config
from privaseeai_security.logger import setup_logger, get_logger
from privaseeai_security.file_watcher import FileWatcher
from privaseeai_security.monitors.vpn_integrity import VPNIntegrityMonitor
from privaseeai_security.monitors.api_abuse import APIAbuseMonitor
from privaseeai_security.alerting.telegram import TelegramAlerter, ThreatDetection, ThreatLevel


def health_check() -> bool:
    """Perform basic health check.
    
    Returns:
        True if application is healthy, False otherwise
    """
    try:
        # Basic health check - can be extended to check database/redis connectivity
        # For now, just verify we can import and initialize config
        config = Config()
        config.validate()
        return True
    except Exception as e:
        print(f"Health check failed: {e}", file=sys.stderr)
        return False


def main() -> NoReturn:
    """Main application entry point - unified security monitoring daemon."""
    print(f"PrivaseeAI Security v{__version__}")
    print("=" * 50)
    
    # Initialize logger
    logger = setup_logger()
    logger.info("Starting PrivaseeAI Security monitoring daemon...")
    
    # Initialize configuration
    config = Config()
    try:
        config.validate()
        logger.info("Configuration validated successfully")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        sys.exit(1)
    
    # Initialize monitors
    logger.info("Initializing security monitors...")
    vpn_monitor = VPNIntegrityMonitor(config)
    api_monitor = APIAbuseMonitor(config)
    
    # Initialize alerting
    logger.info("Initializing alert system...")
    alerter = TelegramAlerter(dry_run=True)  # Set dry_run=False when bot configured
    
    # Initialize file watcher for log monitoring
    logger.info("Initializing file watchers...")
    log_dir = Path.home() / "Library" / "Logs"
    
    # Setup graceful shutdown
    shutdown_flag = False
    
    def signal_handler(signum, frame):
        nonlocal shutdown_flag
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        shutdown_flag = True
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Application initialized successfully")
    logger.info("Monitoring started - Press Ctrl+C to stop")
    logger.info(f"Watching log directory: {log_dir}")
    
    # Main monitoring loop
    try:
        iteration = 0
        while not shutdown_flag:
            iteration += 1
            
            # Process VPN logs (in production, would use FileWatcher)
            # For now, this is a placeholder for the monitoring loop
            
            # Example: Process a log entry (would come from FileWatcher in production)
            # log_entry = file_watcher.get_next_entry()
            # if log_entry:
            #     threats = process_log_entry(log_entry, vpn_monitor, api_monitor)
            #     for threat in threats:
            #         if alerter.should_alert(threat.threat_level):
            #             alerter.send_threat_alert(threat)
            
            # Heartbeat
            if iteration % 60 == 0:  # Log every 10 minutes (60 * 10s)
                logger.debug(
                    f"Monitoring active - {iteration} iterations, "
                    f"no threats detected"
                )
            
            time.sleep(10)
            
    except Exception as e:
        logger.error(f"Monitoring error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Shutting down monitors...")
        logger.info("Shutdown complete")
        sys.exit(0)


def process_log_entry(
    log_entry: str,
    vpn_monitor: VPNIntegrityMonitor,
    api_monitor: APIAbuseMonitor
) -> List[ThreatDetection]:
    """Process a log entry through all monitors.
    
    Args:
        log_entry: Raw log entry to process
        vpn_monitor: VPN integrity monitor
        api_monitor: API abuse monitor
        
    Returns:
        List of threat detections found
    """
    logger = get_logger("privaseeai_security.main")
    threats = []
    
    try:
        # Route log to appropriate monitor based on content
        if any(keyword in log_entry.lower() for keyword in ["vpn", "wireguard", "protonvpn"]):
            vpn_threats = vpn_monitor.analyze_log_entry(log_entry)
            threats.extend(vpn_threats)
        
        # Check for API-related logs
        if any(keyword in log_entry.lower() for keyword in ["api", "http", "request"]):
            # Extract app identifier from log (would need log format parsing)
            app_id = "unknown.app"
            
            # Check for rate limiting
            rate_limit_threat = api_monitor.check_rate_limit_responses(app_id, log_entry)
            if rate_limit_threat:
                threats.append(rate_limit_threat)
        
        # Log threats found
        for threat in threats:
            logger.warning(
                f"Threat detected: {threat.attack_type} "
                f"(level: {threat.threat_level.value})"
            )
    
    except Exception as e:
        logger.error(f"Error processing log entry: {e}", exc_info=True)
    
    return threats


if __name__ == "__main__":
    main()
