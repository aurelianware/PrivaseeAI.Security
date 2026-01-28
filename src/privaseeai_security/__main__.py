"""Main entry point for PrivaseeAI Security application."""

import sys

from privaseeai_security.cli import main as cli_main
from privaseeai_security import __version__


def main():
    """Main entry point - delegate to CLI."""
    # If called with no arguments, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
    
    cli_main()


if __name__ == "__main__":
    main()

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
"""Main entry point for PrivaseeAI Security application."""

import sys

from privaseeai_security.cli import main as cli_main
from privaseeai_security import __version__


def main():
    """Main entry point - delegate to CLI."""
    # If called with no arguments, show help
    if len(sys.argv) == 1:
        sys.argv.append("--help")
    
    cli_main()


if __name__ == "__main__":
    main()
