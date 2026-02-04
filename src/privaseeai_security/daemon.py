"""Daemon entry point for PrivaseeAI Security orchestrator.

This module provides a standalone entry point for running the orchestrator
as a background service via launchd or other init systems.

Usage:
    python -m privaseeai_security.daemon
"""

import asyncio
import signal
import sys
from typing import Optional

from .orchestrator import ThreatOrchestrator
from .logger import get_logger


logger = get_logger(__name__)


# Global orchestrator instance for signal handling
_orchestrator: Optional[ThreatOrchestrator] = None


async def run_daemon():
    """Run the threat orchestrator as a daemon service."""
    global _orchestrator
    
    # Create shutdown event inside async context
    shutdown_event = asyncio.Event()
    
    def _signal_handler(signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        shutdown_event.set()
    
    # Setup signal handlers
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
    
    logger.info("Starting PrivaseeAI Security daemon...")
    
    # Create orchestrator instance
    _orchestrator = ThreatOrchestrator(
        backup_path=None,  # Auto-detect
        telegram_enabled=True,
        monitor_interval=30,
        scan_backups_on_start=True
    )
    
    try:
        # Start monitoring
        await _orchestrator.start()
        logger.info("✅ Orchestrator started successfully")
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        
    except Exception as e:
        logger.error(f"Daemon error: {e}", exc_info=True)
        raise
    finally:
        # Clean shutdown
        if _orchestrator:
            logger.info("Stopping orchestrator...")
            await _orchestrator.stop()
            logger.info("✅ Orchestrator stopped cleanly")


def main():
    """Main entry point for daemon."""
    # Log startup
    logger.info("PrivaseeAI Security Daemon starting...")
    
    try:
        # Run the async daemon
        asyncio.run(run_daemon())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    
    logger.info("Daemon shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
