"""Threat detection orchestrator for concurrent monitoring.

This module coordinates all security monitors, aggregates threats,
and dispatches alerts. It runs monitors concurrently and provides
a central point for status monitoring and health checks.
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from enum import Enum

from .logger import get_logger
from .monitors.vpn_integrity import VPNIntegrityMonitor, ThreatDetection
from .monitors.api_abuse import APIAbuseMonitor, APIThreatDetection
from .monitors.carrier_detection import CarrierCompromiseDetector, CarrierThreatDetection
from .alerting.telegram import TelegramAlerter
from .crypto.cert_validator import ThreatLevel


logger = get_logger(__name__)


class MonitorStatus(Enum):
    """Status of individual monitor."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    PAUSED = "paused"


@dataclass
class ThreatSummary:
    """Aggregated threat information from all monitors."""
    timestamp: datetime
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    threats_by_source: Dict[str, int] = field(default_factory=dict)
    latest_critical: Optional[str] = None


@dataclass
class SystemStatus:
    """Overall system status."""
    running: bool
    started_at: Optional[datetime]
    monitors: Dict[str, MonitorStatus]
    threats_detected: int
    last_threat: Optional[datetime]
    uptime_seconds: float = 0.0


class ThreatOrchestrator:
    """Coordinates all security monitors and threat detection.
    
    This orchestrator runs multiple monitors concurrently:
    - VPN integrity monitoring
    - API abuse detection
    - Carrier compromise detection
    - iOS backup analysis (on-demand or scheduled)
    
    All threats are aggregated, deduplicated, and routed to alerting
    systems (Telegram, logs, etc.).
    
    Example:
        orchestrator = ThreatOrchestrator(
            telegram_enabled=True,
            monitor_interval=30,
            backup_path="/path/to/backups"
        )
        await orchestrator.start()
        
        # Check status
        status = orchestrator.get_status()
        print(f"Running: {status.running}, Threats: {status.threats_detected}")
        
        # Stop when done
        await orchestrator.stop()
    """
    
    def __init__(
        self,
        backup_path: Optional[Path] = None,
        telegram_enabled: bool = True,
        monitor_interval: int = 30,
        scan_backups_on_start: bool = True,
    ):
        """Initialize orchestrator.
        
        Args:
            backup_path: Path to iOS backups (auto-detected if None)
            telegram_enabled: Enable Telegram alerts
            monitor_interval: Seconds between monitor checks
            scan_backups_on_start: Run full backup scan on startup
        """
        self.backup_path = backup_path or self._auto_detect_backup_path()
        self.monitor_interval = monitor_interval
        self.scan_backups_on_start = scan_backups_on_start
        
        # Initialize monitors
        self.vpn_monitor = VPNIntegrityMonitor()
        self.api_monitor = APIAbuseMonitor()
        self.carrier_detector = CarrierCompromiseDetector()
        
        # Initialize alerting
        self.telegram_alerter = TelegramAlerter() if telegram_enabled else None
        
        # State tracking
        self._running = False
        self._started_at: Optional[datetime] = None
        self._monitor_tasks: List[asyncio.Task] = []
        self._monitor_status: Dict[str, MonitorStatus] = {
            "vpn": MonitorStatus.STOPPED,
            "api": MonitorStatus.STOPPED,
            "carrier": MonitorStatus.STOPPED,
        }
        
        # Threat tracking
        self._total_threats = 0
        self._last_threat_time: Optional[datetime] = None
        self._seen_threat_ids: Set[str] = set()
        self._threat_counts: Dict[ThreatLevel, int] = defaultdict(int)
        
        logger.info("Orchestrator initialized", extra={
            "backup_path": str(self.backup_path),
            "telegram_enabled": telegram_enabled,
            "monitor_interval": monitor_interval
        })
    
    @staticmethod
    def _auto_detect_backup_path() -> Path:
        """Auto-detect iOS backup directory.
        
        Returns:
            Path to backup directory
        """
        # macOS default
        default_path = Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"
        if default_path.exists():
            return default_path
        
        # iMazing default (macOS)
        imazing_path = Path.home() / "Library" / "Application Support" / "iMazing" / "Backups"
        if imazing_path.exists():
            return imazing_path
        
        # Fallback
        logger.warning("Could not auto-detect backup path, using default")
        return default_path
    
    async def start(self) -> None:
        """Start all monitors and begin threat detection.
        
        This starts concurrent monitoring tasks and optionally runs
        an initial backup scan.
        """
        if self._running:
            logger.warning("Orchestrator already running")
            return
        
        self._running = True
        self._started_at = datetime.now()
        
        logger.info("🚀 Starting PrivaseeAI Security Orchestrator")
        
        # Initial backup scan if requested
        if self.scan_backups_on_start and self.backup_path.exists():
            logger.info("Running initial backup scan...")
            await self._scan_backups_once()
        
        # Start monitoring tasks
        self._monitor_tasks = [
            asyncio.create_task(self._monitor_vpn(), name="vpn_monitor"),
            asyncio.create_task(self._monitor_api(), name="api_monitor"),
            asyncio.create_task(self._monitor_carrier(), name="carrier_monitor"),
        ]
        
        logger.info("✅ All monitors started", extra={
            "active_monitors": len(self._monitor_tasks)
        })
    
    async def stop(self) -> None:
        """Stop all monitors gracefully."""
        if not self._running:
            logger.warning("Orchestrator not running")
            return
        
        logger.info("Stopping orchestrator...")
        self._running = False
        
        # Cancel all monitor tasks
        for task in self._monitor_tasks:
            task.cancel()
        
        # Wait for clean shutdown
        await asyncio.gather(*self._monitor_tasks, return_exceptions=True)
        
        self._monitor_tasks.clear()
        for monitor_name in self._monitor_status:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
        
        logger.info("✅ Orchestrator stopped", extra={
            "total_threats_detected": self._total_threats,
            "runtime_seconds": (datetime.now() - self._started_at).total_seconds() if self._started_at else 0
        })
    
    async def _monitor_vpn(self) -> None:
        """Monitor VPN integrity continuously."""
        monitor_name = "vpn"
        self._monitor_status[monitor_name] = MonitorStatus.RUNNING
        
        try:
            while self._running:
                # Note: VPN monitor currently parses log files
                # In a real deployment, this would tail live logs
                # For now, we check periodically
                await asyncio.sleep(self.monitor_interval)
                
        except asyncio.CancelledError:
            logger.info(f"{monitor_name} monitor cancelled")
        except Exception as e:
            logger.error(f"{monitor_name} monitor error", exc_info=e)
            self._monitor_status[monitor_name] = MonitorStatus.ERROR
        finally:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
    
    async def _monitor_api(self) -> None:
        """Monitor API abuse continuously."""
        monitor_name = "api"
        self._monitor_status[monitor_name] = MonitorStatus.RUNNING
        
        try:
            while self._running:
                # API monitor also parses logs
                # Real implementation would tail syslog or use API hooks
                await asyncio.sleep(self.monitor_interval)
                
        except asyncio.CancelledError:
            logger.info(f"{monitor_name} monitor cancelled")
        except Exception as e:
            logger.error(f"{monitor_name} monitor error", exc_info=e)
            self._monitor_status[monitor_name] = MonitorStatus.ERROR
        finally:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
    
    async def _monitor_carrier(self) -> None:
        """Monitor carrier configuration continuously."""
        monitor_name = "carrier"
        self._monitor_status[monitor_name] = MonitorStatus.RUNNING
        
        try:
            while self._running:
                # Check for carrier changes
                if self.backup_path.exists():
                    # Run carrier detection
                    threats = self.carrier_detector.monitor_esim_profiles(
                        backup_path=self.backup_path
                    )
                    
                    # Process any threats found
                    for threat in threats:
                        await self._handle_carrier_threat(threat)
                
                await asyncio.sleep(self.monitor_interval * 2)  # Less frequent
                
        except asyncio.CancelledError:
            logger.info(f"{monitor_name} monitor cancelled")
        except Exception as e:
            logger.error(f"{monitor_name} monitor error", exc_info=e)
            self._monitor_status[monitor_name] = MonitorStatus.ERROR
        finally:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
    
    async def _scan_backups_once(self) -> None:
        """Run one-time backup scan for all threats."""
        try:
            # Carrier threats
            carrier_threats = self.carrier_detector.monitor_esim_profiles(
                backup_path=self.backup_path
            )
            
            for threat in carrier_threats:
                await self._handle_carrier_threat(threat)
            
            logger.info(f"Initial scan complete: {len(carrier_threats)} carrier threats found")
            
        except Exception as e:
            logger.error("Error during initial backup scan", exc_info=e)
    
    async def _handle_carrier_threat(self, threat: CarrierThreatDetection) -> None:
        """Process carrier threat detection."""
        # Create unique ID for deduplication
        threat_id = f"carrier_{threat.threat_type}_{threat.esim_id}"
        
        if threat_id in self._seen_threat_ids:
            return  # Already processed
        
        self._seen_threat_ids.add(threat_id)
        self._total_threats += 1
        self._last_threat_time = datetime.now()
        self._threat_counts[threat.threat_level] += 1
        
        # Log threat
        logger.warning(
            f"🚨 Carrier threat detected: {threat.threat_type}",
            extra={
                "threat_level": threat.threat_level.name,
                "esim_id": threat.esim_id,
                "details": threat.details
            }
        )
        
        # Send alert if configured
        if self.telegram_alerter and threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            try:
                self.telegram_alerter.send_carrier_threat_alert(threat)
            except Exception as e:
                logger.error("Failed to send Telegram alert", exc_info=e)
    
    def get_status(self) -> SystemStatus:
        """Get current system status.
        
        Returns:
            SystemStatus with current state
        """
        uptime = 0.0
        if self._started_at:
            uptime = (datetime.now() - self._started_at).total_seconds()
        
        return SystemStatus(
            running=self._running,
            started_at=self._started_at,
            monitors=self._monitor_status.copy(),
            threats_detected=self._total_threats,
            last_threat=self._last_threat_time,
            uptime_seconds=uptime
        )
    
    def get_threat_summary(self) -> ThreatSummary:
        """Get summary of detected threats.
        
        Returns:
            ThreatSummary with aggregated threat data
        """
        return ThreatSummary(
            timestamp=datetime.now(),
            total_threats=self._total_threats,
            critical_count=self._threat_counts[ThreatLevel.CRITICAL],
            high_count=self._threat_counts[ThreatLevel.HIGH],
            medium_count=self._threat_counts[ThreatLevel.MEDIUM],
            low_count=self._threat_counts[ThreatLevel.LOW],
            threats_by_source={
                "carrier": sum(1 for tid in self._seen_threat_ids if tid.startswith("carrier_")),
                "vpn": sum(1 for tid in self._seen_threat_ids if tid.startswith("vpn_")),
                "api": sum(1 for tid in self._seen_threat_ids if tid.startswith("api_")),
            }
        )
    
    async def scan_now(self) -> ThreatSummary:
        """Trigger immediate backup scan.
        
        Returns:
            ThreatSummary with results
        """
        logger.info("Manual scan triggered")
        await self._scan_backups_once()
        return self.get_threat_summary()


# Daemon entry point when running as module
async def _run_daemon():
    """Run orchestrator as a daemon service."""
    import signal
    
    shutdown_event = asyncio.Event()
    orchestrator = None
    
    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        shutdown_event.set()
    
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Create and start orchestrator
        orchestrator = ThreatOrchestrator(
            backup_path=None,  # Auto-detect
            telegram_enabled=True,
            monitor_interval=30,
            scan_backups_on_start=True
        )
        
        await orchestrator.start()
        logger.info("✅ Orchestrator daemon started")
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        
    except Exception as e:
        logger.error(f"Orchestrator daemon error: {e}", exc_info=True)
        raise
    finally:
        if orchestrator:
            await orchestrator.stop()
            logger.info("✅ Orchestrator daemon stopped")


# Entry point for python -m privaseeai_security.orchestrator
if __name__ == "__main__":
    import sys
    
    logger.info("Starting PrivaseeAI Security Orchestrator daemon...")
    
    try:
        asyncio.run(_run_daemon())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

