"""Threat detection orchestrator for concurrent monitoring.

This module coordinates all security monitors, aggregates threats,
and dispatches alerts. It runs monitors concurrently and provides
a central point for status monitoring and health checks.
"""

import asyncio
import json
import signal
from collections import defaultdict
from dataclasses import dataclass, field, asdict
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

# Default state file location
DEFAULT_STATE_FILE = Path.home() / ".privaseeai" / "orchestrator_state.json"


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
class OrchestratorState:
    """Persistent state of the orchestrator for crash recovery."""
    total_threats: int
    last_threat_time: Optional[str]  # ISO format datetime string
    seen_threat_ids: List[str]
    threat_counts: Dict[str, int]  # ThreatLevel.name -> count
    saved_at: str  # ISO format datetime string


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
        state_file: Optional[Path] = None,
        max_retry_delay: int = 300,  # Max 5 minutes
    ):
        """Initialize orchestrator.
        
        Args:
            backup_path: Path to iOS backups (auto-detected if None)
            telegram_enabled: Enable Telegram alerts
            monitor_interval: Seconds between monitor checks
            scan_backups_on_start: Run full backup scan on startup
            state_file: Path to state persistence file (default: ~/.privaseeai/orchestrator_state.json)
            max_retry_delay: Maximum delay for exponential backoff (seconds)
        """
        self.backup_path = backup_path or self._auto_detect_backup_path()
        self.monitor_interval = monitor_interval
        self.scan_backups_on_start = scan_backups_on_start
        self.state_file = state_file or DEFAULT_STATE_FILE
        self.max_retry_delay = max_retry_delay
        
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
        
        # Alert queue tracking for graceful shutdown
        self._pending_alerts: asyncio.Queue = asyncio.Queue()
        self._alert_tasks: List[asyncio.Task] = []
        
        # Retry tracking for exponential backoff
        self._retry_counts: Dict[str, int] = defaultdict(int)
        
        logger.info("Orchestrator initialized", extra={
            "backup_path": str(self.backup_path),
            "telegram_enabled": telegram_enabled,
            "monitor_interval": monitor_interval,
            "state_file": str(self.state_file)
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
        an initial backup scan. Also restores previous state if available.
        """
        if self._running:
            logger.warning("Orchestrator already running")
            return
        
        self._running = True
        self._started_at = datetime.now()
        
        logger.info("🚀 Starting PrivaseeAI Security Orchestrator")
        
        # Restore previous state if available
        self._restore_state()
        
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
        
        # Start alert processing task
        self._alert_tasks = [
            asyncio.create_task(self._process_alerts(), name="alert_processor"),
        ]
        
        logger.info("✅ All monitors started", extra={
            "active_monitors": len(self._monitor_tasks)
        })
    
    async def stop(self) -> None:
        """Stop all monitors gracefully with state persistence."""
        if not self._running:
            logger.warning("Orchestrator not running")
            return
        
        logger.info("🛑 Stopping orchestrator gracefully...")
        self._running = False
        
        # Cancel all monitor tasks
        for task in self._monitor_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for monitors to finish cleanly
        if self._monitor_tasks:
            await asyncio.gather(*self._monitor_tasks, return_exceptions=True)
            logger.info("✅ All monitors stopped")
        
        # Wait for pending alerts to be sent
        logger.info("⏳ Waiting for pending alerts to be sent...")
        await self._drain_alerts()
        
        # Cancel alert processing tasks
        for task in self._alert_tasks:
            if not task.done():
                task.cancel()
        
        if self._alert_tasks:
            await asyncio.gather(*self._alert_tasks, return_exceptions=True)
            logger.info("✅ Alert processing stopped")
        
        # Save current state to disk
        self._save_state()
        
        self._monitor_tasks.clear()
        self._alert_tasks.clear()
        for monitor_name in self._monitor_status:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
        
        runtime = (datetime.now() - self._started_at).total_seconds() if self._started_at else 0
        logger.info("✅ Orchestrator stopped gracefully", extra={
            "total_threats_detected": self._total_threats,
            "runtime_seconds": runtime
        })
    
    async def _monitor_vpn(self) -> None:
        """Monitor VPN integrity continuously with exponential backoff retry."""
        monitor_name = "vpn"
        self._monitor_status[monitor_name] = MonitorStatus.RUNNING
        
        try:
            while self._running:
                try:
                    # Note: VPN monitor currently parses log files
                    # In a real deployment, this would tail live logs
                    await asyncio.sleep(self.monitor_interval)
                    
                    # Reset retry count on successful iteration
                    self._retry_counts[monitor_name] = 0
                    
                except Exception as e:
                    # Exponential backoff for critical monitor
                    retry_count = self._retry_counts[monitor_name]
                    delay = min(2 ** retry_count, self.max_retry_delay)
                    self._retry_counts[monitor_name] += 1
                    
                    logger.error(
                        f"{monitor_name} monitor error, retrying in {delay}s",
                        exc_info=e,
                        extra={"retry_count": retry_count, "delay": delay}
                    )
                    await asyncio.sleep(delay)
                
        except asyncio.CancelledError:
            logger.info(f"{monitor_name} monitor cancelled")
            raise  # Re-raise to properly handle cancellation
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
        """Monitor carrier configuration continuously with exponential backoff retry."""
        monitor_name = "carrier"
        self._monitor_status[monitor_name] = MonitorStatus.RUNNING
        
        try:
            while self._running:
                try:
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
                    
                    # Reset retry count on successful iteration
                    self._retry_counts[monitor_name] = 0
                    
                except Exception as e:
                    # Exponential backoff for critical monitor
                    retry_count = self._retry_counts[monitor_name]
                    delay = min(2 ** retry_count, self.max_retry_delay)
                    self._retry_counts[monitor_name] += 1
                    
                    logger.error(
                        f"{monitor_name} monitor error, retrying in {delay}s",
                        exc_info=e,
                        extra={"retry_count": retry_count, "delay": delay}
                    )
                    await asyncio.sleep(delay)
                
        except asyncio.CancelledError:
            logger.info(f"{monitor_name} monitor cancelled")
            raise  # Re-raise to properly handle cancellation
        finally:
            self._monitor_status[monitor_name] = MonitorStatus.STOPPED
    
    def _save_state(self) -> None:
        """Save current orchestrator state to disk for crash recovery."""
        try:
            # Ensure state directory exists
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert threat counts to serializable format
            threat_counts_dict = {
                level.name: count for level, count in self._threat_counts.items()
            }
            
            state = OrchestratorState(
                total_threats=self._total_threats,
                last_threat_time=self._last_threat_time.isoformat() if self._last_threat_time else None,
                seen_threat_ids=list(self._seen_threat_ids),
                threat_counts=threat_counts_dict,
                saved_at=datetime.now().isoformat()
            )
            
            # Write state to file atomically
            temp_file = self.state_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(asdict(state), f, indent=2)
            
            # Atomic rename
            temp_file.replace(self.state_file)
            
            logger.info("💾 State saved to disk", extra={
                "state_file": str(self.state_file),
                "total_threats": self._total_threats
            })
            
        except Exception as e:
            logger.error("Failed to save state", exc_info=e)
    
    def _restore_state(self) -> None:
        """Restore orchestrator state from disk after crash or restart."""
        if not self.state_file.exists():
            logger.info("No previous state file found, starting fresh")
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state_dict = json.load(f)
            
            # Restore state
            self._total_threats = state_dict.get('total_threats', 0)
            
            last_threat_str = state_dict.get('last_threat_time')
            self._last_threat_time = datetime.fromisoformat(last_threat_str) if last_threat_str else None
            
            self._seen_threat_ids = set(state_dict.get('seen_threat_ids', []))
            
            # Restore threat counts
            threat_counts_dict = state_dict.get('threat_counts', {})
            for level_name, count in threat_counts_dict.items():
                try:
                    level = ThreatLevel[level_name]
                    self._threat_counts[level] = count
                except KeyError:
                    logger.warning(f"Unknown threat level in saved state: {level_name}")
            
            saved_at = state_dict.get('saved_at', 'unknown')
            logger.info("✅ State restored from disk", extra={
                "state_file": str(self.state_file),
                "total_threats": self._total_threats,
                "saved_at": saved_at
            })
            
        except Exception as e:
            logger.error("Failed to restore state, starting fresh", exc_info=e)
    
    async def _process_alerts(self) -> None:
        """Process pending alerts from the queue."""
        try:
            while self._running:
                try:
                    # Wait for alert with timeout
                    alert_data = await asyncio.wait_for(
                        self._pending_alerts.get(),
                        timeout=1.0
                    )
                    
                    # Send the alert
                    if self.telegram_alerter:
                        try:
                            threat_type = alert_data.get('type')
                            threat = alert_data.get('threat')
                            
                            if threat_type == 'carrier':
                                self.telegram_alerter.send_carrier_threat_alert(threat)
                            # Add other alert types as needed
                            
                        except Exception as e:
                            logger.error("Failed to send alert", exc_info=e)
                    
                    self._pending_alerts.task_done()
                    
                except asyncio.TimeoutError:
                    continue  # No alerts in queue, continue
                    
        except asyncio.CancelledError:
            logger.info("Alert processor cancelled")
            raise
    
    async def _drain_alerts(self, timeout: float = 10.0) -> None:
        """Wait for all pending alerts to be sent before shutdown.
        
        Args:
            timeout: Maximum time to wait for alerts (seconds)
        """
        if self._pending_alerts.empty():
            logger.info("No pending alerts to drain")
            return
        
        try:
            pending_count = self._pending_alerts.qsize()
            logger.info(f"Draining {pending_count} pending alerts...")
            
            # Wait for queue to be empty with timeout
            await asyncio.wait_for(
                self._pending_alerts.join(),
                timeout=timeout
            )
            logger.info("✅ All pending alerts sent")
            
        except asyncio.TimeoutError:
            remaining = self._pending_alerts.qsize()
            logger.warning(f"Alert drain timeout, {remaining} alerts may not have been sent")
    
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
        # Create unique ID for deduplication using deterministic hash
        import hashlib
        threat_data = f"{threat.attack_type}_{str(sorted(threat.indicators))}"
        threat_hash = hashlib.sha256(threat_data.encode()).hexdigest()[:16]
        threat_id = f"carrier_{threat.attack_type}_{threat_hash}"
        
        if threat_id in self._seen_threat_ids:
            return  # Already processed
        
        self._seen_threat_ids.add(threat_id)
        self._total_threats += 1
        self._last_threat_time = datetime.now()
        self._threat_counts[threat.threat_level] += 1
        
        # Log threat
        logger.warning(
            f"🚨 Carrier threat detected: {threat.attack_type}",
            extra={
                "threat_level": threat.threat_level.name,
                "indicators": threat.indicators,
                "details": threat.details
            }
        )
        
        # Queue alert if configured and severity is high
        if self.telegram_alerter and threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            await self._pending_alerts.put({
                'type': 'carrier',
                'threat': threat
            })
    
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
    """Run orchestrator as a daemon service with robust crash recovery."""
    orchestrator = None
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    
    def signal_handler(sig):
        """Handle shutdown signals (SIGTERM, SIGINT)."""
        sig_name = signal.Signals(sig).name
        logger.info(f"📡 Received signal {sig_name}, initiating graceful shutdown...")
        shutdown_event.set()
    
    # Setup signal handlers for graceful shutdown
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
    
    try:
        # Create and start orchestrator
        orchestrator = ThreatOrchestrator(
            backup_path=None,  # Auto-detect
            telegram_enabled=True,
            monitor_interval=30,
            scan_backups_on_start=True
        )
        
        await orchestrator.start()
        logger.info("✅ Orchestrator daemon started and running")
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        
    except asyncio.CancelledError:
        logger.info("⚠️  Orchestrator task cancelled")
    except Exception as e:
        logger.error(f"💥 Orchestrator daemon error: {e}", exc_info=True)
        raise
    finally:
        if orchestrator:
            try:
                await orchestrator.stop()
                logger.info("✅ Orchestrator daemon stopped cleanly")
            except Exception as e:
                logger.error(f"Error during shutdown: {e}", exc_info=True)


# Entry point for python -m privaseeai_security.orchestrator
if __name__ == "__main__":
    import sys
    
    logger.info("Starting PrivaseeAI Security Orchestrator daemon...")
    
    try:
        asyncio.run(_run_daemon())
    except KeyboardInterrupt:
        logger.info("⌨️  Keyboard interrupt received")
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}", exc_info=True)
        sys.exit(1)
    
    logger.info("👋 Daemon exiting")
    sys.exit(0)

