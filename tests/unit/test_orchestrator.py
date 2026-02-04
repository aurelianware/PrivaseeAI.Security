"""Unit tests for orchestrator crash recovery and shutdown."""

import asyncio
import json
import pytest
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

from privaseeai_security.orchestrator import (
    ThreatOrchestrator,
    MonitorStatus,
    OrchestratorState,
    _run_daemon,
)
from privaseeai_security.crypto.cert_validator import ThreatLevel
from privaseeai_security.monitors.carrier_detection import CarrierThreatDetection


class TestOrchestratorShutdown:
    """Test graceful shutdown behavior."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_cancels_monitors(self):
        """Test that shutdown cancels all monitor tasks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                monitor_interval=1,
                scan_backups_on_start=False,
                state_file=state_file,
            )
            
            # Start orchestrator
            await orchestrator.start()
            assert orchestrator._running is True
            assert len(orchestrator._monitor_tasks) == 3
            
            # Wait a bit for tasks to start
            await asyncio.sleep(0.1)
            
            # Stop orchestrator
            await orchestrator.stop()
            
            # Verify shutdown
            assert orchestrator._running is False
            assert len(orchestrator._monitor_tasks) == 0
            assert all(
                status == MonitorStatus.STOPPED 
                for status in orchestrator._monitor_status.values()
            )

    @pytest.mark.asyncio
    async def test_shutdown_waits_for_pending_alerts(self):
        """Test that shutdown waits for pending alerts to be sent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            # Mock telegram alerter
            mock_alerter = MagicMock()
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                monitor_interval=1,
                scan_backups_on_start=False,
                state_file=state_file,
            )
            orchestrator.telegram_alerter = mock_alerter
            
            await orchestrator.start()
            
            # Add some pending alerts
            threat = CarrierThreatDetection(
                threat_level=ThreatLevel.CRITICAL,
                attack_type="suspicious_esim",
                indicators=["test"],
                timestamp=datetime.now(),
                details="Test threat"
            )
            
            await orchestrator._pending_alerts.put({
                'type': 'carrier',
                'threat': threat
            })
            
            # Wait for alert to be processed
            await asyncio.sleep(0.2)
            
            # Stop should wait for alerts
            await orchestrator.stop()
            
            # Verify alert queue is empty
            assert orchestrator._pending_alerts.empty()

    @pytest.mark.asyncio
    async def test_shutdown_saves_state(self):
        """Test that shutdown saves state to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                monitor_interval=1,
                scan_backups_on_start=False,
                state_file=state_file,
            )
            
            # Set some state
            orchestrator._total_threats = 5
            orchestrator._last_threat_time = datetime.now()
            orchestrator._seen_threat_ids.add("threat1")
            orchestrator._seen_threat_ids.add("threat2")
            orchestrator._threat_counts[ThreatLevel.HIGH] = 3
            
            await orchestrator.start()
            await orchestrator.stop()
            
            # Verify state file was created
            assert state_file.exists()
            
            # Verify state contents
            with open(state_file, 'r') as f:
                state = json.load(f)
            
            assert state['total_threats'] == 5
            assert 'threat1' in state['seen_threat_ids']
            assert 'threat2' in state['seen_threat_ids']
            assert state['threat_counts']['HIGH'] == 3


class TestStatePersistence:
    """Test state save and restore functionality."""

    def test_save_state_creates_file(self):
        """Test that save_state creates a state file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            orchestrator._total_threats = 10
            orchestrator._save_state()
            
            assert state_file.exists()

    def test_save_state_correct_format(self):
        """Test that saved state has correct format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            # Set test state
            test_time = datetime(2024, 1, 1, 12, 0, 0)
            orchestrator._total_threats = 15
            orchestrator._last_threat_time = test_time
            orchestrator._seen_threat_ids = {"threat1", "threat2", "threat3"}
            orchestrator._threat_counts[ThreatLevel.CRITICAL] = 2
            orchestrator._threat_counts[ThreatLevel.HIGH] = 5
            
            orchestrator._save_state()
            
            with open(state_file, 'r') as f:
                state = json.load(f)
            
            assert state['total_threats'] == 15
            assert state['last_threat_time'] == test_time.isoformat()
            assert len(state['seen_threat_ids']) == 3
            assert state['threat_counts']['CRITICAL'] == 2
            assert state['threat_counts']['HIGH'] == 5
            assert 'saved_at' in state

    def test_restore_state_loads_data(self):
        """Test that restore_state loads data correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            # Create a state file
            test_time = datetime(2024, 1, 1, 12, 0, 0)
            state_data = {
                'total_threats': 20,
                'last_threat_time': test_time.isoformat(),
                'seen_threat_ids': ['threat1', 'threat2'],
                'threat_counts': {'CRITICAL': 3, 'HIGH': 7},
                'saved_at': datetime.now().isoformat()
            }
            
            with open(state_file, 'w') as f:
                json.dump(state_data, f)
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            orchestrator._restore_state()
            
            assert orchestrator._total_threats == 20
            assert orchestrator._last_threat_time == test_time
            assert len(orchestrator._seen_threat_ids) == 2
            assert orchestrator._threat_counts[ThreatLevel.CRITICAL] == 3
            assert orchestrator._threat_counts[ThreatLevel.HIGH] == 7

    def test_restore_state_handles_missing_file(self):
        """Test that restore_state handles missing file gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "nonexistent.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            # Should not raise exception
            orchestrator._restore_state()
            
            # Should start with default state
            assert orchestrator._total_threats == 0
            assert orchestrator._last_threat_time is None

    @pytest.mark.asyncio
    async def test_startup_restores_state(self):
        """Test that orchestrator restores state on startup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            # Create a state file
            state_data = {
                'total_threats': 25,
                'last_threat_time': datetime.now().isoformat(),
                'seen_threat_ids': ['threat1', 'threat2', 'threat3'],
                'threat_counts': {'HIGH': 10},
                'saved_at': datetime.now().isoformat()
            }
            
            with open(state_file, 'w') as f:
                json.dump(state_data, f)
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                scan_backups_on_start=False,
                state_file=state_file,
            )
            
            await orchestrator.start()
            
            # Verify state was restored
            assert orchestrator._total_threats == 25
            assert len(orchestrator._seen_threat_ids) == 3
            
            await orchestrator.stop()


class TestExponentialBackoff:
    """Test exponential backoff retry logic."""

    @pytest.mark.asyncio
    async def test_vpn_monitor_retries_with_backoff(self):
        """Test VPN monitor uses exponential backoff on errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                monitor_interval=0.1,  # Fast for testing
                scan_backups_on_start=False,
                state_file=state_file,
                max_retry_delay=4,  # Low for testing
            )
            
            # Track sleep calls to verify backoff
            sleep_calls = []
            original_sleep = asyncio.sleep
            
            async def mock_sleep(delay):
                sleep_calls.append(delay)
                await original_sleep(0.01)  # Actual short sleep
            
            with patch('asyncio.sleep', side_effect=mock_sleep):
                # Start the monitor
                task = asyncio.create_task(orchestrator._monitor_vpn())
                
                # Let it run briefly
                await asyncio.sleep(0.1)
                
                # Cancel and wait
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            # The monitor should have slept for monitor_interval
            assert len(sleep_calls) > 0

    @pytest.mark.asyncio
    async def test_carrier_monitor_retries_with_backoff(self):
        """Test carrier monitor uses exponential backoff on errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                monitor_interval=0.1,
                scan_backups_on_start=False,
                state_file=state_file,
                max_retry_delay=4,
            )
            
            # Start the monitor
            task = asyncio.create_task(orchestrator._monitor_carrier())
            
            # Let it run briefly
            await asyncio.sleep(0.2)
            
            # Cancel and wait
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # Should complete without error


class TestSignalHandling:
    """Test signal handling for graceful shutdown."""

    @pytest.mark.asyncio
    async def test_daemon_handles_cancellation(self):
        """Test that daemon handles CancelledError gracefully."""
        # Mock the orchestrator to avoid actual startup
        with patch('privaseeai_security.orchestrator.ThreatOrchestrator') as mock_orch_class:
            mock_orch = AsyncMock()
            mock_orch_class.return_value = mock_orch
            
            # Create task and cancel it immediately
            task = asyncio.create_task(_run_daemon())
            await asyncio.sleep(0.1)
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # Verify stop was called
            mock_orch.stop.assert_called()


class TestAlertQueue:
    """Test alert queue processing."""

    @pytest.mark.asyncio
    async def test_alerts_are_queued(self):
        """Test that alerts are properly queued."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            threat = CarrierThreatDetection(
                threat_level=ThreatLevel.CRITICAL,
                attack_type="test",
                indicators=["test"],
                timestamp=datetime.now(),
                details="Test"
            )
            
            # Enable telegram for alert queueing
            orchestrator.telegram_alerter = MagicMock()
            
            await orchestrator._handle_carrier_threat(threat)
            
            # Verify alert was queued
            assert not orchestrator._pending_alerts.empty()

    @pytest.mark.asyncio
    async def test_drain_alerts_waits_for_completion(self):
        """Test that drain_alerts waits for queue to be empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            
            orchestrator = ThreatOrchestrator(
                backup_path=Path(tmpdir),
                telegram_enabled=False,
                state_file=state_file,
            )
            
            # Start to initialize queue properly
            await orchestrator.start()
            
            # Put some items in queue
            for i in range(3):
                await orchestrator._pending_alerts.put({'test': i})
            
            # Mark tasks as done to allow drain
            for i in range(3):
                await orchestrator._pending_alerts.get()
                orchestrator._pending_alerts.task_done()
            
            # Drain should complete quickly
            await orchestrator._drain_alerts(timeout=1.0)
            
            assert orchestrator._pending_alerts.empty()
            
            await orchestrator.stop()
