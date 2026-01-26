"""Integration tests for backup monitoring system."""

import pytest
import tempfile
from pathlib import Path

from privaseeai_security.backup_monitor import BackupMonitor, BackupMonitorError
from privaseeai_security.config import Config
from privaseeai_security.device_info import DeviceInfoExtractor


class TestBackupMonitorIntegration:
    """Integration tests for BackupMonitor."""

    def test_backup_monitor_initialization(self):
        """Test backup monitor initialization."""
        config = Config()
        monitor = BackupMonitor(config=config)
        
        assert monitor.config is not None
        assert monitor.is_running is False

    def test_backup_monitor_initialization_without_config(self):
        """Test backup monitor initialization without explicit config."""
        monitor = BackupMonitor()
        
        assert monitor.config is not None
        assert isinstance(monitor.config, Config)

    def test_backup_monitor_start_with_valid_directory(self):
        """Test starting backup monitor with valid directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            monitor = BackupMonitor(config=config)
            monitor.start()
            
            assert monitor.is_running is True
            
            monitor.stop()

    def test_backup_monitor_start_without_backup_directory(self):
        """Test starting monitor without backup directory configured."""
        config = Config()
        config.set("backup_directory", None)
        
        monitor = BackupMonitor(config=config)
        
        with pytest.raises(BackupMonitorError, match="Backup directory not configured"):
            monitor.start()

    def test_backup_monitor_start_with_nonexistent_directory(self):
        """Test starting monitor with non-existent directory."""
        config = Config()
        config.set("backup_directory", "/nonexistent/backup/directory")
        
        monitor = BackupMonitor(config=config)
        
        with pytest.raises(BackupMonitorError, match="Backup directory does not exist"):
            monitor.start()

    def test_backup_monitor_stop(self):
        """Test stopping backup monitor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            monitor = BackupMonitor(config=config)
            monitor.start()
            monitor.stop()
            
            assert monitor.is_running is False

    def test_backup_monitor_file_watching(self):
        """Test that backup monitor watches for file changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            config.set("watch_interval", 1)
            
            monitor = BackupMonitor(config=config)
            monitor.start()
            
            # Verify file watcher is initialized
            assert monitor._file_watcher is not None
            assert monitor._file_watcher.is_running is True
            
            monitor.stop()

    def test_backup_monitor_scan_existing_backups_empty(self):
        """Test scanning empty backup directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            monitor = BackupMonitor(config=config)
            backup_ids = monitor.scan_existing_backups()
            
            assert isinstance(backup_ids, list)
            assert len(backup_ids) == 0

    def test_backup_monitor_scan_existing_backups_with_devices(self):
        """Test scanning backup directory with device backups."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            # Create mock backup directories
            device_dir1 = Path(tmpdir) / "device1"
            device_dir2 = Path(tmpdir) / "device2"
            device_dir1.mkdir()
            device_dir2.mkdir()
            
            monitor = BackupMonitor(config=config)
            backup_ids = monitor.scan_existing_backups()
            
            # Should detect 2 backup directories
            assert len(backup_ids) == 2

    def test_backup_monitor_scan_ignores_files(self):
        """Test that scan ignores files in backup directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            # Create a file (not a directory)
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")
            
            # Create one valid directory
            device_dir = Path(tmpdir) / "device1"
            device_dir.mkdir()
            
            monitor = BackupMonitor(config=config)
            backup_ids = monitor.scan_existing_backups()
            
            # Should only detect the directory, not the file
            assert len(backup_ids) == 1

    def test_backup_monitor_full_workflow(self):
        """Test complete backup monitoring workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup
            config = Config()
            config.set("backup_directory", tmpdir)
            config.set("watch_interval", 1)
            
            monitor = BackupMonitor(config=config)
            
            # Create initial backup
            device_dir = Path(tmpdir) / "test-device-001"
            device_dir.mkdir()
            
            # Start monitoring
            monitor.start()
            assert monitor.is_running is True
            
            # Scan existing backups
            backup_ids = monitor.scan_existing_backups()
            assert len(backup_ids) >= 1
            
            # Stop monitoring
            monitor.stop()
            assert monitor.is_running is False

    def test_backup_monitor_handles_callback_on_changes(self):
        """Test that monitor triggers callback on file changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            monitor = BackupMonitor(config=config)
            monitor.start()
            
            # Create a new backup file
            backup_file = Path(tmpdir) / "new_backup.db"
            backup_file.write_text("backup data")
            
            # Check for changes manually (in real scenario, this happens automatically)
            if monitor._file_watcher:
                monitor._file_watcher.run_once()
            
            monitor.stop()

    def test_backup_monitor_integration_with_device_extractor(self):
        """Test integration between BackupMonitor and DeviceInfoExtractor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            
            # Create device backup directory
            device_dir = Path(tmpdir) / "test-device-backup"
            device_dir.mkdir()
            
            # Test device info extraction
            extractor = DeviceInfoExtractor(str(device_dir))
            device_id = extractor.get_device_id()
            
            # Test backup monitoring
            monitor = BackupMonitor(config=config)
            backup_ids = monitor.scan_existing_backups()
            
            # Should find the device
            assert len(backup_ids) > 0
            assert device_id in backup_ids

    def test_backup_monitor_respects_watch_interval(self):
        """Test that monitor respects configured watch interval."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            config.set("backup_directory", tmpdir)
            config.set("watch_interval", 2)
            
            monitor = BackupMonitor(config=config)
            monitor.start()
            
            assert monitor._file_watcher.interval == 2
            
            monitor.stop()
