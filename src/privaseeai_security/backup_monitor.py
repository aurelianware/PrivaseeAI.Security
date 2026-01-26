"""iOS backup monitoring system."""

from pathlib import Path
from typing import List, Optional

from .config import Config
from .device_info import DeviceInfoExtractor
from .file_watcher import FileWatcher
from .logger import get_logger


class BackupMonitorError(Exception):
    """Backup monitor error exception."""
    pass


class BackupMonitor:
    """Monitor iOS backups for security threats."""

    def __init__(self, config: Optional[Config] = None):
        """Initialize backup monitor.
        
        Args:
            config: Configuration object (optional)
        """
        self.config = config or Config()
        self.logger = get_logger(__name__)
        self._file_watcher: Optional[FileWatcher] = None
        self._running = False

    def start(self) -> None:
        """Start monitoring iOS backups."""
        backup_dir = self.config.get("backup_directory")
        if not backup_dir:
            raise BackupMonitorError("Backup directory not configured")
        
        backup_path = Path(backup_dir)
        if not backup_path.exists():
            raise BackupMonitorError(f"Backup directory does not exist: {backup_dir}")
        
        self.logger.info(f"Starting backup monitor for: {backup_dir}")
        
        # Initialize file watcher
        interval = self.config.get("watch_interval", 5)
        self._file_watcher = FileWatcher([backup_dir], interval=interval)
        self._file_watcher.add_callback(self._on_backup_changed)
        self._file_watcher.start()
        
        self._running = True
        self.logger.info("Backup monitor started successfully")

    def stop(self) -> None:
        """Stop monitoring iOS backups."""
        if self._file_watcher:
            self._file_watcher.stop()
        self._running = False
        self.logger.info("Backup monitor stopped")

    def _on_backup_changed(self, changed_files: List[Path]) -> None:
        """Handle backup file changes.
        
        Args:
            changed_files: List of changed file paths
        """
        self.logger.info(f"Detected {len(changed_files)} changed files")
        for file_path in changed_files:
            self._analyze_file(file_path)

    def _analyze_file(self, file_path: Path) -> None:
        """Analyze a backup file for threats.
        
        Args:
            file_path: Path to file to analyze
            
        Note:
            This is a stub implementation. Real implementation would
            perform actual threat analysis.
        """
        self.logger.debug(f"Analyzing file: {file_path}")

    def scan_existing_backups(self) -> List[str]:
        """Scan existing backups in the backup directory.
        
        Returns:
            List of backup device IDs found
        """
        backup_dir = self.config.get("backup_directory")
        if not backup_dir:
            return []
        
        backup_path = Path(backup_dir)
        
        if not backup_path.exists():
            return []
        
        backup_ids = []
        for item in backup_path.iterdir():
            if item.is_dir():
                # Each subdirectory is typically a device backup
                try:
                    extractor = DeviceInfoExtractor(str(item))
                    if extractor.validate_backup():
                        device_id = extractor.get_device_id()
                        backup_ids.append(device_id)
                except Exception as e:
                    self.logger.warning(f"Failed to process backup {item}: {e}")
        
        return backup_ids

    @property
    def is_running(self) -> bool:
        """Check if monitor is running.
        
        Returns:
            True if running, False otherwise
        """
        return self._running
