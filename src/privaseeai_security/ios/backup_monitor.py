"""iOS backup monitoring system."""

import time
from collections.abc import Callable
from pathlib import Path

from privaseeai_security.core.config import get_settings
from privaseeai_security.core.logger import get_logger
from privaseeai_security.ios.backup_parser import BackupParser
from privaseeai_security.ios.device_info import DeviceInfo, extract_device_info
from privaseeai_security.utils.file_watcher import FileWatcher

logger = get_logger(__name__)


class BackupMonitor:
    """Monitor iOS backup directories for changes and threats."""

    def __init__(
        self,
        backup_path: Path,
        on_new_file: Callable[[Path], None] | None = None,
        on_modified_file: Callable[[Path], None] | None = None,
        debounce_seconds: int | None = None,
    ):
        """Initialize backup monitor.

        Args:
            backup_path: Path to iOS backup directory
            on_new_file: Optional callback for new files
            on_modified_file: Optional callback for modified files
            debounce_seconds: Optional debounce time (uses config if not provided)
        """
        self.backup_path = backup_path
        self.device_info: DeviceInfo | None = None
        self._is_running = False

        # Get settings
        settings = get_settings()

        # Set up callbacks
        self._on_new_file = on_new_file
        self._on_modified_file = on_modified_file

        # Initialize file watcher
        debounce = debounce_seconds or settings.monitoring.file_watch_debounce_seconds
        self.file_watcher = FileWatcher(
            watch_path=backup_path,
            on_created=self._handle_new_file,
            on_modified=self._handle_modified_file,
            debounce_seconds=debounce,
            file_patterns={".db", ".plist", ".sqlite"},
            recursive=True,
        )

        logger.info(f"Initialized backup monitor for: {backup_path}")

    def _handle_new_file(self, file_path: Path) -> None:
        """Handle new file detected in backup.

        Args:
            file_path: Path to the new file
        """
        logger.info(f"New backup file detected: {file_path.name}")

        # Perform basic analysis
        self._analyze_file(file_path)

        # Call custom callback if provided
        if self._on_new_file:
            try:
                self._on_new_file(file_path)
            except Exception as e:
                logger.error(f"Error in new file callback: {e}")

    def _handle_modified_file(self, file_path: Path) -> None:
        """Handle modified file detected in backup.

        Args:
            file_path: Path to the modified file
        """
        logger.info(f"Backup file modified: {file_path.name}")

        # Perform basic analysis
        self._analyze_file(file_path)

        # Call custom callback if provided
        if self._on_modified_file:
            try:
                self._on_modified_file(file_path)
            except Exception as e:
                logger.error(f"Error in modified file callback: {e}")

    def _analyze_file(self, file_path: Path) -> None:
        """Perform basic analysis on a backup file.

        Args:
            file_path: Path to the file to analyze
        """
        # Log file details
        try:
            file_size = file_path.stat().st_size
            logger.debug(
                f"File analysis: {file_path.name} "
                f"(size: {file_size} bytes, "
                f"type: {file_path.suffix})"
            )

            # Check for suspicious file patterns (basic example)
            suspicious_patterns = [
                "spyware",
                "pegasus",
                "cellebrite",
                "grayshift",
            ]

            file_name_lower = file_path.name.lower()
            for pattern in suspicious_patterns:
                if pattern in file_name_lower:
                    logger.warning(
                        f"Suspicious file pattern detected: {file_path.name} "
                        f"(matches pattern: {pattern})"
                    )

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")

    def load_device_info(self) -> DeviceInfo:
        """Load device information from backup.

        Returns:
            DeviceInfo object

        Raises:
            Various exceptions from extract_device_info
        """
        logger.info("Loading device information from backup...")
        self.device_info = extract_device_info(self.backup_path)
        logger.info(f"Loaded device: {self.device_info.device_name}")
        return self.device_info

    def scan_backup(self) -> dict:
        """Perform a one-time scan of the backup.

        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting backup scan: {self.backup_path}")

        results = {
            "backup_path": str(self.backup_path),
            "device_info": None,
            "is_encrypted": False,
            "installed_apps": [],
            "file_count": 0,
            "scan_timestamp": time.time(),
        }

        try:
            # Load device info
            device_info = self.load_device_info()
            results["device_info"] = device_info.to_dict()

            # Parse backup
            parser = BackupParser(self.backup_path)

            # Check encryption status
            results["is_encrypted"] = parser.is_encrypted()

            # Get installed apps (if not encrypted)
            if not results["is_encrypted"]:
                try:
                    results["installed_apps"] = parser.get_installed_apps()
                except Exception as e:
                    logger.warning(f"Could not get installed apps: {e}")

                # Get file count
                try:
                    files = parser.get_manifest_files()
                    results["file_count"] = len(files)
                except Exception as e:
                    logger.warning(f"Could not get file count: {e}")

            logger.info(
                f"Scan complete: {results['file_count']} files, "
                f"{len(results['installed_apps'])} apps, "
                f"encrypted: {results['is_encrypted']}"
            )

        except Exception as e:
            logger.error(f"Error during backup scan: {e}")
            results["error"] = str(e)

        return results

    def start(self) -> None:
        """Start monitoring the backup directory."""
        if self._is_running:
            logger.warning("Monitor is already running")
            return

        # Load device info before starting
        try:
            self.load_device_info()
        except Exception as e:
            logger.error(f"Failed to load device info: {e}")

        # Start file watcher
        self.file_watcher.start()
        self._is_running = True
        logger.info(f"Started monitoring backup: {self.backup_path}")

    def stop(self) -> None:
        """Stop monitoring the backup directory."""
        if not self._is_running:
            return

        self.file_watcher.stop()
        self._is_running = False
        logger.info(f"Stopped monitoring backup: {self.backup_path}")

    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._is_running

    def __enter__(self) -> "BackupMonitor":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type: type, exc_val: Exception, exc_tb: object) -> None:
        """Context manager exit."""
        self.stop()
