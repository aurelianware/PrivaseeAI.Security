"""File system watcher for monitoring iOS backups."""

import time
from pathlib import Path
from typing import Callable, List, Optional, Set


class FileWatcherError(Exception):
    """File watcher error exception."""
    pass


class FileWatcher:
    """Monitor file system for changes."""

    def __init__(self, watch_paths: List[str], interval: int = 5):
        """Initialize file watcher.
        
        Args:
            watch_paths: List of paths to watch
            interval: Polling interval in seconds
        """
        self.watch_paths = [Path(p) for p in watch_paths]
        self.interval = interval
        self._running = False
        self._callbacks: List[Callable] = []
        self._known_files: Set[Path] = set()

    def add_callback(self, callback: Callable) -> None:
        """Add callback to be called when changes detected.
        
        Args:
            callback: Function to call with changed files
        """
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start watching for file changes.
        
        Note:
            This is a stub implementation. Real implementation would use
            watchdog library or platform-specific file system events.
        """
        self._running = True
        self._scan_initial_state()

    def stop(self) -> None:
        """Stop watching for file changes."""
        self._running = False

    def _scan_initial_state(self) -> None:
        """Scan initial state of watched directories."""
        for watch_path in self.watch_paths:
            if watch_path.exists() and watch_path.is_dir():
                for file_path in watch_path.rglob("*"):
                    if file_path.is_file():
                        self._known_files.add(file_path)

    def check_for_changes(self) -> List[Path]:
        """Check for file changes.
        
        Returns:
            List of changed files
        """
        changes = []
        current_files: Set[Path] = set()
        
        for watch_path in self.watch_paths:
            if watch_path.exists() and watch_path.is_dir():
                for file_path in watch_path.rglob("*"):
                    if file_path.is_file():
                        current_files.add(file_path)
                        if file_path not in self._known_files:
                            changes.append(file_path)
        
        # Update known files
        self._known_files = current_files
        return changes

    def run_once(self) -> None:
        """Run a single check cycle.
        
        Note:
            This method is useful for testing.
        """
        changes = self.check_for_changes()
        if changes:
            for callback in self._callbacks:
                callback(changes)

    @property
    def is_running(self) -> bool:
        """Check if watcher is running.
        
        Returns:
            True if running, False otherwise
        """
        return self._running
