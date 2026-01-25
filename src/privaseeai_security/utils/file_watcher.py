"""File system monitoring utilities using watchdog."""

import time
from pathlib import Path
from typing import Callable, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from privaseeai_security.core.logger import get_logger

logger = get_logger(__name__)


class DebounceEventHandler(FileSystemEventHandler):
    """File system event handler with debouncing."""

    def __init__(
        self,
        on_created: Optional[Callable[[Path], None]] = None,
        on_modified: Optional[Callable[[Path], None]] = None,
        on_deleted: Optional[Callable[[Path], None]] = None,
        debounce_seconds: int = 5,
        file_patterns: Optional[Set[str]] = None,
    ):
        """Initialize debounce event handler.

        Args:
            on_created: Callback for file creation events
            on_modified: Callback for file modification events
            on_deleted: Callback for file deletion events
            debounce_seconds: Debounce time in seconds
            file_patterns: Set of file patterns to filter (e.g., {'.db', '.plist'})
        """
        super().__init__()
        self.on_created_callback = on_created
        self.on_modified_callback = on_modified
        self.on_deleted_callback = on_deleted
        self.debounce_seconds = debounce_seconds
        self.file_patterns = file_patterns or set()
        self._last_event_time: dict[str, float] = {}

    def _should_process_event(self, path: Path) -> bool:
        """Check if event should be processed based on debounce and filters."""
        # Check file pattern if specified
        if self.file_patterns and path.suffix not in self.file_patterns:
            return False

        # Check debounce
        path_str = str(path)
        current_time = time.time()
        last_time = self._last_event_time.get(path_str, 0)

        if current_time - last_time < self.debounce_seconds:
            return False

        self._last_event_time[path_str] = current_time
        return True

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation event."""
        if event.is_directory:
            return

        path = Path(event.src_path)
        if self._should_process_event(path) and self.on_created_callback:
            logger.info(f"File created: {path}")
            try:
                self.on_created_callback(path)
            except Exception as e:
                logger.error(f"Error processing file creation event for {path}: {e}")

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification event."""
        if event.is_directory:
            return

        path = Path(event.src_path)
        if self._should_process_event(path) and self.on_modified_callback:
            logger.info(f"File modified: {path}")
            try:
                self.on_modified_callback(path)
            except Exception as e:
                logger.error(f"Error processing file modification event for {path}: {e}")

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file deletion event."""
        if event.is_directory:
            return

        path = Path(event.src_path)
        # Don't check debounce for deletion events
        if self.on_deleted_callback:
            logger.info(f"File deleted: {path}")
            try:
                self.on_deleted_callback(path)
            except Exception as e:
                logger.error(f"Error processing file deletion event for {path}: {e}")


class FileWatcher:
    """File system watcher for monitoring directory changes."""

    def __init__(
        self,
        watch_path: Path,
        on_created: Optional[Callable[[Path], None]] = None,
        on_modified: Optional[Callable[[Path], None]] = None,
        on_deleted: Optional[Callable[[Path], None]] = None,
        debounce_seconds: int = 5,
        file_patterns: Optional[Set[str]] = None,
        recursive: bool = True,
    ):
        """Initialize file watcher.

        Args:
            watch_path: Directory path to watch
            on_created: Callback for file creation events
            on_modified: Callback for file modification events
            on_deleted: Callback for file deletion events
            debounce_seconds: Debounce time in seconds
            file_patterns: Set of file patterns to filter
            recursive: Whether to watch subdirectories
        """
        self.watch_path = watch_path
        self.recursive = recursive
        self.observer = Observer()
        self.event_handler = DebounceEventHandler(
            on_created=on_created,
            on_modified=on_modified,
            on_deleted=on_deleted,
            debounce_seconds=debounce_seconds,
            file_patterns=file_patterns,
        )
        self._is_running = False

    def start(self) -> None:
        """Start watching the directory."""
        if not self.watch_path.exists():
            raise FileNotFoundError(f"Watch path does not exist: {self.watch_path}")

        if not self.watch_path.is_dir():
            raise NotADirectoryError(f"Watch path is not a directory: {self.watch_path}")

        logger.info(f"Starting file watcher for: {self.watch_path}")
        self.observer.schedule(
            self.event_handler, str(self.watch_path), recursive=self.recursive
        )
        self.observer.start()
        self._is_running = True

    def stop(self) -> None:
        """Stop watching the directory."""
        if self._is_running:
            logger.info(f"Stopping file watcher for: {self.watch_path}")
            self.observer.stop()
            self.observer.join()
            self._is_running = False

    def is_running(self) -> bool:
        """Check if watcher is running."""
        return self._is_running

    def __enter__(self) -> "FileWatcher":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type: type, exc_val: Exception, exc_tb: object) -> None:
        """Context manager exit."""
        self.stop()
