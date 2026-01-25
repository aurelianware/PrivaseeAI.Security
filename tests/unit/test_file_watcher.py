"""Unit tests for file watcher module."""

import pytest
import tempfile
import time
from pathlib import Path

from privaseeai_security.file_watcher import FileWatcher, FileWatcherError


class TestFileWatcher:
    """Test cases for FileWatcher class."""

    def test_file_watcher_initialization(self):
        """Test FileWatcher initialization."""
        watcher = FileWatcher(watch_paths=["/tmp/test"], interval=5)
        assert len(watcher.watch_paths) == 1
        assert watcher.interval == 5
        assert watcher.is_running is False

    def test_file_watcher_multiple_paths(self):
        """Test FileWatcher with multiple watch paths."""
        paths = ["/tmp/path1", "/tmp/path2", "/tmp/path3"]
        watcher = FileWatcher(watch_paths=paths, interval=3)
        
        assert len(watcher.watch_paths) == 3
        for i, path in enumerate(watcher.watch_paths):
            assert str(path) == paths[i]

    def test_file_watcher_default_interval(self):
        """Test FileWatcher with default interval."""
        watcher = FileWatcher(watch_paths=["/tmp/test"])
        assert watcher.interval == 5

    def test_add_callback(self):
        """Test adding callback to file watcher."""
        watcher = FileWatcher(watch_paths=["/tmp/test"])
        
        def test_callback(files):
            pass
        
        watcher.add_callback(test_callback)
        assert len(watcher._callbacks) == 1

    def test_add_multiple_callbacks(self):
        """Test adding multiple callbacks."""
        watcher = FileWatcher(watch_paths=["/tmp/test"])
        
        def callback1(files):
            pass
        
        def callback2(files):
            pass
        
        watcher.add_callback(callback1)
        watcher.add_callback(callback2)
        
        assert len(watcher._callbacks) == 2

    def test_start_watcher(self):
        """Test starting file watcher."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            assert watcher.is_running is True
            
            watcher.stop()

    def test_stop_watcher(self):
        """Test stopping file watcher."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            watcher.stop()
            
            assert watcher.is_running is False

    def test_check_for_changes_empty_directory(self):
        """Test checking for changes in empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            changes = watcher.check_for_changes()
            assert isinstance(changes, list)
            assert len(changes) == 0

    def test_check_for_changes_new_file(self):
        """Test detecting new file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            # First check - no changes
            changes = watcher.check_for_changes()
            assert len(changes) == 0
            
            # Create a new file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")
            
            # Second check - should detect new file
            changes = watcher.check_for_changes()
            assert len(changes) == 1
            assert changes[0] == test_file

    def test_check_for_changes_ignores_existing_files(self):
        """Test that existing files are not reported as changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file before starting watcher
            test_file = Path(tmpdir) / "existing.txt"
            test_file.write_text("existing content")
            
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            # Check should not report existing file
            changes = watcher.check_for_changes()
            assert len(changes) == 0

    def test_run_once(self):
        """Test running a single check cycle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            callback_called = []
            
            def callback(files):
                callback_called.append(files)
            
            watcher.add_callback(callback)
            
            # Create new file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test")
            
            # Run once should trigger callback
            watcher.run_once()
            
            assert len(callback_called) == 1
            assert len(callback_called[0]) == 1

    def test_run_once_no_changes(self):
        """Test run_once when there are no changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            watcher.start()
            
            callback_called = []
            
            def callback(files):
                callback_called.append(files)
            
            watcher.add_callback(callback)
            watcher.run_once()
            
            # Callback should not be called if no changes
            assert len(callback_called) == 0

    def test_watch_nonexistent_directory(self):
        """Test watching non-existent directory."""
        watcher = FileWatcher(watch_paths=["/nonexistent/directory"])
        watcher.start()
        
        # Should not raise error, just find no files
        changes = watcher.check_for_changes()
        assert len(changes) == 0

    def test_is_running_property(self):
        """Test is_running property."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(watch_paths=[tmpdir])
            
            assert watcher.is_running is False
            
            watcher.start()
            assert watcher.is_running is True
            
            watcher.stop()
            assert watcher.is_running is False

    def test_watch_multiple_directories(self):
        """Test watching multiple directories simultaneously."""
        with tempfile.TemporaryDirectory() as tmpdir1:
            with tempfile.TemporaryDirectory() as tmpdir2:
                watcher = FileWatcher(watch_paths=[tmpdir1, tmpdir2])
                watcher.start()
                
                # Create files in both directories
                file1 = Path(tmpdir1) / "file1.txt"
                file2 = Path(tmpdir2) / "file2.txt"
                file1.write_text("content1")
                file2.write_text("content2")
                
                changes = watcher.check_for_changes()
                
                # Should detect both files
                assert len(changes) == 2
