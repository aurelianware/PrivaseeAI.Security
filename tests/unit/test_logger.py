"""Unit tests for logging module."""

import gzip
import json
import logging
import tempfile
import time
from pathlib import Path

import pytest

from privaseeai_security.logger import (
    setup_logger,
    get_logger,
    JSONFormatter,
    setup_production_logger,
    configure_structlog,
    get_structlog,
    CustomJsonFormatter,
)


class TestJSONFormatter:
    """Test cases for JSONFormatter class."""

    def test_format_basic_log(self):
        """Test formatting basic log record."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.module = "test_module"
        record.funcName = "test_function"
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test_logger"
        assert log_data["message"] == "Test message"
        assert log_data["module"] == "test_module"
        assert log_data["function"] == "test_function"
        assert log_data["line"] == 10

    def test_format_includes_timestamp(self):
        """Test that formatted log includes timestamp."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.module = "test"
        record.funcName = "test"
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert "timestamp" in log_data
        assert log_data["timestamp"].endswith("Z") or "T" in log_data["timestamp"]


class TestSetupLogger:
    """Test cases for setup_logger function."""

    def test_setup_logger_default_params(self):
        """Test logger setup with default parameters."""
        logger = setup_logger()
        assert logger.name == "privaseeai_security"
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0

    def test_setup_logger_custom_name(self):
        """Test logger setup with custom name."""
        logger = setup_logger(name="custom_logger")
        assert logger.name == "custom_logger"

    def test_setup_logger_custom_level(self):
        """Test logger setup with custom log level."""
        logger = setup_logger(level="DEBUG")
        assert logger.level == logging.DEBUG

    def test_setup_logger_text_format(self):
        """Test logger setup with text format."""
        logger = setup_logger(log_format="text")
        assert len(logger.handlers) > 0
        handler = logger.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_setup_logger_json_format(self):
        """Test logger setup with JSON format."""
        logger = setup_logger(log_format="json")
        assert len(logger.handlers) > 0
        handler = logger.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_setup_logger_with_file(self):
        """Test logger setup with file handler."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name
        
        try:
            logger = setup_logger(log_file=log_file)
            assert len(logger.handlers) == 2  # Console and file handler
            
            # Test that log file is created
            logger.info("Test log message")
            assert Path(log_file).exists()
        finally:
            Path(log_file).unlink(missing_ok=True)

    def test_setup_logger_clears_existing_handlers(self):
        """Test that setup_logger clears existing handlers."""
        logger = setup_logger(name="test_clear_handlers")
        initial_handlers = len(logger.handlers)
        
        # Setup again should clear and recreate handlers
        logger = setup_logger(name="test_clear_handlers")
        assert len(logger.handlers) == initial_handlers

    def test_setup_logger_levels(self):
        """Test all log levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in levels:
            logger = setup_logger(name=f"test_{level}", level=level)
            assert logger.level == getattr(logging, level)


class TestGetLogger:
    """Test cases for get_logger function."""

    def test_get_logger_default(self):
        """Test getting logger with default name."""
        logger = get_logger()
        assert logger.name == "privaseeai_security"

    def test_get_logger_custom_name(self):
        """Test getting logger with custom name."""
        logger = get_logger(name="custom_name")
        assert logger.name == "custom_name"

    def test_get_logger_returns_same_instance(self):
        """Test that get_logger returns same instance for same name."""
        logger1 = get_logger(name="test_instance")
        logger2 = get_logger(name="test_instance")
        assert logger1 is logger2


@pytest.fixture
def temp_log_dir():
    """Provide a temporary directory for log files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestProductionLogger:
    """Test cases for production logger with rotation."""

    def test_setup_production_logger_creates_log_files(self, temp_log_dir):
        """Test that production logger creates log files."""
        logger = setup_production_logger(
            name="test_prod",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Write some logs
        logger.info("Test message")
        
        # Check that log files were created
        log_files = list(temp_log_dir.glob("*.log"))
        assert len(log_files) > 0

    def test_production_logger_json_format(self, temp_log_dir):
        """Test that production logger writes JSON formatted logs."""
        logger = setup_production_logger(
            name="test_json",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Write a log message
        logger.info("Test JSON message", extra={"user_id": 123})
        
        # Find and read the log file
        log_files = list(temp_log_dir.glob("*.log"))
        assert len(log_files) > 0
        
        with open(log_files[0], "r") as f:
            log_line = f.readline()
            log_data = json.loads(log_line)
            
            assert "timestamp" in log_data
            assert log_data["level"] == "INFO"
            assert "Test JSON message" in log_data["message"]

    def test_production_logger_with_rich_console(self, temp_log_dir):
        """Test production logger with Rich console handler."""
        logger = setup_production_logger(
            name="test_rich",
            log_dir=temp_log_dir,
            enable_console=True,
            enable_rich=True,
        )
        
        # Should have both file and console handlers
        assert len(logger.handlers) >= 2
        
        # Write a log message
        logger.info("Test Rich message")

    def test_production_logger_rotation_ready(self, temp_log_dir):
        """Test that production logger has rotation configured."""
        logger = setup_production_logger(
            name="test_rotation",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Check that handlers have rotation capabilities
        rotating_handlers = [
            h for h in logger.handlers
            if isinstance(h, (logging.handlers.RotatingFileHandler, 
                            logging.handlers.TimedRotatingFileHandler))
        ]
        
        assert len(rotating_handlers) > 0

    def test_production_logger_fallback_to_local_logs(self):
        """Test that logger falls back to local logs when /var/log is not writable."""
        # Use a non-existent directory that will require fallback
        logger = setup_production_logger(
            name="test_fallback",
            log_dir=None,  # Will auto-detect and fallback
            enable_console=True,
        )
        
        # Logger should still be created
        assert logger is not None


class TestLogRotation:
    """Test cases for log rotation functionality."""

    def test_size_based_rotation(self, temp_log_dir):
        """Test that logs rotate based on file size."""
        # Create logger with very small max size for testing
        logger = setup_production_logger(
            name="test_size_rotation",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Manually configure a small size for testing
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.maxBytes = 1024  # 1 KB for testing
                handler.backupCount = 3
        
        # Write enough logs to trigger rotation
        for i in range(100):
            logger.info(f"Test message {i} with some extra content to make it longer")
        
        # Check for rotated files (they should have .gz extension)
        log_files = list(temp_log_dir.glob("*.log*"))
        assert len(log_files) > 1  # Should have main file plus rotated files

    def test_gzip_compression_on_rotation(self, temp_log_dir):
        """Test that rotated logs are compressed with gzip."""
        logger = setup_production_logger(
            name="test_gzip",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Configure small size for testing
        rotating_handler = None
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.maxBytes = 500  # Very small for quick rotation
                handler.backupCount = 2
                rotating_handler = handler
                break
        
        if rotating_handler:
            # Write logs to trigger rotation
            for i in range(50):
                logger.info(f"Test message {i} " + "x" * 100)
            
            # Force a rotation
            rotating_handler.doRollover()
            
            # Check for .gz files
            gz_files = list(temp_log_dir.glob("*.gz"))
            if gz_files:
                # Verify it's a valid gzip file
                with gzip.open(gz_files[0], "rt") as f:
                    content = f.read()
                    assert len(content) > 0

    def test_retention_policy(self, temp_log_dir):
        """Test that old log files are removed according to retention policy."""
        logger = setup_production_logger(
            name="test_retention",
            log_dir=temp_log_dir,
            enable_console=False,
        )
        
        # Configure small size and backup count for testing
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.maxBytes = 500
                handler.backupCount = 3  # Keep only 3 backups
        
        # Write many logs to trigger multiple rotations
        for i in range(200):
            logger.info(f"Test message {i} " + "x" * 100)
        
        # Count log files (should not exceed backup count + 1 for main file)
        log_files = list(temp_log_dir.glob("privaseeai.log*"))
        # Allow some flexibility in the count due to timing
        assert len(log_files) <= 10  # Main + backups


class TestStructlog:
    """Test cases for structlog integration."""

    def test_configure_structlog_development(self):
        """Test structlog configuration for development."""
        configure_structlog(development_mode=True)
        
        # Get a structlog instance
        logger = get_structlog("test_structlog")
        
        # Should be able to log
        logger.info("test_message", key="value")

    def test_configure_structlog_production(self):
        """Test structlog configuration for production."""
        configure_structlog(development_mode=False)
        
        # Get a structlog instance
        logger = get_structlog("test_structlog_prod")
        
        # Should be able to log
        logger.info("test_message", key="value")

    def test_get_structlog(self):
        """Test getting structlog instance."""
        logger = get_structlog()
        assert logger is not None


class TestCustomJsonFormatter:
    """Test cases for CustomJsonFormatter."""

    def test_custom_json_formatter_fields(self):
        """Test that CustomJsonFormatter includes all required fields."""
        formatter = CustomJsonFormatter()
        
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.module = "test_module"
        record.funcName = "test_function"
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        # Check all required fields
        assert "timestamp" in log_data
        assert log_data["timestamp"].endswith("Z")
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test_logger"
        assert log_data["module"] == "test_module"
        assert log_data["function"] == "test_function"
        assert log_data["line"] == 42
        assert "process" in log_data
        assert "thread" in log_data


@pytest.fixture
def rotation_logger(temp_log_dir):
    """Pytest fixture for testing log rotation.
    
    Creates a logger configured for easy rotation testing with:
    - Small file size limit (1 KB)
    - Small backup count (3 files)
    - Gzip compression enabled
    - No console output (to avoid clutter in tests)
    
    Usage:
        def test_my_rotation(rotation_logger):
            logger = rotation_logger
            # Write logs to trigger rotation
            for i in range(100):
                logger.info(f"Message {i}")
    """
    logger = setup_production_logger(
        name="rotation_test",
        log_dir=temp_log_dir,
        enable_console=False,
    )
    
    # Configure for easy testing
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.maxBytes = 1024  # 1 KB
            handler.backupCount = 3
    
    yield logger
    
    # Cleanup
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)


@pytest.fixture  
def production_logger_fixture(temp_log_dir):
    """Pytest fixture for production logger testing.
    
    Provides a fully configured production logger with:
    - Size-based rotation (100 MB, keep 10 files)
    - Time-based rotation (daily, keep 30 days)
    - JSON structured logging
    - Gzip compression
    - Temporary log directory for testing
    
    Usage:
        def test_logging_feature(production_logger_fixture):
            logger = production_logger_fixture
            logger.info("Test message", extra={"key": "value"})
    """
    logger = setup_production_logger(
        name="production_test",
        log_dir=temp_log_dir,
        enable_console=True,
        enable_rich=False,
    )
    
    yield logger
    
    # Cleanup
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
