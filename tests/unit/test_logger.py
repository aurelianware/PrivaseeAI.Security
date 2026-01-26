"""Unit tests for logging module."""

import json
import logging
import tempfile
from pathlib import Path

from privaseeai_security.logger import setup_logger, get_logger, JSONFormatter


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
