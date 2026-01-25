"""Unit tests for logging system."""

import logging

from privaseeai_security.core.logger import (
    CorrelationIdFilter,
    JSONFormatter,
    TextFormatter,
    get_logger,
    setup_logger,
)


def test_json_formatter():
    """Test JSON formatter."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "Test message" in formatted
    assert "INFO" in formatted
    assert "timestamp" in formatted
    assert "test" in formatted  # logger name


def test_text_formatter():
    """Test text formatter."""
    formatter = TextFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "Test message" in formatted
    assert "INFO" in formatted
    assert "test" in formatted


def test_correlation_id_filter():
    """Test correlation ID filter."""
    correlation_id = "test-correlation-123"
    filter_obj = CorrelationIdFilter(correlation_id)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    # Filter should add correlation_id to record
    result = filter_obj.filter(record)
    assert result is True
    assert hasattr(record, "correlation_id")
    assert record.correlation_id == correlation_id


def test_setup_logger():
    """Test logger setup."""
    logger = setup_logger("test_logger")
    assert logger.name == "test_logger"
    assert len(logger.handlers) > 0
    assert not logger.propagate


def test_get_logger():
    """Test getting logger."""
    logger = get_logger("test_get_logger")
    assert logger.name == "test_get_logger"
    assert isinstance(logger, logging.Logger)
