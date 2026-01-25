"""Logging system for PrivaseeAI.Security."""

import json
import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler

from privaseeai_security.core.config import LogFormat, LoggingSettings, get_settings


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "correlation_id"):
            log_data["correlation_id"] = record.correlation_id

        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id

        # Add any custom attributes
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "stack_info",
                "correlation_id",
                "user_id",
            ]:
                log_data[key] = value

        return json.dumps(log_data)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for development."""

    def __init__(self) -> None:
        """Initialize text formatter."""
        super().__init__(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def setup_logger(
    name: str = "privaseeai_security",
    settings: LoggingSettings | None = None,
) -> logging.Logger:
    """Set up and configure logger.

    Args:
        name: Logger name
        settings: Logging settings (uses global settings if not provided)

    Returns:
        Configured logger instance
    """
    if settings is None:
        app_settings = get_settings()
        settings = app_settings.logging

    logger = logging.getLogger(name)

    # Only configure if not already configured
    if logger.handlers:
        return logger

    # Set log level
    log_level = getattr(logging, settings.level.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Choose formatter based on configuration
    if settings.format == LogFormat.JSON:
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if path is specified)
    if settings.file_path:
        try:
            # Create log directory if it doesn't exist
            log_dir = settings.file_path.parent
            log_dir.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                settings.file_path,
                maxBytes=settings.rotation_size,
                backupCount=settings.backup_count,
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except (OSError, PermissionError) as e:
            # Log to console if file logging fails
            logger.warning(f"Failed to set up file logging: {e}")

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str = "privaseeai_security") -> logging.Logger:
    """Get logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records."""

    def __init__(self, correlation_id: str):
        """Initialize correlation ID filter.

        Args:
            correlation_id: Correlation ID to add to log records
        """
        super().__init__()
        self.correlation_id = correlation_id

    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation ID to record."""
        record.correlation_id = self.correlation_id
        return True
