"""Logging utilities for PrivaseeAI Security.

Production-ready logging with:
- Log rotation (daily or at 100 MB)
- Retention (30 days / 10 files max)
- Gzip compression of old logs
- JSON structured logs to /var/log/privaseeai/
- Rich console output during development
"""

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from pythonjsonlogger import jsonlogger
from rich.console import Console
from rich.logging import RichHandler


# Default log directory for production
DEFAULT_LOG_DIR = Path("/var/log/privaseeai")
DEFAULT_LOG_FILE = "privaseeai.log"

# Rotation settings
MAX_BYTES = 100 * 1024 * 1024  # 100 MB
BACKUP_COUNT = 10  # Keep 10 backup files
ROTATION_TIME = "midnight"  # Daily rotation


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""

    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """Add custom fields to log record.
        
        Args:
            log_record: The log record dictionary to modify
            record: The logging.LogRecord instance
            message_dict: Message dictionary
        """
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp in ISO format
        log_record["timestamp"] = datetime.now(timezone.utc).isoformat()
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["module"] = record.module
        log_record["function"] = record.funcName
        log_record["line"] = record.lineno
        
        # Add process info for debugging
        log_record["process"] = record.process
        log_record["thread"] = record.thread


class JSONFormatter(logging.Formatter):
    """JSON log formatter (kept for backward compatibility)."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted log string
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


def _create_rotating_file_handler(
    log_dir: Path,
    log_file: str,
    level: int,
    max_bytes: int = MAX_BYTES,
    backup_count: int = BACKUP_COUNT,
) -> logging.handlers.RotatingFileHandler:
    """Create a rotating file handler with gzip compression.
    
    Args:
        log_dir: Directory to store log files
        log_file: Name of the log file
        level: Log level
        max_bytes: Maximum file size before rotation (default: 100 MB)
        backup_count: Number of backup files to keep (default: 10)
        
    Returns:
        Configured RotatingFileHandler
    """
    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_path = log_dir / log_file
    
    # Create rotating file handler
    handler = logging.handlers.RotatingFileHandler(
        filename=str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(level)
    
    # Use custom namer and rotator for gzip compression
    handler.namer = lambda name: name + ".gz"
    
    def rotator(source: str, dest: str) -> None:
        """Compress rotated log file with gzip."""
        import gzip
        import shutil
        
        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)
    
    handler.rotator = rotator
    
    return handler


def _create_timed_rotating_file_handler(
    log_dir: Path,
    log_file: str,
    level: int,
    when: str = ROTATION_TIME,
    interval: int = 1,
    backup_count: int = 30,
) -> logging.handlers.TimedRotatingFileHandler:
    """Create a timed rotating file handler with gzip compression.
    
    Args:
        log_dir: Directory to store log files
        log_file: Name of the log file
        level: Log level
        when: When to rotate ('midnight', 'H', 'D', etc.)
        interval: Rotation interval
        backup_count: Number of backup files to keep (default: 30 days)
        
    Returns:
        Configured TimedRotatingFileHandler
    """
    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_path = log_dir / log_file
    
    # Create timed rotating file handler
    handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_path),
        when=when,
        interval=interval,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(level)
    
    # Use custom namer and rotator for gzip compression
    handler.namer = lambda name: name + ".gz"
    
    def rotator(source: str, dest: str) -> None:
        """Compress rotated log file with gzip."""
        import gzip
        import shutil
        
        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)
    
    handler.rotator = rotator
    
    return handler


def setup_production_logger(
    name: str = "privaseeai_security",
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    log_file: str = DEFAULT_LOG_FILE,
    enable_console: bool = True,
    enable_rich: bool = False,
) -> logging.Logger:
    """Setup production-ready logger with rotation and compression.
    
    Features:
    - Dual rotation: size-based (100MB) AND time-based (daily)
    - Keeps last 30 days of daily rotations
    - Keeps last 10 size-based rotations
    - Gzip compression of old logs
    - JSON structured logs to file
    - Optional Rich console output for development
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (default: /var/log/privaseeai or ./logs if no permissions)
        log_file: Log file name
        enable_console: Enable console output
        enable_rich: Use Rich handler for console (development mode)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.propagate = False
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    
    log_level = getattr(logging, level.upper())
    
    # Determine log directory
    if log_dir is None:
        # Try production directory first, fallback to local logs
        if os.access("/var/log", os.W_OK):
            log_dir = DEFAULT_LOG_DIR
        else:
            log_dir = Path.cwd() / "logs"
    
    # Add file handlers with rotation
    try:
        # Size-based rotation (100 MB, keep 10 files)
        size_handler = _create_rotating_file_handler(
            log_dir=log_dir,
            log_file=log_file,
            level=log_level,
            max_bytes=MAX_BYTES,
            backup_count=BACKUP_COUNT,
        )
        
        # Use JSON formatter for file logs
        json_formatter = CustomJsonFormatter(
            fmt="%(timestamp)s %(level)s %(name)s %(message)s"
        )
        size_handler.setFormatter(json_formatter)
        logger.addHandler(size_handler)
        
        # Time-based rotation (daily, keep 30 days)
        # Use a different filename to avoid conflicts
        time_handler = _create_timed_rotating_file_handler(
            log_dir=log_dir,
            log_file=log_file.replace(".log", "_daily.log"),
            level=log_level,
            when=ROTATION_TIME,
            backup_count=30,
        )
        time_handler.setFormatter(json_formatter)
        logger.addHandler(time_handler)
        
    except (OSError, PermissionError) as e:
        # If we can't write to log directory, warn and continue with console only
        print(f"Warning: Could not setup file logging: {e}", file=sys.stderr)
    
    # Add console handler
    if enable_console:
        if enable_rich:
            # Rich handler for development (pretty output)
            console = Console(stderr=True)
            console_handler = RichHandler(
                console=console,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
                markup=True,
            )
        else:
            # Standard handler
            console_handler = logging.StreamHandler(sys.stdout)
            
        console_handler.setLevel(log_level)
        
        # Use simple formatter for console
        if not enable_rich:
            console_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(console_formatter)
        
        logger.addHandler(console_handler)
    
    return logger


def setup_logger(
    name: str = "privaseeai_security",
    level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Setup logger with specified configuration (backward compatible).
    
    This function is kept for backward compatibility with existing code.
    For production use, prefer setup_production_logger().
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers (close them first to prevent file descriptor leaks)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    # Set formatter
    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def configure_structlog(
    development_mode: bool = True,
    log_dir: Optional[Path] = None,
) -> None:
    """Configure structlog for structured logging.
    
    Args:
        development_mode: Enable development-friendly output with Rich
        log_dir: Directory for log files (uses default if None)
    """
    # Determine log directory
    if log_dir is None:
        if os.access("/var/log", os.W_OK):
            log_dir = DEFAULT_LOG_DIR
        else:
            log_dir = Path.cwd() / "logs"
    
    # Configure processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if development_mode:
        # Development: pretty console output
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        # Production: JSON output
        processors.append(structlog.processors.JSONRenderer())
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "privaseeai_security") -> logging.Logger:
    """Get logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def get_structlog(name: str = "privaseeai_security") -> structlog.BoundLogger:
    """Get structlog instance for structured logging.
    
    Args:
        name: Logger name
        
    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)
