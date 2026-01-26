"""Logging utilities for PrivaseeAI Security."""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted log string
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
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


def setup_logger(
    name: str = "privaseeai_security",
    level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Setup logger with specified configuration.
    
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


def get_logger(name: str = "privaseeai_security") -> logging.Logger:
    """Get logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
