# Production-Ready Logging System

## Overview

PrivaseeAI.Security now includes a production-ready logging system with:

- **Log Rotation**: Automatic rotation based on size (100 MB) or time (daily)
- **Retention Policies**: Keep last 30 days (time-based) or 10 files (size-based)
- **Compression**: Old logs are automatically compressed with gzip
- **Structured Logging**: JSON format for production, pretty console for development
- **Rich Integration**: Beautiful console output with Rich library during development
- **Structlog Support**: Advanced structured logging with context

## Quick Start

### Basic Usage (Backward Compatible)

```python
from privaseeai_security.logger import setup_logger, get_logger

# Setup logger (existing code continues to work)
logger = setup_logger()
logger.info("Application started")

# Or get existing logger
logger = get_logger(__name__)
logger.warning("Warning message")
```

### Production Usage (Recommended)

```python
from privaseeai_security.logger import setup_production_logger

# Production logger with rotation and compression
logger = setup_production_logger(
    name="my_app",
    level="INFO",
    enable_rich=False  # Standard console output
)

logger.info("Production ready logging")
logger.error("Logs will rotate at 100 MB or daily")
```

### Development Usage (Pretty Console)

```python
from privaseeai_security.logger import setup_production_logger

# Development logger with Rich console
logger = setup_production_logger(
    name="my_app",
    level="DEBUG",
    enable_rich=True  # Pretty console with colors
)

logger.info("Beautiful console output")
logger.warning("With syntax highlighting")
```

### Structured Logging with Structlog

```python
from privaseeai_security.logger import configure_structlog, get_structlog

# Configure structlog
configure_structlog(development_mode=True)

# Get structured logger
logger = get_structlog("my_app")

# Log with context
logger.info("user_login", user_id=123, ip="192.168.1.1")
logger.warning("rate_limit", user_id=456, requests=1000)
```

## Features

### Log Rotation

The production logger implements **dual rotation strategy**:

1. **Size-based rotation**:
   - Rotates when log file reaches 100 MB
   - Keeps last 10 backup files
   - Old files are compressed with gzip

2. **Time-based rotation**:
   - Rotates daily at midnight
   - Keeps last 30 days of logs
   - Old files are compressed with gzip

### Log Storage

- **Production**: Logs are written to `/var/log/privaseeai/`
- **Fallback**: If `/var/log` is not writable, falls back to `./logs/`
- **Files**:
  - `privaseeai.log` - Main log file (size-based rotation)
  - `privaseeai_daily.log` - Daily log file (time-based rotation)
  - `*.log.*.gz` - Compressed backup files

### Log Format

**File Logs** (JSON structured):
```json
{
  "timestamp": "2026-02-04T11:20:23.974709+00:00",
  "level": "INFO",
  "logger": "my_app",
  "message": "User logged in",
  "module": "auth",
  "function": "login",
  "line": 42,
  "process": 12345,
  "thread": 67890
}
```

**Console Logs** (Standard):
```
2026-02-04 11:20:23,976 - my_app - INFO - User logged in
```

**Console Logs** (Rich):
```
[02/04/26 11:20:23] INFO     User logged in     auth.py:42
```

## API Reference

### setup_production_logger()

Setup production-ready logger with rotation and compression.

```python
def setup_production_logger(
    name: str = "privaseeai_security",
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    log_file: str = "privaseeai.log",
    enable_console: bool = True,
    enable_rich: bool = False,
) -> logging.Logger
```

**Parameters**:
- `name`: Logger name (default: "privaseeai_security")
- `level`: Log level - DEBUG, INFO, WARNING, ERROR, CRITICAL (default: "INFO")
- `log_dir`: Directory for log files (default: auto-detect)
- `log_file`: Log file name (default: "privaseeai.log")
- `enable_console`: Enable console output (default: True)
- `enable_rich`: Use Rich for console output (default: False)

**Returns**: Configured logger instance

### setup_logger()

Setup basic logger (backward compatible).

```python
def setup_logger(
    name: str = "privaseeai_security",
    level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
) -> logging.Logger
```

**Parameters**:
- `name`: Logger name
- `level`: Log level
- `log_format`: Format - "json" or "text"
- `log_file`: Optional log file path

**Returns**: Configured logger instance

### configure_structlog()

Configure structlog for structured logging.

```python
def configure_structlog(
    development_mode: bool = True,
    log_dir: Optional[Path] = None,
) -> None
```

**Parameters**:
- `development_mode`: Enable development-friendly output
- `log_dir`: Directory for log files

### get_structlog()

Get structlog instance for structured logging.

```python
def get_structlog(name: str = "privaseeai_security") -> structlog.BoundLogger
```

**Parameters**:
- `name`: Logger name

**Returns**: Structured logger instance

## Testing

### Running Tests

```bash
# Run all logger tests
pytest tests/unit/test_logger.py -v

# Run specific test class
pytest tests/unit/test_logger.py::TestProductionLogger -v

# Run with coverage
pytest tests/unit/test_logger.py --cov=src/privaseeai_security/logger
```

### Test Fixtures

The test suite includes pytest fixtures for easy testing:

```python
def test_my_feature(production_logger_fixture):
    """Test with production logger."""
    logger = production_logger_fixture
    logger.info("Testing feature")
    # Test continues...

def test_rotation(rotation_logger):
    """Test log rotation."""
    logger = rotation_logger
    # Write logs to trigger rotation
    for i in range(100):
        logger.info(f"Message {i}")
    # Verify rotation occurred...
```

## Migration Guide

### Migrating from Basic Logger

**Before**:
```python
from privaseeai_security.logger import setup_logger

logger = setup_logger(log_format="json")
logger.info("Message")
```

**After** (with rotation):
```python
from privaseeai_security.logger import setup_production_logger

logger = setup_production_logger(enable_rich=False)
logger.info("Message")
```

### Migrating to Structlog

**Before**:
```python
logger.info(f"User {user_id} logged in from {ip}")
```

**After**:
```python
from privaseeai_security.logger import configure_structlog, get_structlog

configure_structlog(development_mode=False)
logger = get_structlog()
logger.info("user_login", user_id=user_id, ip=ip)
```

## Best Practices

1. **Use Production Logger in Production**:
   ```python
   logger = setup_production_logger(enable_rich=False)
   ```

2. **Use Rich Console in Development**:
   ```python
   logger = setup_production_logger(enable_rich=True)
   ```

3. **Use Structlog for Structured Data**:
   ```python
   logger = get_structlog()
   logger.info("event", key="value", user_id=123)
   ```

4. **Set Appropriate Log Levels**:
   - DEBUG: Detailed development information
   - INFO: General production information
   - WARNING: Important notices
   - ERROR: Error messages
   - CRITICAL: Critical issues

5. **Monitor Log Disk Space**:
   - Rotation keeps logs under control
   - Old logs are compressed with gzip
   - Configure backup count based on disk space

## Troubleshooting

### Logs Not Rotating

**Check**:
1. Verify log directory permissions
2. Ensure enough disk space
3. Check that logger handlers are properly configured

### Cannot Write to /var/log

**Solution**:
The logger automatically falls back to `./logs/` directory if `/var/log` is not writable.

### Large Log Files

**Solution**:
1. Reduce backup count (keeps fewer files)
2. Reduce max file size (rotates more frequently)
3. Increase log level to reduce verbosity

## Examples

See `demo_logger.py` for complete working examples of all features.

```bash
# Run the demo
python demo_logger.py
```

## Dependencies

- Python 3.11+
- structlog >= 23.2.0
- rich >= 13.7.0
- python-json-logger >= 2.0.7

## License

Apache-2.0
