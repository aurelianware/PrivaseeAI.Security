# PrivaseeAI.Security Test Suite

This directory contains the comprehensive test suite for the PrivaseeAI.Security project.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── test_config.py      # Configuration module tests
│   ├── test_logger.py      # Logging module tests
│   ├── test_crypto.py      # Cryptography module tests
│   ├── test_device_info.py # Device information module tests
│   └── test_file_watcher.py # File watcher module tests
├── integration/            # Integration tests
│   └── test_backup_monitor.py # Backup monitoring integration tests
└── fixtures/               # Test fixtures and sample data
    └── sample_data.py      # Mock data for testing
```

## Running Tests

### Prerequisites

Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

### All Tests

Run the entire test suite:
```bash
pytest
# or
make test
```

### Unit Tests Only

Run only unit tests:
```bash
pytest tests/unit -v
# or
make test-unit
```

### Integration Tests Only

Run only integration tests:
```bash
pytest tests/integration -v
# or
make test-integration
```

### Coverage Report

Generate a coverage report:
```bash
pytest --cov --cov-report=html --cov-report=term
# or
make test-coverage
```

The HTML coverage report will be generated in the `htmlcov/` directory. Open `htmlcov/index.html` in a browser to view detailed coverage information.

## Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests

Run tests by marker:
```bash
pytest -m unit      # Run only unit tests
pytest -m integration  # Run only integration tests
pytest -m "not slow"   # Skip slow tests
```

## Writing Tests

### Test Naming Convention

- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Example Test

```python
import pytest
from privaseeai_security.config import Config

class TestConfig:
    """Test cases for Config class."""
    
    def test_init_with_defaults(self):
        """Test configuration initialization with default values."""
        config = Config()
        assert config.get("log_level") == "INFO"
```

### Using Fixtures

Test fixtures are available in `tests/fixtures/sample_data.py`:

```python
from tests.fixtures.sample_data import get_mock_config, get_sample_device_info

def test_with_mock_data():
    config_data = get_mock_config()
    device_info = get_sample_device_info()
    # Use mock data in test
```

## Current Test Coverage

**Overall Coverage: 98%**

| Module | Coverage |
|--------|----------|
| config.py | 100% |
| crypto.py | 100% |
| file_watcher.py | 100% |
| __init__.py | 100% |
| logger.py | 97% |
| backup_monitor.py | 95% |
| device_info.py | 93% |

## Continuous Integration

This repository does not include CI workflow configuration files (e.g., GitHub Actions workflows).

When setting up CI for this project, we recommend running the test suite:
- On every pull request
- On every commit to the main branch
- On scheduled nightly builds

## Contributing

When adding new features:
1. Write tests first (TDD approach recommended)
2. Ensure all tests pass: `make test`
3. Maintain minimum 90% coverage
4. Update this README if adding new test categories
