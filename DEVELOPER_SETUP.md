# Developer Setup Guide

Complete guide for setting up a development environment for PrivaseeAI.Security.

## Prerequisites

- **Python 3.11+** (required)
- **macOS** (primary development platform)
- **Git** (for version control)
- **Make** (for build automation)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
make install-dev

# 4. Install pre-commit hooks
make setup-hooks

# 5. Run tests to verify setup
make test

# 6. Verify everything works
privasee --version  # Should show v0.3.0
```

## Detailed Setup

### 1. Virtual Environment

Always use a virtual environment to isolate dependencies:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it (macOS/Linux)
source .venv/bin/activate

# Activate it (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Verify Python version
python --version  # Should be 3.11+
```

### 2. Install Dependencies

```bash
# Production dependencies
make install

# Development dependencies (includes testing, linting, etc.)
make install-dev

# Or install manually:
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install pre-commit
```

### 3. Install Package in Editable Mode

```bash
# Install as editable package for development
pip install -e .

# Now you can run privasee from anywhere
privasee --version
```

### 4. Set Up Pre-Commit Hooks

Pre-commit hooks automatically check your code before each commit:

```bash
# Install hooks
make setup-hooks

# Or manually:
pre-commit install
pre-commit install --hook-type commit-msg

# Test hooks on all files
make pre-commit
```

**What the hooks do:**
- ✅ Format code with **black**
- ✅ Sort imports with **isort**
- ✅ Lint with **flake8**
- ✅ Type check with **mypy**
- ✅ Security scan with **bandit**
- ✅ Check for secrets/credentials
- ✅ Validate YAML/JSON files
- ✅ Check for trailing whitespace
- ✅ Ensure files end with newline

### 5. Configure IDE

#### Visual Studio Code

Create `.vscode/settings.json`:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": false,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "python.formatting.blackArgs": ["--line-length", "100"],
  "python.sortImports.args": ["--profile", "black"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "python.testing.pytestArgs": ["tests"],
  "[python]": {
    "editor.rulers": [100],
    "editor.tabSize": 4
  }
}
```

#### PyCharm

1. **Set Python Interpreter:**
   - File → Settings → Project → Python Interpreter
   - Add Interpreter → Existing Environment
   - Select `.venv/bin/python`

2. **Configure Code Style:**
   - Settings → Tools → Black
   - Enable "On save"
   - Line length: 100

3. **Enable Tests:**
   - Settings → Tools → Python Integrated Tools
   - Default test runner: pytest

## Development Workflow

### Running Tests

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Run with coverage
make test-coverage

# Watch mode (runs tests on file changes)
make test-watch
```

### Code Quality

```bash
# Format code
make format

# Check linting (don't auto-fix)
make lint

# Type checking
make type-check

# Run all quality checks
make lint && make type-check && make security-check

# Or use pre-commit to run everything
make pre-commit
```

### Security Checks

```bash
# Run security vulnerability scan
make security-check

# This runs:
# - bandit (Python security linter)
# - pip-audit (dependency vulnerability scanner)
```

### Before Committing

```bash
# 1. Make your changes
vim src/privaseeai_security/some_file.py

# 2. Run tests
make test

# 3. Format and lint
make format
make lint

# 4. Commit (hooks run automatically)
git add .
git commit -m "feat: add new detection rule"

# If hooks fail, fix issues and try again
```

## Common Tasks

### Adding a New Dependency

```bash
# 1. Add to requirements.txt (production) or requirements-dev.txt (dev only)
echo "new-package>=1.0.0" >> requirements.txt

# 2. Install it
pip install new-package

# 3. Update lock file
pip freeze > requirements-lock.txt

# 4. Commit changes
git add requirements.txt requirements-lock.txt
git commit -m "deps: add new-package for feature X"
```

### Creating a New Monitor

```bash
# 1. Create new file
touch src/privaseeai_security/monitors/my_monitor.py

# 2. Write code following existing patterns
# See: src/privaseeai_security/monitors/vpn_integrity.py

# 3. Create tests
touch tests/unit/test_my_monitor.py
touch tests/integration/test_my_monitor_integration.py

# 4. Run tests
make test

# 5. Update documentation
# Add to README.md and create docs/monitors/my_monitor.md
```

### Debugging

```bash
# Run with debug logging
export LOG_LEVEL=DEBUG
privasee start

# Or use Python debugger
python -m pdb -c continue -m privaseeai_security.cli start

# In code, add breakpoint:
import pdb; pdb.set_trace()
```

### Building Docker Image

```bash
# Build image
make docker-build

# Run in Docker
make docker-up

# View logs
make docker-logs

# Open shell in container
make docker-shell

# Stop services
make docker-down

# Clean up
make docker-clean
```

## Testing

### Test Structure

```
tests/
├── unit/                  # Fast, isolated tests
│   ├── test_*.py         # Test individual functions/classes
│   └── ...
├── integration/          # Slower, end-to-end tests
│   ├── test_*.py        # Test component interactions
│   └── ...
└── fixtures/            # Test data
    └── sample_data.py
```

### Writing Tests

```python
# tests/unit/test_my_feature.py
import pytest
from privaseeai_security.my_module import my_function


class TestMyFeature:
    """Test suite for my feature."""

    def test_basic_functionality(self):
        """Test basic case."""
        result = my_function("input")
        assert result == "expected_output"

    def test_edge_case(self):
        """Test edge case."""
        with pytest.raises(ValueError):
            my_function(None)

    @pytest.mark.asyncio
    async def test_async_function(self):
        """Test async function."""
        result = await my_async_function()
        assert result is not None
```

### Running Specific Tests

```bash
# Run specific test file
pytest tests/unit/test_config.py

# Run specific test class
pytest tests/unit/test_config.py::TestConfig

# Run specific test method
pytest tests/unit/test_config.py::TestConfig::test_load_from_file

# Run tests matching pattern
pytest -k "test_vpn"

# Run with verbose output
pytest -v

# Run with extra debugging
pytest -vv --tb=short
```

## Troubleshooting

### Common Issues

#### Import Errors

```bash
# Ensure package is installed in editable mode
pip install -e .

# Verify PYTHONPATH includes src/
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
```

#### Pre-commit Hooks Failing

```bash
# Update hooks to latest versions
pre-commit autoupdate

# Clear cache and reinstall
pre-commit clean
pre-commit install --install-hooks

# Skip hooks temporarily (emergency only!)
git commit --no-verify -m "message"
```

#### Tests Failing

```bash
# Clear pytest cache
rm -rf .pytest_cache

# Reinstall dependencies
pip install -r requirements-dev.txt

# Check Python version
python --version  # Must be 3.11+
```

#### Type Checking Errors

```bash
# Run mypy with verbose output
mypy src --show-error-codes

# Ignore specific error on one line
result = function()  # type: ignore[error-code]

# Update mypy configuration in pyproject.toml
```

## Best Practices

### Code Style

1. **Follow PEP 8** - Let black handle formatting
2. **Type hints** - Add type annotations to all functions
3. **Docstrings** - Google-style docstrings for all public APIs
4. **Line length** - Max 100 characters
5. **Import order** - stdlib → third-party → local (isort handles this)

### Git Commits

```bash
# Use conventional commits format
git commit -m "type(scope): description"

# Types:
# - feat: New feature
# - fix: Bug fix
# - docs: Documentation changes
# - test: Test changes
# - refactor: Code refactoring
# - perf: Performance improvement
# - chore: Build/tooling changes

# Examples:
git commit -m "feat(monitors): add DNS tampering detection"
git commit -m "fix(orchestrator): handle shutdown signal properly"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(vpn): add integration test for TCP fallback"
```

### Pull Requests

1. **Create feature branch** from `main`
2. **Make atomic commits** - one logical change per commit
3. **Run full test suite** before pushing
4. **Update documentation** for user-facing changes
5. **Reference issues** in PR description

```bash
# Create feature branch
git checkout -b feat/my-new-feature

# Make changes and commit
git add .
git commit -m "feat: implement new feature"

# Push to origin
git push origin feat/my-new-feature

# Create PR on GitHub
```

## Resources

### Documentation
- [README.md](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [ROADMAP.md](ROADMAP.md) - Development roadmap
- [USER_GUIDE.md](USER_GUIDE.md) - End-user documentation

### External Resources
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Pytest Documentation](https://docs.pytest.org/)
- [Pre-commit Hooks](https://pre-commit.com/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [Conventional Commits](https://www.conventionalcommits.org/)

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
- **Discussions:** [GitHub Discussions](https://github.com/aurelianware/PrivaseeAI.Security/discussions)
- **Email:** dev@aurelianware.com

---

**Happy coding! 🛡️**
