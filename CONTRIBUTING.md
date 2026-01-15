# Contributing to PrivaseeAI.Security

Thank you for your interest in contributing to PrivaseeAI.Security! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)
- [Community](#community)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.11 or higher
- Git
- PostgreSQL 14+ (for database development)
- Redis 6+ (for caching/streaming features)

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/PrivaseeAI.Security.git
   cd PrivaseeAI.Security
   ```

3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/aurelianware/PrivaseeAI.Security.git
   ```

4. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

6. **Copy environment configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

7. **Verify your setup**:
   ```bash
   python -m pytest tests/
   ```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Reports**: Report bugs using GitHub Issues
- **Feature Requests**: Suggest new features or enhancements
- **Code Contributions**: Submit bug fixes or new features via Pull Requests
- **Documentation**: Improve or add documentation
- **Testing**: Add or improve test coverage
- **Security**: Report security vulnerabilities (see [SECURITY.md](SECURITY.md))

### Reporting Bugs

Before creating a bug report:

1. **Check existing issues** to avoid duplicates
2. **Verify the bug** in the latest version
3. **Gather information** about your environment

When creating a bug report, include:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- System information (OS, Python version, etc.)
- Relevant logs or error messages
- Screenshots if applicable

### Suggesting Enhancements

When suggesting features:

1. **Check existing issues** for similar requests
2. **Provide clear use cases** for the feature
3. **Explain the expected behavior**
4. **Consider the scope** - does it fit the project goals?

## Development Process

### Branching Strategy

We follow a Git Flow-inspired branching model:

- `main` - Production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Urgent production fixes
- `docs/*` - Documentation updates

### Creating a Feature Branch

```bash
# Update your local repository
git checkout develop
git pull upstream develop

# Create your feature branch
git checkout -b feature/your-feature-name

# Make your changes and commit
git add .
git commit -m "feat: add your feature description"

# Push to your fork
git push origin feature/your-feature-name
```

### Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes
- `build`: Build system changes

**Examples:**
```
feat(monitoring): add continuous backup monitoring
fix(network): resolve packet capture memory leak
docs(readme): update installation instructions
test(analyzer): add unit tests for threat detection
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some project-specific conventions:

- **Line Length**: Maximum 100 characters
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Prefer double quotes for strings
- **Imports**: Group and sort using `isort`
- **Type Hints**: Use type hints for all functions
- **Docstrings**: Use Google-style docstrings

### Code Quality Tools

We use the following tools to maintain code quality:

```bash
# Format code
black privaseeai_security/

# Sort imports
isort privaseeai_security/

# Lint code
pylint privaseeai_security/
flake8 privaseeai_security/

# Type checking
mypy privaseeai_security/

# Security scanning
bandit -r privaseeai_security/
```

### Example Code Style

```python
"""Module for iOS backup monitoring.

This module provides continuous monitoring of iOS backups
and triggers analysis on changes.
"""

from typing import List, Optional, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class BackupMonitor:
    """Monitor iOS backup directory for changes.
    
    Attributes:
        backup_path: Path to the iOS backup directory.
        monitoring_enabled: Whether monitoring is currently active.
    """
    
    def __init__(self, backup_path: Path) -> None:
        """Initialize the backup monitor.
        
        Args:
            backup_path: Path to the iOS backup directory.
            
        Raises:
            ValueError: If backup_path doesn't exist.
        """
        if not backup_path.exists():
            raise ValueError(f"Backup path does not exist: {backup_path}")
        
        self.backup_path = backup_path
        self.monitoring_enabled = False
        logger.info(f"Initialized backup monitor for {backup_path}")
    
    def start_monitoring(self) -> None:
        """Start monitoring the backup directory."""
        self.monitoring_enabled = True
        logger.info("Started backup monitoring")
    
    def analyze_changes(
        self,
        changed_files: List[Path],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Analyze changed files for threats.
        
        Args:
            changed_files: List of files that have changed.
            context: Optional context for analysis.
            
        Returns:
            Dictionary containing analysis results.
        """
        results = {
            "threats_detected": 0,
            "files_analyzed": len(changed_files),
            "findings": []
        }
        
        # Analysis implementation here
        
        return results
```

## Testing Guidelines

### Writing Tests

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Coverage Target**: Aim for 80%+ code coverage

### Test Structure

```python
import pytest
from privaseeai_security.monitoring import BackupMonitor


class TestBackupMonitor:
    """Tests for BackupMonitor class."""
    
    @pytest.fixture
    def backup_monitor(self, tmp_path):
        """Create a BackupMonitor instance for testing."""
        return BackupMonitor(backup_path=tmp_path)
    
    def test_initialization(self, backup_monitor):
        """Test BackupMonitor initialization."""
        assert backup_monitor.monitoring_enabled is False
    
    def test_start_monitoring(self, backup_monitor):
        """Test starting the monitoring process."""
        backup_monitor.start_monitoring()
        assert backup_monitor.monitoring_enabled is True
    
    def test_invalid_path(self):
        """Test initialization with invalid path."""
        with pytest.raises(ValueError):
            BackupMonitor(backup_path=Path("/nonexistent/path"))
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=privaseeai_security --cov-report=html

# Run specific test file
pytest tests/test_monitoring.py

# Run with verbose output
pytest -v

# Run tests matching a pattern
pytest -k "test_backup"
```

## Submitting Changes

### Pull Request Process

1. **Ensure your code follows our standards**:
   ```bash
   black privaseeai_security/
   isort privaseeai_security/
   pylint privaseeai_security/
   pytest
   ```

2. **Update documentation** if needed:
   - Update README.md for new features
   - Add docstrings to new code
   - Update CHANGELOG.md

3. **Commit your changes** with a clear commit message

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request** on GitHub:
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe your changes in detail
   - Include screenshots for UI changes
   - List any breaking changes

### Pull Request Template

When you create a PR, include:

- **Description**: What does this PR do?
- **Motivation**: Why is this change needed?
- **Related Issues**: Fixes #123, Closes #456
- **Type of Change**: Bug fix, new feature, breaking change, etc.
- **Testing**: How was this tested?
- **Checklist**: 
  - [ ] Code follows style guidelines
  - [ ] Tests added/updated
  - [ ] Documentation updated
  - [ ] All tests passing
  - [ ] No new security vulnerabilities

## Review Process

### What to Expect

1. **Automated Checks**: CI/CD will run tests and linters
2. **Code Review**: Maintainers will review your code
3. **Feedback**: You may receive requests for changes
4. **Approval**: Once approved, your PR will be merged

### Review Criteria

Reviewers will check for:

- Code quality and style compliance
- Test coverage
- Documentation completeness
- Security considerations
- Performance implications
- Backward compatibility

### Responding to Feedback

- Be responsive to review comments
- Ask questions if feedback is unclear
- Make requested changes promptly
- Update your PR branch as needed

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General discussions and questions
- **Pull Requests**: Code contributions and reviews

### Getting Help

If you need help:

1. Check the [documentation](README.md)
2. Search [existing issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
3. Ask in [GitHub Discussions](https://github.com/aurelianware/PrivaseeAI.Security/discussions)
4. Contact maintainers (see [CODEOWNERS](.github/CODEOWNERS))

### Recognition

Contributors are recognized in:

- CHANGELOG.md for their contributions
- GitHub contributor graph
- Release notes for significant contributions

## Additional Resources

- [Technical Specification](privaseeAI_iOS_Threat_Detection_Spec.md)
- [Security Policy](SECURITY.md)
- [Roadmap](ROADMAP.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

By contributing to PrivaseeAI.Security, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

Thank you for contributing to PrivaseeAI.Security! Your efforts help make iOS security better for everyone.
