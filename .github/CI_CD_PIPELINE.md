# CI/CD Pipeline Documentation

## Overview

This repository uses GitHub Actions for continuous integration and continuous deployment. The pipeline automatically runs tests, performs code quality checks, and publishes metrics for every push and pull request.

## Workflows

### Test Suite Workflow (`.github/workflows/test.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual workflow dispatch

**Features:**
- **Multi-Python Version Testing**: Tests are run on Python 3.11 and 3.12 to ensure compatibility
- **Code Coverage**: Generates comprehensive coverage reports using pytest-cov
- **Test Result Publishing**: Publishes test results directly in GitHub PRs
- **Artifact Upload**: Stores coverage HTML reports and test results for 30 days
- **Codecov Integration**: Automatically uploads coverage to Codecov (requires CODECOV_TOKEN secret)
- **PR Comments**: Automatically comments coverage metrics on pull requests

**Published Metrics:**
1. **Test Results**: Pass/fail status for all tests
2. **Code Coverage**: Line coverage percentage and detailed HTML reports
3. **Test Artifacts**: Downloadable coverage reports and test results

### Code Quality Workflow (`.github/workflows/code-quality.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

**Checks:**
1. **flake8**: Python linting and style checking
2. **black**: Code formatting verification
3. **isort**: Import sorting verification
4. **mypy**: Static type checking

## Viewing Test Results and Metrics

### In Pull Requests

1. **Status Checks**: All workflow runs appear as status checks in PRs
2. **Test Results**: Detailed test results are published as PR status checks (not comments)
3. **Coverage Comment**: Coverage metrics are automatically commented on PRs (Python 3.11 only)

### In GitHub Actions Tab

1. Navigate to the **Actions** tab in the repository
2. Select the workflow run you want to inspect
3. View:
   - Overall workflow status
   - Individual job results
   - Test summaries
   - Code coverage metrics

### Downloading Artifacts

1. Go to the workflow run in the Actions tab
2. Scroll to the **Artifacts** section
3. Download:
   - `coverage-report-{python-version}`: HTML coverage report
   - `test-results-{python-version}`: JUnit XML test results

## Local Testing

Before pushing code, you can run the same tests locally:

```bash
# Run all tests with coverage
make test-coverage

# Run linters
make lint

# Run type checking
make type-check

# Format code
make format
```

## Setting Up Codecov (Optional)

To enable Codecov integration:

1. Sign up at [codecov.io](https://codecov.io)
2. Add your repository to Codecov
3. Get your Codecov token
4. Add it as a GitHub secret named `CODECOV_TOKEN`:
   - Go to repository Settings > Secrets and variables > Actions
   - Click "New repository secret"
   - Name: `CODECOV_TOKEN`
   - Value: Your Codecov token

## Coverage Thresholds

The PR coverage comment action uses these thresholds:
- **Green**: ≥80% coverage
- **Orange**: 60-79% coverage
- **Red**: <60% coverage

## Test Organization

Tests are organized in the `tests/` directory:
- `tests/unit/`: Unit tests for individual components
- `tests/integration/`: Integration tests for system interactions
- `tests/fixtures/`: Test fixtures and sample data

## Continuous Improvement

The CI/CD pipeline helps maintain code quality by:
- Preventing merges that break tests
- Ensuring code follows style guidelines
- Tracking coverage trends over time
- Providing immediate feedback on PRs

## Troubleshooting

### Workflow Fails on Dependencies

If the workflow fails during dependency installation:
1. Check that `requirements.txt` and `requirements-dev.txt` are up to date
2. Verify Python version compatibility
3. Check for platform-specific dependencies

### Tests Pass Locally but Fail in CI

Common causes:
- Environment variable differences
- Missing test fixtures or data files
- Platform-specific behavior (local vs. Linux)
- Dependency version mismatches

### Coverage Report Not Generated

Ensure:
- pytest-cov is installed
- Coverage configuration in `pyproject.toml` is correct
- Tests are being discovered and run
