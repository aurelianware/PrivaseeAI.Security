.PHONY: help
help:
	@echo "PrivaseeAI Security - Available Make Targets"
	@echo "=============================================="
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-coverage     - Run tests with coverage report"
	@echo "  make test-watch        - Run tests in watch mode"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run code linters"
	@echo "  make format            - Format code with black and isort"
	@echo "  make type-check        - Run mypy type checking"
	@echo ""
	@echo "Setup:"
	@echo "  make install           - Install dependencies"
	@echo "  make install-dev       - Install development dependencies"
	@echo "  make clean             - Clean build artifacts"

.PHONY: install
install:
	pip install -r requirements.txt

.PHONY: install-dev
install-dev:
	pip install -r requirements-dev.txt

.PHONY: test
test:
	pytest

.PHONY: test-unit
test-unit:
	pytest tests/unit -v

.PHONY: test-integration
test-integration:
	pytest tests/integration -v

.PHONY: test-coverage
test-coverage:
	pytest --cov --cov-report=html --cov-report=term

.PHONY: test-watch
test-watch:
	pytest-watch

.PHONY: lint
lint:
	flake8 src tests
	black --check src tests
	isort --check-only src tests

.PHONY: format
format:
	black src tests
	isort src tests

.PHONY: type-check
type-check:
	mypy src

.PHONY: clean
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist .coverage htmlcov .pytest_cache .mypy_cache
