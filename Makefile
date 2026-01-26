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
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build      - Build Docker images"
	@echo "  make docker-up         - Start Docker services"
	@echo "  make docker-down       - Stop Docker services"
	@echo "  make docker-logs       - View Docker logs"
	@echo "  make docker-shell      - Open shell in app container"
	@echo "  make docker-test       - Run tests in Docker"
	@echo "  make docker-clean      - Clean Docker resources"

.PHONY: install
install:
	pip install -r requirements.txt

.PHONY: install-dev
install-dev:
	pip install -r requirements-dev.txt

.PHONY: setup-venv
setup-venv:
	@echo "Creating virtualenv in .venv and installing dev dependencies"
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip
	. .venv/bin/activate && python -m pip install -r requirements-dev.txt


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

# =====================================
# Docker Targets
# =====================================

.PHONY: docker-build
docker-build:
	docker compose build

.PHONY: docker-up
docker-up:
	docker compose up -d

.PHONY: docker-down
docker-down:
	docker compose down

.PHONY: docker-logs
docker-logs:
	docker compose logs -f

.PHONY: docker-shell
docker-shell:
	docker compose exec app /bin/bash

.PHONY: docker-test
docker-test:
	@echo "Tests should be run on the host machine (production image excludes tests):"
	@echo "  make test              - Run all tests"
	@echo "  make test-coverage     - Run tests with coverage"

.PHONY: docker-clean
docker-clean:
	docker compose down -v --remove-orphans
	docker system prune -f
