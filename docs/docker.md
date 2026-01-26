# Docker Support for PrivaseeAI.Security

This guide covers running PrivaseeAI.Security using Docker and Docker Compose for both development and production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building Images](#building-images)
- [Running Services](#running-services)
- [Managing Services](#managing-services)
- [Accessing Services](#accessing-services)
- [Database Management](#database-management)
- [Development Workflow](#development-workflow)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

- **Docker**: Version 20.10.0 or higher
  - [Install Docker on Linux](https://docs.docker.com/engine/install/)
  - [Install Docker Desktop on macOS](https://docs.docker.com/desktop/install/mac-install/)
  - [Install Docker Desktop on Windows](https://docs.docker.com/desktop/install/windows-install/)

- **Docker Compose**: Version 2.0.0 or higher (included with Docker Desktop)
  - Verify installation: `docker compose --version`

### System Requirements

- **RAM**: Minimum 4GB, recommended 8GB or more
- **Disk Space**: At least 5GB free space for images and volumes
- **CPU**: Multi-core processor recommended

## Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone the repository (if not already done)
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# 2. Copy the environment file and configure
cp .env.example .env
# Edit .env with your preferred settings (optional for development)

# 3. Build the Docker images
docker compose build

# 4. Start all services
docker compose up -d

# 5. Check service status
docker compose ps

# 6. View logs
docker compose logs -f
```

Your services should now be running:
- Application: http://localhost:8000
- TimescaleDB: localhost:5432
- Redis: localhost:6379

## Building Images

### Build All Services

```bash
# Build all services defined in docker compose.yml
docker compose build

# Build with no cache (clean build)
docker compose build --no-cache

# Build specific service only
docker compose build app
```

### Build Options

```bash
# Pull latest base images before building
docker compose build --pull

# Build in parallel (faster)
docker compose build --parallel

# Build with progress output
docker compose build --progress=plain
```

## Running Services

### Start All Services

```bash
# Start in detached mode (background)
docker compose up -d

# Start with logs visible
docker compose up

# Start specific services only
docker compose up -d timescaledb redis
```

### Start with pgAdmin (Optional)

```bash
# Start all services including pgAdmin
docker compose --profile admin up -d

# Access pgAdmin at http://localhost:5050
# Default credentials: admin@privaseeai.local / admin
```

### Service Dependencies

Services start in the correct order automatically:
1. TimescaleDB (with health check)
2. Redis (with health check)
3. Application (waits for database and Redis to be healthy)

## Managing Services

### Stop Services

```bash
# Stop all services (preserves data)
docker compose down

# Stop and remove volumes (deletes all data)
docker compose down -v

# Stop specific service
docker compose stop app
```

### Restart Services

```bash
# Restart all services
docker compose restart

# Restart specific service
docker compose restart app

# Restart with rebuild
docker compose up -d --build
```

### View Service Status

```bash
# List running containers
docker compose ps

# View detailed service info
docker compose ps -a

# View service logs
docker compose logs -f

# View logs for specific service
docker compose logs -f app
docker compose logs -f timescaledb
```

## Accessing Services

### Service URLs and Ports

| Service | URL | Default Port | Credentials |
|---------|-----|--------------|-------------|
| Application | http://localhost:8000 | 8000 | N/A |
| TimescaleDB | localhost:5432 | 5432 | See .env file |
| Redis | localhost:6379 | 6379 | See .env file |
| pgAdmin | http://localhost:5050 | 5050 | admin@privaseeai.local / admin |

### Connect to Database

```bash
# Using psql from host (requires psql installed)
psql -h localhost -p 5432 -U privaseeai -d privaseeai_security

# Using Docker exec
docker compose exec timescaledb psql -U privaseeai -d privaseeai_security

# Using pgAdmin (start with --profile admin)
# Navigate to http://localhost:5050
# Add server: Host=timescaledb, Port=5432
```

### Connect to Redis

```bash
# Using redis-cli from host (requires redis-cli installed)
redis-cli -h localhost -p 6379

# Using Docker exec
docker compose exec redis redis-cli

# Test connection
docker compose exec redis redis-cli ping
# Should return: PONG
```

### Shell Access

```bash
# Access application container shell
docker compose exec app /bin/bash

# Access as root (for debugging)
docker compose exec -u root app /bin/bash

# Access database container
docker compose exec timescaledb /bin/bash

# Access Redis container
docker compose exec redis /bin/sh
```

## Database Management

### Initialize Database

The database is automatically initialized on first startup using `scripts/init_db.sql`. This script:
- Enables TimescaleDB extension
- Creates necessary schemas and tables
- Sets up time-series hypertables
- Configures retention policies
- Creates indexes for performance

### Manual Database Operations

```bash
# Run SQL script
docker compose exec timescaledb psql -U privaseeai -d privaseeai_security -f /docker-entrypoint-initdb.d/init_db.sql

# Backup database
docker compose exec timescaledb pg_dump -U privaseeai privaseeai_security > backup.sql

# Restore database
cat backup.sql | docker compose exec -T timescaledb psql -U privaseeai -d privaseeai_security

# View database size
docker compose exec timescaledb psql -U privaseeai -d privaseeai_security -c "\l+"

# View table sizes
docker compose exec timescaledb psql -U privaseeai -d privaseeai_security -c "\dt+ security.*"
```

### Database Migrations

For future migrations:

```bash
# Run migrations inside container
docker compose exec app python -m alembic upgrade head

# Create new migration
docker compose exec app python -m alembic revision -m "description"
```

## Development Workflow

### Live Code Reloading

The docker compose.yml is configured for development with source code mounted as a volume:

```yaml
volumes:
  - ./src/privaseeai_security:/app/privaseeai_security
```

This means changes to your local code are immediately reflected in the container.

### Running Tests

**Note**: The production Docker image does not include development dependencies (pytest, linters, etc.) to keep the image size minimal and secure. For testing and development, use one of the following approaches:

**Option 1: Run tests on the host (recommended for development)**

```bash
# Install dev dependencies locally
pip install -r requirements-dev.txt

# Run tests locally
pytest

# Or use the Makefile
make test
make test-coverage
```

**Option 2: Create a development Dockerfile (for isolated testing)**

Create a `Dockerfile.dev` with dev dependencies:
```dockerfile
FROM privaseeaisecurity-app:latest
USER root
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
USER privasee
```

Then run tests:
```bash
# Build dev image
docker build -f Dockerfile.dev -t privaseeai-dev .

# Run tests in dev container
docker run --rm privaseeai-dev pytest
```

**Option 3: Use docker compose with volume mounts for development**

The current setup already mounts source code, so you can:
```bash
# Install dependencies in the running container (temporary)
docker compose exec app pip install pytest pytest-cov

# Run tests
docker compose exec app pytest
```

Note: Dependencies installed this way are lost when the container is recreated.

### Code Quality Checks

**Note**: Like testing tools, code quality tools (linters, formatters) are not included in the production image. Run these on the host:

```bash
# Install dev dependencies locally
pip install -r requirements-dev.txt

# Run linter
make lint

# Format code
make format

# Type checking
make type-check
```

Or install them temporarily in the container:
```bash
# Install dev tools (temporary)
docker compose exec app pip install flake8 black isort mypy

# Run checks
docker compose exec app flake8 privaseeai_security
docker compose exec app black --check privaseeai_security
```

### Debugging

```bash
# View application logs
docker compose logs -f app

# Follow all logs
docker compose logs -f

# View last 100 lines
docker compose logs --tail=100 app

# Enable debug mode in .env
# Set: LOG_LEVEL=DEBUG
docker compose restart app
```

### Interactive Python Shell

```bash
# Start Python REPL with application context
docker compose exec app python

# Start IPython shell (if installed)
docker compose exec app ipython

# Run Python script
docker compose exec app python -m privaseeai_security.module_name
```

## Production Deployment

### Production Configuration

1. **Update .env file for production:**

```bash
# Copy example and edit
cp .env.example .env.production

# Key settings to change:
APP_ENV=production
LOG_LEVEL=WARNING
DEBUG=false
RELOAD=false

# Use strong passwords
DATABASE_PASSWORD=<strong-random-password>
REDIS_PASSWORD=<strong-random-password>
PGADMIN_PASSWORD=<strong-random-password>
```

2. **Modify docker compose.yml for production:**

```yaml
# Comment out development volume mounts
# volumes:
#   - ./src/privaseeai_security:/app/privaseeai_security

# Add resource limits
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
    reservations:
      cpus: '1'
      memory: 1G
```

### Security Best Practices

1. **Use Docker Secrets** (for Docker Swarm):

```bash
# Create secrets
echo "mypassword" | docker secret create db_password -
echo "redispassword" | docker secret create redis_password -
```

2. **Network Security:**

```yaml
# Limit port exposure
# Only expose necessary ports
# Use reverse proxy (nginx/traefik) in front
```

3. **Run Security Scans:**

```bash
# Scan images for vulnerabilities
docker scan privaseeai-security-app

# Use Trivy
trivy image privaseeai-security-app
```

### Performance Optimization

```bash
# Use BuildKit for faster builds
DOCKER_BUILDKIT=1 docker compose build

# Multi-stage builds (already implemented in Dockerfile)
# Reduces final image size by ~60%

# Clean up unused resources
docker system prune -a --volumes
```

### Monitoring and Logging

```bash
# Configure log rotation
# Edit docker compose.yml to add logging config:

logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Backup Strategy

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker compose exec -T timescaledb pg_dump -U privaseeai privaseeai_security > "backup_${DATE}.sql"
gzip "backup_${DATE}.sql"

# Schedule with cron
# 0 2 * * * /path/to/backup.sh
```

## Troubleshooting

### Common Issues

#### Services Won't Start

```bash
# Check logs for errors
docker compose logs

# Check if ports are already in use
lsof -i :5432  # PostgreSQL
lsof -i :6379  # Redis
lsof -i :8000  # Application

# Remove containers and try again
docker compose down -v
docker compose up -d
```

#### Database Connection Errors

```bash
# Verify database is healthy
docker compose ps timescaledb

# Check database logs
docker compose logs timescaledb

# Test connection
docker compose exec timescaledb psql -U privaseeai -d privaseeai_security -c "SELECT 1;"

# Restart database
docker compose restart timescaledb
```

#### Redis Connection Issues

```bash
# Verify Redis is running
docker compose ps redis

# Test Redis connection
docker compose exec redis redis-cli ping

# Check if password is required
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping
```

#### Application Won't Start

```bash
# Check application logs
docker compose logs app

# Verify dependencies are healthy
docker compose ps

# Rebuild application image
docker compose build --no-cache app
docker compose up -d app
```

#### Out of Disk Space

```bash
# Check disk usage
docker system df

# Clean up unused resources
docker system prune -a --volumes

# Remove specific volumes
docker volume ls
docker volume rm <volume_name>
```

#### Permission Errors

```bash
# Check file ownership
ls -la src/privaseeai_security

# Fix ownership (on Linux)
sudo chown -R $USER:$USER src/

# Run as root for debugging
docker compose exec -u root app /bin/bash
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Increase resources in Docker Desktop settings
# Settings > Resources > Advanced
# Increase CPU and Memory allocation

# Check for container restarts
docker compose ps
# Look for "Restarting" status
```

### Health Check Failures

```bash
# Manually run health check command
docker compose exec app python -c "import sys; sys.exit(0)"

# Disable health check temporarily (debugging)
# Comment out healthcheck section in docker compose.yml

# Increase health check timeout
# Modify healthcheck in docker compose.yml
```

### Network Issues

```bash
# Inspect network
docker network inspect privaseeai_privaseeai-network

# Recreate network
docker compose down
docker network prune
docker compose up -d

# Test connectivity between containers
docker compose exec app ping timescaledb
docker compose exec app ping redis
```

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
2. Review Docker logs: `docker compose logs`
3. Check Docker daemon logs: `journalctl -u docker` (Linux)
4. Create a new issue with:
   - Error messages and logs
   - Docker and Docker Compose versions
   - Operating system
   - Steps to reproduce

## Useful Commands Reference

```bash
# Build and start
docker compose up -d --build

# View logs
docker compose logs -f [service]

# Execute command in container
docker compose exec [service] [command]

# Stop all services
docker compose down

# Remove all data
docker compose down -v

# Clean everything
docker compose down -v --remove-orphans
docker system prune -a --volumes

# Inspect service
docker compose exec [service] /bin/bash

# Check service health
docker compose ps

# Rebuild specific service
docker compose up -d --build [service]

# Scale service (if supported)
docker compose up -d --scale app=3
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [TimescaleDB Documentation](https://docs.timescale.com/)
- [Redis Documentation](https://redis.io/documentation)
- [Project README](../README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
