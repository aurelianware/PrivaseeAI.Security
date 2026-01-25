# Installation Guide

## System Requirements

### Operating System
- **Linux**: Ubuntu 20.04+, Debian 11+, RHEL 8+, or compatible
- **macOS**: 12.0 (Monterey) or later
- **Windows**: Windows 10/11 with WSL2 (for development)

### Software Requirements
- **Python**: 3.11 or higher
- **PostgreSQL**: 14+ with TimescaleDB extension
- **Redis**: 6.0 or higher
- **Git**: For cloning the repository

### Hardware Requirements (Minimum)
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Storage**: 10 GB free space (plus space for backups)

### Hardware Requirements (Recommended)
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Storage**: 50+ GB SSD

## Installation Methods

### Method 1: Installation from Source (Recommended for Development)

#### 1. Clone the Repository

```bash
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security
```

#### 2. Create Virtual Environment

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows (WSL):
source venv/bin/activate
```

#### 3. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt

# Install package in development mode
pip install -e .
```

#### 4. Set Up Configuration

```bash
# Copy example configuration
cp .env.example .env

# Edit configuration file
nano .env  # or use your preferred editor
```

Required configuration values:
- `DATABASE_PASSWORD`: Set a secure password
- `ENCRYPTION_KEY`: Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
- `IOS_BACKUP_PATH`: Set to your iOS backup directory

#### 5. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    postgresql-14 \
    postgresql-14-timescaledb \
    redis-server \
    build-essential \
    libpq-dev
```

**macOS (using Homebrew):**
```bash
brew install postgresql@15 redis
brew tap timescale/tap
brew install timescaledb
```

#### 6. Set Up Database

```bash
# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql@15  # macOS

# Create database and user
sudo -u postgres psql << EOF
CREATE USER privaseeai WITH PASSWORD 'your_password';
CREATE DATABASE privaseeai_security OWNER privaseeai;
\c privaseeai_security
CREATE EXTENSION IF NOT EXISTS timescaledb;
EOF
```

#### 7. Start Redis

```bash
# Linux
sudo systemctl start redis

# macOS
brew services start redis
```

#### 8. Verify Installation

```bash
# Check application status
privaseeai status

# Should display:
# PrivaseeAI.Security Status
# Version: 0.1.0
# Environment: development
# ...
```

### Method 2: Docker Installation (Recommended for Production)

#### 1. Prerequisites

Install Docker and Docker Compose:
- Docker: https://docs.docker.com/get-docker/
- Docker Compose: https://docs.docker.com/compose/install/

#### 2. Clone Repository

```bash
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security
```

#### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
nano .env
```

#### 4. Build and Start Services

```bash
# Build Docker images
docker-compose build

# Start services
docker-compose up -d

# Check status
docker-compose ps
```

#### 5. Verify Installation

```bash
# Check application logs
docker-compose logs privaseeai

# Run status command
docker-compose exec privaseeai privaseeai status
```

### Method 3: Using Make (Automated Setup)

```bash
# Clone repository
git clone https://github.com/aurelianware/PrivaseeAI.Security.git
cd PrivaseeAI.Security

# Install dependencies
make install-dev

# Set up configuration
make init  # This will copy .env.example to .env

# Edit .env file
nano .env

# Run tests
make test

# Check status
privaseeai status
```

## Post-Installation Setup

### 1. Configure iOS Backup Path

Set up the directory where iOS backups are stored:

```bash
# Create backup directory
sudo mkdir -p /var/lib/privaseeai/backups
sudo chown $USER:$USER /var/lib/privaseeai/backups

# Update .env file
IOS_BACKUP_PATH=/var/lib/privaseeai/backups
```

**Finding iOS Backups:**

- **macOS**: `~/Library/Application Support/MobileSync/Backup/`
- **Windows**: `%APPDATA%\Apple Computer\MobileSync\Backup\`
- **Linux** (with libimobiledevice): Custom location

### 2. Set Up Pre-commit Hooks (Development)

```bash
pre-commit install
```

### 3. Initialize Database Schema (Future Feature)

```bash
# Will be available in future versions
# privaseeai db init
# privaseeai db migrate
```

## Configuration

### Environment Variables

See [.env.example](.env.example) for all available configuration options.

**Key Configuration Sections:**

1. **Application Settings**
   - `APP_ENV`: development, staging, or production
   - `DEBUG`: Enable debug mode
   - `LOG_LEVEL`: Logging verbosity

2. **Database Settings**
   - `DATABASE_HOST`: PostgreSQL host
   - `DATABASE_PORT`: PostgreSQL port
   - `DATABASE_NAME`: Database name
   - `DATABASE_USER`: Database user
   - `DATABASE_PASSWORD`: Database password

3. **Redis Settings**
   - `REDIS_HOST`: Redis host
   - `REDIS_PORT`: Redis port
   - `REDIS_PASSWORD`: Redis password (if set)

4. **iOS Backup Settings**
   - `IOS_BACKUP_PATH`: Path to iOS backups
   - `IOS_MONITOR_INTERVAL`: Monitoring interval (seconds)

5. **Security Settings**
   - `ENCRYPTION_KEY`: Fernet encryption key
   - `SECRET_KEY`: Application secret key

### Logging Configuration

Logs are written to:
- **Console**: stdout (configurable format)
- **File**: `/var/log/privaseeai/security.log` (with rotation)

Configure in `.env`:
```bash
LOG_LEVEL=INFO
LOG_FORMAT=json  # or 'text' for development
LOG_FILE_PATH=/var/log/privaseeai/security.log
```

## Basic Usage

### Monitor a Backup Directory

```bash
# Start continuous monitoring
privaseeai monitor /path/to/backup

# With custom interval
privaseeai monitor /path/to/backup --interval 30
```

### Perform One-Time Scan

```bash
# Scan a backup
privaseeai scan /path/to/backup

# Save results to JSON
privaseeai scan /path/to/backup --output results.json
```

### View Device Information

```bash
# Display device info
privaseeai device-info /path/to/backup

# Output as JSON
privaseeai device-info /path/to/backup --json
```

### List Available Backups

```bash
# List all backups in a directory
privaseeai list-backups /path/to/backups/root
```

## Development Setup

### 1. Install Development Dependencies

```bash
make install-dev
```

### 2. Run Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test
pytest tests/unit/test_config.py
```

### 3. Code Quality

```bash
# Format code
make format

# Lint code
make lint

# Type check
make type-check
```

### 4. Build Package

```bash
make build
```

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Problem**: `ModuleNotFoundError: No module named 'privaseeai_security'`

**Solution**:
```bash
pip install -e .
```

#### 2. Database Connection Error

**Problem**: Cannot connect to PostgreSQL

**Solution**:
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Check connection settings in .env
# Verify DATABASE_HOST, DATABASE_PORT, DATABASE_USER, DATABASE_PASSWORD
```

#### 3. Permission Errors

**Problem**: Permission denied accessing backup directory

**Solution**:
```bash
# Fix permissions
sudo chown -R $USER:$USER /path/to/backup

# Or run with appropriate permissions
sudo privaseeai monitor /path/to/backup
```

#### 4. Redis Connection Error

**Problem**: Cannot connect to Redis

**Solution**:
```bash
# Check Redis is running
sudo systemctl status redis

# Test connection
redis-cli ping
# Should return: PONG
```

#### 5. Missing Info.plist

**Problem**: `BackupParseError: Info.plist not found`

**Solution**:
- Verify the path points to a valid iOS backup directory
- Check that the backup is not encrypted and inaccessible
- Ensure the backup was created successfully

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/aurelianware/PrivaseeAI.Security/issues)
2. Review the [Architecture Documentation](ARCHITECTURE.md)
3. Join [GitHub Discussions](https://github.com/aurelianware/PrivaseeAI.Security/discussions)
4. Read the [Contributing Guide](../CONTRIBUTING.md)

## Uninstallation

### Remove Virtual Environment Installation

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf venv

# Remove installed package
pip uninstall privaseeai-security
```

### Remove Docker Installation

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (warning: deletes data)
docker-compose down -v

# Remove images
docker rmi privaseeai-security:latest
```

### Remove System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get remove postgresql-14 redis-server
sudo apt-get autoremove
```

**macOS:**
```bash
brew uninstall postgresql@15 redis timescaledb
```

## Next Steps

After installation:

1. Read the [Architecture Documentation](ARCHITECTURE.md)
2. Review the [Technical Specification](../privaseeAI_iOS_Threat_Detection_Spec.md)
3. Check the [ROADMAP](../ROADMAP.md) for upcoming features
4. See [CONTRIBUTING](../CONTRIBUTING.md) to contribute

## Updates and Upgrades

### Updating from Source

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Reinstall package
pip install -e .
```

### Updating Docker Installation

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d
```

## Security Considerations

1. **Secure Passwords**: Use strong, unique passwords for database
2. **Encryption Keys**: Generate and securely store encryption keys
3. **File Permissions**: Restrict access to configuration files
4. **Network Security**: Use firewall rules to limit database/Redis access
5. **Updates**: Keep system and dependencies up to date

```bash
# Restrict .env permissions
chmod 600 .env

# Restrict log directory
sudo chmod 750 /var/log/privaseeai
```
