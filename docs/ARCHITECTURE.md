# Architecture Documentation

## Overview

PrivaseeAI.Security is a continuous iOS threat detection and monitoring system designed to provide real-time security analysis of iOS devices through backup monitoring, behavioral analysis, and threat intelligence integration.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PrivaseeAI.Security v0.1.0                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    CLI Interface Layer                   │   │
│  │  (click-based commands: monitor, scan, status, etc.)     │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────▼─────────────────────────────────┐   │
│  │                 Core Services Layer                       │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
│  │  │   Config   │  │   Logger   │  │ Exceptions │         │   │
│  │  │ Management │  │   System   │  │  Handling  │         │   │
│  │  └────────────┘  └────────────┘  └────────────┘         │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────▼─────────────────────────────────┐   │
│  │              iOS Monitoring Components                    │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
│  │  │  Backup    │  │  Backup    │  │  Device    │         │   │
│  │  │  Monitor   │  │  Parser    │  │    Info    │         │   │
│  │  └────────────┘  └────────────┘  └────────────┘         │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────▼─────────────────────────────────┐   │
│  │                  Utility Services                         │   │
│  │  ┌────────────┐  ┌────────────┐                          │   │
│  │  │   File     │  │   Crypto   │                          │   │
│  │  │  Watcher   │  │  Manager   │                          │   │
│  │  └────────────┘  └────────────┘                          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

         ▼                           ▼                    ▼
┌─────────────────┐        ┌──────────────────┐  ┌──────────────┐
│   PostgreSQL    │        │      Redis       │  │ File System  │
│  (TimescaleDB)  │        │   (Caching &     │  │ (iOS Backups)│
│  Time-series DB │        │  Event Streaming)│  │              │
└─────────────────┘        └──────────────────┘  └──────────────┘
```

## Component Details

### 1. CLI Interface Layer (`cli/`)

**Purpose**: Provides command-line interface for user interaction.

**Components**:
- `main.py`: Entry point with Click-based commands

**Key Commands**:
- `monitor`: Continuous monitoring of backup directories
- `scan`: One-time backup analysis
- `device-info`: Extract device information
- `status`: System status check
- `init`: Initialize configuration
- `list-backups`: Find and list backup directories

### 2. Core Services Layer (`core/`)

**Purpose**: Foundational services used across the application.

#### Configuration Management (`config.py`)
- **Technology**: Pydantic Settings
- **Features**:
  - Environment-based configuration
  - Type validation
  - Nested settings for different services
  - Support for multiple environments (dev, staging, prod)

**Configuration Sections**:
- Database (PostgreSQL/TimescaleDB)
- Redis
- iOS Backup paths and settings
- Security (encryption keys, JWT)
- Monitoring intervals
- Logging configuration

#### Logging System (`logger.py`)
- **Features**:
  - Structured logging (JSON/Text formats)
  - Multiple log levels
  - File rotation
  - Correlation ID support
  - Console and file handlers

#### Exception Handling (`exceptions.py`)
- Custom exception hierarchy
- Domain-specific exceptions
- Clear error messages

### 3. iOS Monitoring Components (`ios/`)

**Purpose**: Core iOS backup analysis and monitoring functionality.

#### Backup Monitor (`backup_monitor.py`)
- **Features**:
  - Real-time file system monitoring
  - Change detection (new, modified files)
  - Basic threat pattern matching
  - Device info extraction
  - One-time scanning capability

**Monitoring Flow**:
```
1. Initialize FileWatcher on backup directory
2. Load device information from Info.plist
3. Watch for file changes (.db, .plist, .sqlite)
4. On file change:
   a. Log event
   b. Analyze file (basic checks)
   c. Call custom callbacks
   d. Check for suspicious patterns
```

#### Backup Parser (`backup_parser.py`)
- **Features**:
  - Parse Manifest.db (SQLite)
  - Parse Info.plist and Manifest.plist
  - Extract file listings
  - Identify installed applications
  - Check encryption status

**Database Schema Knowledge**:
- `Files` table: fileID, domain, relativePath, flags, file

#### Device Info (`device_info.py`)
- **Features**:
  - Extract device metadata from Info.plist
  - Parse device model, iOS version
  - Get serial number, UDID
  - Find backup directories

### 4. Utility Services (`utils/`)

#### File Watcher (`file_watcher.py`)
- **Technology**: watchdog library
- **Features**:
  - Directory monitoring
  - File pattern filtering
  - Event debouncing
  - Recursive watching
  - Context manager support

**Event Types**:
- Created: New file added
- Modified: Existing file changed
- Deleted: File removed

#### Crypto Manager (`crypto.py`)
- **Technology**: cryptography (Fernet)
- **Features**:
  - Symmetric encryption
  - Key generation
  - String hashing (SHA-256)
  - Secure random generation

## Data Flow

### Monitoring Flow

```
User Command (privaseeai monitor /path) 
    ↓
CLI validates path and initializes BackupMonitor
    ↓
BackupMonitor loads device info from Info.plist
    ↓
FileWatcher starts monitoring directory
    ↓
On file change detected:
    ↓
Event debounced and filtered by pattern
    ↓
BackupMonitor._analyze_file() performs basic checks
    ↓
Logs generated (structured JSON/text)
    ↓
Custom callbacks executed (if provided)
```

### Scan Flow

```
User Command (privaseeai scan /path)
    ↓
BackupMonitor initialized
    ↓
Device info extracted → DeviceInfo object
    ↓
BackupParser analyzes Manifest.db
    ↓
Results collected:
  - Device metadata
  - Encryption status
  - File count
  - Installed apps
    ↓
Results output to console or JSON file
```

## Technology Stack

### Core Dependencies
- **Python 3.11+**: Runtime environment
- **Pydantic 2.x**: Configuration and validation
- **Click 8.x**: CLI framework
- **watchdog 3.x**: File system monitoring
- **cryptography 41.x**: Encryption

### Database & Caching
- **PostgreSQL 14+**: Relational database
- **TimescaleDB**: Time-series extension
- **Redis 5+**: Caching and event streaming
- **SQLAlchemy 2.x**: ORM

### Development
- **pytest**: Testing framework
- **black**: Code formatting
- **ruff**: Fast linting
- **mypy**: Type checking
- **pre-commit**: Git hooks

## Design Patterns

### 1. Dependency Injection
Configuration and services passed as dependencies rather than global imports.

### 2. Context Managers
FileWatcher and BackupMonitor support `with` statements for automatic cleanup.

### 3. Observer Pattern
FileWatcher implements observer pattern for file system events.

### 4. Factory Pattern
CryptoManager.generate_key() for creating encryption keys.

## Security Considerations

### v0.1.0 Security Features
1. **Encryption at Rest**: CryptoManager for sensitive data
2. **Configuration Security**: No hardcoded secrets, env-based config
3. **Input Validation**: Path validation, type checking
4. **Logging**: Security event logging with correlation IDs

### Future Security Enhancements
- STIX/TAXII threat intelligence integration
- Advanced behavioral analysis
- Network traffic monitoring
- AI-powered threat detection

## Scalability Considerations

### Current Design (v0.1.0)
- Single device monitoring
- Local file system only
- Synchronous operations

### Future Scalability
- Multi-device monitoring
- Distributed processing (Celery)
- Asynchronous I/O
- Horizontal scaling with load balancers

## Database Schema

### TimescaleDB Tables (Future)

**device_info**
- id (PK)
- udid (unique)
- device_name
- model
- ios_version
- serial_number
- created_at
- updated_at

**backup_events** (Hypertable)
- timestamp (time)
- device_id (FK)
- event_type
- file_path
- file_hash
- metadata (JSONB)

**threat_indicators**
- id (PK)
- indicator_type
- pattern
- severity
- stix_data (JSONB)
- created_at

## API Design (Future)

### REST API Endpoints (Planned)
```
GET    /api/v1/devices
GET    /api/v1/devices/{id}
POST   /api/v1/devices/{id}/scan
GET    /api/v1/threats
GET    /api/v1/monitoring/status
POST   /api/v1/monitoring/start
POST   /api/v1/monitoring/stop
```

## Deployment Architecture

### Docker Deployment
```yaml
services:
  - postgres (TimescaleDB)
  - redis
  - privaseeai (application)

volumes:
  - postgres_data
  - redis_data
  - backup_data (mounted read-only)

networks:
  - privaseeai_network (bridge)
```

### Production Considerations
- Use secrets management (e.g., HashiCorp Vault)
- Implement log aggregation (e.g., ELK stack)
- Add monitoring (Prometheus, Grafana)
- Use reverse proxy (nginx)
- Implement rate limiting
- Add SSL/TLS termination

## File System Layout

### iOS Backup Structure
```
<backup_directory>/
├── Info.plist                 # Device metadata
├── Manifest.plist             # Backup metadata
├── Manifest.db               # File catalog (SQLite)
├── Manifest.mbdb             # Legacy format
└── <hashed_files>/           # Backup files
    ├── 00/
    ├── 01/
    └── ...
```

### Application Data Directory
```
/var/lib/privaseeai/
├── backups/                   # iOS backup storage
├── cache/                     # Temporary cache
└── data/                      # Application data
```

### Log Directory
```
/var/log/privaseeai/
├── security.log              # Main application log
├── security.log.1            # Rotated logs
└── ...
```

## Performance Characteristics

### v0.1.0 Performance
- **File Watching**: Near real-time (< 5s debounce)
- **Manifest Parsing**: < 1s for typical backups
- **Device Info Extraction**: < 100ms
- **Memory**: ~50-100 MB base usage

### Optimization Opportunities
- Implement file indexing
- Cache parsed manifests
- Batch database operations
- Use connection pooling

## Error Handling Strategy

### Exception Hierarchy
```
PrivaseeAIError (base)
├── ConfigurationError
├── DatabaseError
├── BackupParseError
├── DeviceNotFoundError
├── EncryptionError
├── MonitoringError
└── ValidationError
```

### Error Handling Principles
1. Fail fast for configuration errors
2. Log and continue for monitoring errors
3. Provide clear error messages
4. Include context in exceptions

## Testing Strategy

### Test Organization
```
tests/
├── unit/              # Unit tests (isolated)
├── integration/       # Integration tests
└── fixtures/          # Shared test fixtures
```

### Coverage Goals
- Overall: >80%
- Core modules: >90%
- Utilities: >85%
- CLI: >70%

## Future Enhancements

### Planned for v0.2.0
- FastAPI REST API
- Web dashboard (React/Vue)
- Multi-device support
- Advanced threat detection
- STIX/TAXII integration

### Planned for v0.3.0
- Network traffic monitoring
- AI/ML behavioral analysis
- Automated response actions
- Physical security integration

## References

- [Technical Specification](../privaseeAI_iOS_Threat_Detection_Spec.md)
- [README](../README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
