# PrivaseeAI.Security Database Layer

Async SQLAlchemy + asyncpg model layer for threat persistence using PostgreSQL with TimescaleDB.

## Features

- **Async-first design** using SQLAlchemy 2.0 with asyncpg driver
- **TimescaleDB hypertables** for efficient time-series threat event storage
- **Repository pattern** for clean separation of data access logic
- **Fingerprint-based deduplication** to prevent duplicate threat alerts
- **Automatic partitioning** on timestamp with daily chunks
- **Production-ready** with connection pooling, migrations, and comprehensive examples

## Architecture

### Models

- **Device**: Represents monitored iOS devices with metadata and baseline tracking
- **ThreatEvent**: Security threat detections stored as TimescaleDB hypertable

### Repositories

- **DeviceRepository**: CRUD operations for device management
- **ThreatEventRepository**: Async CRUD with upsert logic for threat deduplication

### Query Utilities

Pre-built queries for common threat analysis patterns:
- Threats grouped by severity over time windows
- Top threat types
- Device-specific threat summaries
- Trending threats
- Unacknowledged critical threats

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `sqlalchemy>=2.0.23`
- `asyncpg>=0.29.0`
- `alembic>=1.13.0`

### 2. Configure Database

Set the database URL via environment variable:

```bash
export DATABASE_URL="postgresql+asyncpg://user:password@localhost:5432/privasee_security"
```

Or use the default: `postgresql+asyncpg://privasee:privasee@localhost:5432/privasee_security`

### 3. Run Migrations

Initialize the database schema with alembic:

```bash
# Run migrations
alembic upgrade head

# Verify migration
alembic current
```

### 4. Use the Database Layer

```python
import asyncio
from src.privaseeai_security.database import (
    DeviceRepository,
    ThreatEventRepository,
    ThreatEvent,
    get_async_session,
)

async def main():
    # Get an async session
    async for session in get_async_session():
        # Create repositories
        device_repo = DeviceRepository(session)
        threat_repo = ThreatEventRepository(session)
        
        # Create a device
        device = await device_repo.create(
            name="iPhone 15 Pro",
            udid="unique-device-id-12345",
            baseline_hash="abc123def456"
        )
        
        # Create a threat event with deduplication
        fingerprint = ThreatEvent.generate_fingerprint(
            device_id=device.id,
            threat_type="VPN_MANIPULATION",
            key_indicators="tcp_fallback:protonvpn:us-ny-01"
        )
        
        threat = await threat_repo.create_or_update(
            device_id=device.id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="VPN forced to TCP fallback",
            evidence_jsonb={
                "vpn_provider": "ProtonVPN",
                "server": "us-ny-01",
                "protocol_before": "UDP",
                "protocol_after": "TCP"
            },
            fingerprint=fingerprint
        )
        
        print(f"Created threat: {threat.threat_type} (ID: {threat.id})")
        break

if __name__ == "__main__":
    asyncio.run(main())
```

## Example: Threats Last 7 Days Grouped by Severity

```python
from src.privaseeai_security.database import (
    get_async_session,
    get_threats_last_n_days_grouped_by_severity,
)

async def analyze_threats():
    async for session in get_async_session():
        # Get threat counts by severity for last 7 days
        severity_counts = await get_threats_last_n_days_grouped_by_severity(
            session, days=7
        )
        
        print("Threat counts by severity (last 7 days):")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        break

asyncio.run(analyze_threats())
```

Output:
```
Threat counts by severity (last 7 days):
  CRITICAL: 5
  HIGH: 12
  MEDIUM: 8
  LOW: 3
```

## Repository Pattern

### DeviceRepository

```python
from src.privaseeai_security.database import DeviceRepository

async for session in get_async_session():
    repo = DeviceRepository(session)
    
    # Create
    device = await repo.create(name="iPhone", udid="12345")
    
    # Read
    device = await repo.get_by_id(device_id)
    device = await repo.get_by_udid("12345")
    devices = await repo.list_all(limit=10, offset=0)
    
    # Update
    await repo.update_last_seen(device_id)
    await repo.update_baseline(device_id, "new-hash")
    
    # Delete
    await repo.delete(device_id)
    
    break
```

### ThreatEventRepository

```python
from src.privaseeai_security.database import ThreatEventRepository, ThreatEvent

async for session in get_async_session():
    repo = ThreatEventRepository(session)
    
    # Create or update (upsert with deduplication)
    fingerprint = ThreatEvent.generate_fingerprint(
        device_id, "VPN_MANIPULATION", "key-indicators"
    )
    threat = await repo.create_or_update(
        device_id=device_id,
        severity="CRITICAL",
        threat_type="VPN_MANIPULATION",
        description="VPN issue detected",
        evidence_jsonb={"details": "..."},
        fingerprint=fingerprint
    )
    
    # Read
    threat = await repo.get_by_id(threat_id)
    threat = await repo.get_by_fingerprint(fingerprint)
    threats = await repo.list_by_device(device_id, unresolved_only=True)
    recent = await repo.list_recent(days=7, severity="CRITICAL")
    
    # Analysis queries
    severity_counts = await repo.get_threats_last_n_days_grouped_by_severity(days=7)
    
    # Update
    await repo.acknowledge(threat_id)
    await repo.resolve(threat_id)
    
    # Delete
    await repo.delete(threat_id)
    
    break
```

## Database Schema

### devices table

| Column        | Type         | Description                          |
|---------------|--------------|--------------------------------------|
| id            | UUID         | Primary key                          |
| name          | VARCHAR(255) | Human-readable device name           |
| udid          | VARCHAR(255) | Unique device identifier (indexed)   |
| last_seen     | TIMESTAMP    | Last activity timestamp              |
| baseline_hash | VARCHAR(64)  | Baseline fingerprint for comparison  |
| metadata      | JSONB        | Additional device metadata           |
| created_at    | TIMESTAMP    | Creation timestamp                   |
| updated_at    | TIMESTAMP    | Last update timestamp (auto-updated) |

### threat_events table (TimescaleDB Hypertable)

| Column           | Type         | Description                               |
|------------------|--------------|-------------------------------------------|
| id               | UUID         | Primary key                               |
| timestamp        | TIMESTAMP    | When threat was detected (partitioning key)|
| device_id        | UUID         | Foreign key to devices (cascading delete) |
| severity         | VARCHAR(20)  | CRITICAL, HIGH, MEDIUM, LOW (indexed)     |
| threat_type      | VARCHAR(100) | Type of threat (indexed)                  |
| description      | TEXT         | Human-readable description                |
| evidence_jsonb   | JSONB        | Supporting evidence as JSON               |
| fingerprint      | VARCHAR(64)  | SHA256 hash for deduplication (unique)    |
| occurrence_count | INTEGER      | Number of times this threat occurred      |
| first_seen       | TIMESTAMP    | First occurrence timestamp                |
| last_seen        | TIMESTAMP    | Most recent occurrence                    |
| acknowledged     | BOOLEAN      | Whether threat has been acknowledged      |
| resolved         | BOOLEAN      | Whether threat has been resolved          |

**Partitioning**: Daily chunks on `timestamp` column via TimescaleDB hypertable

## Migrations

### Create a New Migration

```bash
# Auto-generate migration from model changes
alembic revision --autogenerate -m "Add new column to devices"

# Create empty migration
alembic revision -m "Custom migration"
```

### Apply Migrations

```bash
# Upgrade to latest
alembic upgrade head

# Upgrade one step
alembic upgrade +1

# Downgrade one step
alembic downgrade -1

# Show current version
alembic current

# Show migration history
alembic history
```

## TimescaleDB Configuration

The initial migration creates the hypertable automatically. For additional TimescaleDB features:

### Retention Policy

```sql
-- Automatically drop data older than 90 days
SELECT add_retention_policy('threat_events', INTERVAL '90 days');
```

### Compression

```sql
-- Enable compression for chunks older than 7 days
ALTER TABLE threat_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id,severity'
);

SELECT add_compression_policy('threat_events', INTERVAL '7 days');
```

### Continuous Aggregates

```sql
-- Pre-compute hourly threat statistics
CREATE MATERIALIZED VIEW threat_hourly_stats
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS hour,
    device_id,
    severity,
    COUNT(*) as threat_count
FROM threat_events
GROUP BY hour, device_id, severity;
```

## Testing

Run unit tests:

```bash
# All tests
pytest tests/unit/test_database.py -v

# Specific test
pytest tests/unit/test_database.py::TestThreatEventModel::test_fingerprint_generation -v
```

Run integration tests (requires test database):

```bash
# Set test database URL
export DATABASE_URL="postgresql+asyncpg://test:test@localhost:5432/test_db"

# Run integration tests
pytest tests/unit/test_database.py -m integration -v
```

## Examples

See `examples/database_usage_example.py` for a complete working example demonstrating:

1. Database initialization
2. Device management
3. Threat event creation with deduplication
4. Example queries including "threats last 7 days grouped by severity"
5. Repository pattern usage

Run the example:

```bash
python examples/database_usage_example.py
```

## Environment Variables

| Variable       | Description                          | Default                                                      |
|----------------|--------------------------------------|--------------------------------------------------------------|
| DATABASE_URL   | PostgreSQL connection URL            | postgresql+asyncpg://privasee:privasee@localhost:5432/privasee_security |

## Connection Pooling

The async engine uses connection pooling for optimal performance:

- **pool_size**: 20 connections
- **max_overflow**: 10 additional connections
- **pool_recycle**: 3600 seconds (1 hour)
- **pool_pre_ping**: Enabled (verifies connections before use)

## Best Practices

1. **Use fingerprints for deduplication**: Always generate fingerprints using `ThreatEvent.generate_fingerprint()` to ensure consistent hashing
2. **Leverage upsert**: Use `create_or_update()` instead of separate create/update logic
3. **Use repositories**: Don't bypass the repository layer - it provides consistent error handling and business logic
4. **Close sessions properly**: Always use `async for session in get_async_session()` to ensure proper cleanup
5. **Run migrations in production**: Never use `init_db()` in production - use alembic migrations
6. **Monitor connection pool**: Watch for pool exhaustion in high-traffic scenarios

## Troubleshooting

### Connection Issues

```python
# Test database connection
from src.privaseeai_security.database.engine import get_engine

engine = get_engine()
async with engine.connect() as conn:
    result = await conn.execute(text("SELECT 1"))
    print("Database connection successful!")
```

### Migration Issues

```bash
# Show pending migrations
alembic upgrade head --sql

# Force mark migration as complete (dangerous!)
alembic stamp head
```

### TimescaleDB Extension Not Found

```sql
-- Install TimescaleDB extension manually
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
```

## Contributing

When adding new features to the database layer:

1. Update models in `models.py`
2. Create alembic migration with `alembic revision --autogenerate`
3. Add repository methods if needed in `repositories.py`
4. Add query utilities if applicable in `queries.py`
5. Write tests in `tests/unit/test_database.py`
6. Update this README

## License

Apache-2.0
