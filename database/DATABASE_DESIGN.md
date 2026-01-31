# Database Design Documentation

## Phase 4: PostgreSQL + TimescaleDB

### Overview

The PrivaseeAI.Security database is designed to store threat detection data, device information, and time-series monitoring events using PostgreSQL with TimescaleDB extension for efficient time-series data management.

### Technology Stack

- **PostgreSQL 15+** - Primary relational database
- **TimescaleDB 2.11+** - Time-series extension for high-performance event storage
- **SQLAlchemy 2.0+** - Python ORM
- **Alembic** - Database migrations

### Design Principles

1. **Time-Series Optimization** - Events stored in TimescaleDB hypertables for efficient queries
2. **Data Retention** - Automatic data aging (90 days for raw events, indefinite for threats)
3. **Scalability** - Supports unlimited devices with partitioning
4. **Forensics** - Complete audit trail of all detections and configurations
5. **Real-Time Analytics** - Continuous aggregates for dashboards
6. **Deduplication** - Fingerprint-based threat deduplication

---

## Table Structure

### Core Tables

#### `devices`
Stores information about monitored iOS devices.

**Key Fields:**
- `device_udid` - Unique device identifier
- `backup_location` - Path to iOS backup directory
- `encryption_enabled` - Whether backup is encrypted
- `last_seen_at` - Last monitoring activity

**Use Cases:**
- Device registration and tracking
- Multi-device support
- Device health monitoring

#### `threats`
All detected security threats and alerts.

**Key Fields:**
- `fingerprint` - SHA256 hash for deduplication (prevents duplicate alerts)
- `severity` - CRITICAL, HIGH, MEDIUM, LOW
- `threat_type` - Classification (VPN_MANIPULATION, CARRIER_COMPROMISE, etc.)
- `indicators` - JSONB array of detection indicators
- `evidence` - JSONB supporting evidence

**Deduplication Logic:**
```python
fingerprint = hashlib.sha256(
    f"{device_id}:{threat_type}:{key_indicators}".encode()
).hexdigest()
```

If fingerprint exists, increment `occurrences` and update `last_occurrence`.

**Use Cases:**
- Real-time threat dashboard
- Historical threat analysis
- Incident response tracking

---

### Time-Series Tables (TimescaleDB Hypertables)

#### `vpn_events`
High-frequency VPN connection events.

**Partitioning:** 1-day chunks
**Retention:** 90 days (configurable)

**Key Metrics:**
- Connection status changes
- Protocol switches (UDP → TCP detection)
- Server hopping patterns
- Performance metrics (latency, throughput)

**Aggregations:**
- Hourly/daily VPN statistics
- Server switch frequency analysis
- Anomaly detection baselines

#### `network_events`
Network connectivity and configuration events.

**Key Detections:**
- DNS tampering
- Localhost routing
- Suspicious connections

**Use Cases:**
- Carrier-level attack detection
- Network configuration monitoring
- Baseline behavior learning

#### `api_events`
API request patterns and rate limiting.

**Key Detections:**
- Location API abuse
- Rate limiting patterns
- Burst activity detection
- Background activity monitoring

**Retention Strategy:**
- Raw events: 90 days
- Aggregated stats: Indefinite via continuous aggregates

---

### Forensic Tables

#### `backup_snapshots`
Metadata about iOS backup analysis.

**Key Fields:**
- `vpn_profiles` - JSONB array of extracted VPN configurations
- `mdm_profiles` - Mobile Device Management profiles
- `carrier_bundles` - Carrier configuration bundles
- `certificates` - Extracted certificates

**Use Cases:**
- Historical backup comparison
- Profile persistence tracking
- Evidence preservation

#### `configuration_profiles`
Individual configuration profiles extracted from backups.

**Persistence Tracking:**
- `persistence_count` - How many backups contained this profile
- `survived_factory_reset` - Indicator of compromise

**Threat Scoring:**
- Localhost routing: CRITICAL
- Unknown VPN profile: HIGH
- Self-signed certificates: MEDIUM

#### `certificates`
SSL/TLS certificate tracking and validation.

**Fingerprinting:**
- SHA-256 hash of certificate
- Comparison against `certificate_baseline` (known good)

**Trust Evaluation:**
- Trusted: In baseline, not expired
- Untrusted: Self-signed, expired, or invalid chain
- Suspicious: Unexpected issuer for VPN

---

### System Tables

#### `monitor_status`
Health monitoring for detection components.

**Metrics:**
- Heartbeat timestamps
- Events processed count
- Error rates
- Performance (avg processing time)

**Use Cases:**
- Monitor health dashboard
- Automatic restart triggers
- Performance optimization

#### `alert_notifications`
Delivery tracking for alerts.

**Features:**
- Multi-channel support (Telegram, email, webhook)
- Delivery confirmation
- Retry logic with backoff
- Rate limiting protection

#### `device_baselines`
30-day behavioral profiles for ML anomaly detection.

**Learned Patterns:**
- Typical VPN providers and protocols
- Normal API usage patterns
- Expected connection types
- Active hours profile

**Confidence Scoring:**
- 0.0-0.5: Learning (7-14 days)
- 0.5-0.8: Partial confidence (15-21 days)
- 0.8-1.0: High confidence (22-30 days)

---

## Continuous Aggregates (TimescaleDB)

### `threats_hourly_summary`
Pre-computed hourly threat statistics.

**Updated:** Every 5 minutes
**Retention:** Indefinite

**Queries Optimized:**
```sql
-- Get threats for last 24 hours
SELECT * FROM threats_hourly_summary
WHERE hour > NOW() - INTERVAL '24 hours';
```

### `vpn_daily_stats`
Daily VPN usage and anomaly statistics.

**Metrics:**
- Unique servers used
- Total server switches
- TCP fallback occurrences
- Average latency

**Dashboard Uses:**
- Weekly/monthly trends
- Anomaly detection
- Performance monitoring

---

## Indexing Strategy

### Critical Indexes

**Frequently Queried:**
```sql
-- Threats by device and time (dashboard)
CREATE INDEX idx_threats_device_time ON threats(device_id, detected_at DESC);

-- Active threats (status page)
CREATE INDEX idx_threats_status ON threats(status) WHERE status = 'open';

-- Recent VPN anomalies
CREATE INDEX idx_vpn_events_anomalies ON vpn_events(time DESC)
    WHERE is_tcp_fallback OR is_rate_limited OR is_server_hopping;
```

**Partial Indexes:**
Used for common WHERE clauses to reduce index size:
- Open threats only
- Recent events (last 30 days)
- Anomalous events only

---

## Data Retention Policies

### Automatic Aging

**TimescaleDB Retention:**
```sql
-- Raw event data: 90 days
SELECT add_retention_policy('vpn_events', INTERVAL '90 days');
SELECT add_retention_policy('network_events', INTERVAL '90 days');
SELECT add_retention_policy('api_events', INTERVAL '90 days');
```

**Manual Archival:**
```sql
-- Archive resolved threats older than 1 year
UPDATE threats
SET status = 'archived'
WHERE status = 'resolved'
  AND resolved_at < NOW() - INTERVAL '1 year';
```

### Backup Strategy

**Daily Backups:**
- Full database: 7 days retention
- Continuous archiving (WAL): 30 days

**Critical Tables (Never Delete):**
- `threats` - Permanent audit trail
- `backup_snapshots` - Forensic evidence
- `configuration_profiles` - Persistence tracking

---

## Query Patterns

### Common Queries

**Active Threats Dashboard:**
```sql
SELECT
    d.device_name,
    t.severity,
    t.title,
    t.detected_at,
    t.occurrences
FROM threats t
JOIN devices d ON t.device_id = d.id
WHERE t.status = 'open'
ORDER BY
    CASE t.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END,
    t.detected_at DESC;
```

**VPN Anomaly Detection (Last 24h):**
```sql
SELECT
    time,
    vpn_provider,
    server_location,
    protocol
FROM vpn_events
WHERE device_id = :device_id
  AND time > NOW() - INTERVAL '24 hours'
  AND (is_tcp_fallback OR is_server_hopping OR is_rate_limited)
ORDER BY time DESC;
```

**Persistent Profile Detection:**
```sql
SELECT
    profile_name,
    profile_type,
    persistence_count,
    survived_factory_reset,
    first_seen_at,
    last_seen_at
FROM configuration_profiles
WHERE device_id = :device_id
  AND persistence_count >= 3
  AND is_suspicious = true
ORDER BY threat_level DESC, persistence_count DESC;
```

---

## Migration Strategy

### Phase 4A: Initial Setup (Week 1)
1. Deploy PostgreSQL + TimescaleDB
2. Run schema migrations
3. Create indexes and views
4. Set retention policies

### Phase 4B: Data Pipeline (Week 2)
1. Implement SQLAlchemy models
2. Create repository layer
3. Add event writers for monitors
4. Test data ingestion

### Phase 4C: Query API (Week 3)
1. Build query service
2. Implement aggregations
3. Add caching layer (Redis)
4. Performance testing

---

## Performance Targets

**Write Performance:**
- 1,000 events/second sustained
- <10ms insert latency (p95)
- No backpressure under normal load

**Read Performance:**
- Dashboard queries: <100ms (p95)
- Threat history: <500ms (p95)
- Aggregated stats: <50ms (cached)

**Storage:**
- ~1 MB/day per device (compressed)
- ~30 MB/month per device
- ~360 MB/year per device

**Scaling:**
- 100 devices: 36 GB/year
- 1,000 devices: 360 GB/year
- 10,000 devices: 3.6 TB/year

---

## Security Considerations

**Access Control:**
```sql
-- Create application user with limited permissions
CREATE USER privasee_app WITH PASSWORD 'secure_password';
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO privasee_app;
GRANT DELETE ON alert_notifications TO privasee_app;  -- Cleanup only
REVOKE DELETE ON threats, devices FROM privasee_app;  -- Prevent data loss
```

**Sensitive Data:**
- Device UDIDs: Hashed in logs
- IP addresses: Anonymized for non-threats
- Certificate data: Encrypted at rest

**Audit Trail:**
- All UPDATE operations logged
- Threat resolution requires notes
- Configuration changes tracked

---

## Monitoring & Observability

**Prometheus Metrics:**
```python
# Export from application
db_query_duration_seconds
db_connection_pool_size
db_active_queries
threats_total{severity="CRITICAL"}
events_written_total{table="vpn_events"}
```

**Alerts:**
- Database connection pool exhaustion
- Slow query detection (>1s)
- Hypertable chunk creation failures
- Retention policy errors

---

## Next Steps

### After Phase 4 Launch

**Optimization:**
1. Add composite indexes based on query patterns
2. Tune TimescaleDB compression
3. Implement query result caching
4. Optimize continuous aggregates

**Enhancements:**
5. Multi-region replication for HA
6. Read replicas for dashboard queries
7. Archival to S3 for long-term storage
8. Advanced analytics with Grafana

---

## References

- [TimescaleDB Documentation](https://docs.timescale.com/)
- [PostgreSQL Performance Tuning](https://www.postgresql.org/docs/current/performance-tips.html)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
- [Alembic Migrations](https://alembic.sqlalchemy.org/)
