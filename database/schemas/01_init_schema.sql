-- PrivaseeAI.Security Database Schema
-- Phase 4: PostgreSQL + TimescaleDB
-- Version: 1.0.0
-- Created: 2026-01-31

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "timescaledb";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Devices table: Track monitored iOS devices
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_name VARCHAR(255) NOT NULL,
    device_model VARCHAR(100) NOT NULL,  -- e.g., "iPhone 16 Pro"
    ios_version VARCHAR(50) NOT NULL,     -- e.g., "18.2"
    device_udid VARCHAR(255) UNIQUE NOT NULL,
    backup_location TEXT NOT NULL,
    encryption_enabled BOOLEAN DEFAULT false,
    carrier VARCHAR(100),
    last_backup_date TIMESTAMP,
    first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'active',  -- active, inactive, deleted
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_udid ON devices(device_udid);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at DESC);

-- ============================================================================
-- THREAT DETECTION
-- ============================================================================

-- Threats/Alerts table: All detected threats
CREATE TABLE threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    threat_type VARCHAR(100) NOT NULL,  -- VPN_MANIPULATION, CARRIER_COMPROMISE, etc.
    severity VARCHAR(20) NOT NULL,      -- CRITICAL, HIGH, MEDIUM, LOW
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open',  -- open, investigating, resolved, false_positive

    -- Detection details
    monitor_name VARCHAR(100) NOT NULL,  -- Which monitor detected it
    indicators JSONB DEFAULT '[]',       -- Array of indicator strings
    evidence JSONB DEFAULT '{}',         -- Supporting evidence

    -- Response tracking
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMP,
    resolution_notes TEXT,

    -- Metadata
    fingerprint VARCHAR(64) UNIQUE,  -- SHA256 hash for deduplication
    occurrences INTEGER DEFAULT 1,
    first_occurrence TIMESTAMP NOT NULL DEFAULT NOW(),
    last_occurrence TIMESTAMP NOT NULL DEFAULT NOW(),

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threats_device ON threats(device_id);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_threats_status ON threats(status);
CREATE INDEX idx_threats_type ON threats(threat_type);
CREATE INDEX idx_threats_detected_at ON threats(detected_at DESC);
CREATE INDEX idx_threats_fingerprint ON threats(fingerprint);
CREATE INDEX idx_threats_monitor ON threats(monitor_name);

-- Convert to TimescaleDB hypertable for time-series optimization
SELECT create_hypertable('threats', 'detected_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- ============================================================================
-- TIME-SERIES MONITORING DATA
-- ============================================================================

-- VPN monitoring events (time-series)
CREATE TABLE vpn_events (
    time TIMESTAMP NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- VPN details
    vpn_provider VARCHAR(100),
    server_location VARCHAR(100),
    protocol VARCHAR(20),           -- udp, tcp, wireguard, openvpn
    connection_status VARCHAR(20),  -- connected, disconnected, reconnecting

    -- Performance metrics
    connection_duration INTEGER,    -- seconds
    bytes_sent BIGINT,
    bytes_received BIGINT,
    latency_ms INTEGER,

    -- Detection metrics
    server_switches INTEGER DEFAULT 0,
    protocol_changes INTEGER DEFAULT 0,
    disconnection_count INTEGER DEFAULT 0,

    -- Anomalies
    is_tcp_fallback BOOLEAN DEFAULT false,
    is_rate_limited BOOLEAN DEFAULT false,
    is_server_hopping BOOLEAN DEFAULT false,

    metadata JSONB DEFAULT '{}'
);

-- Create hypertable
SELECT create_hypertable('vpn_events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX idx_vpn_events_device_time ON vpn_events(device_id, time DESC);
CREATE INDEX idx_vpn_events_provider ON vpn_events(vpn_provider);
CREATE INDEX idx_vpn_events_anomalies ON vpn_events(time DESC)
    WHERE is_tcp_fallback = true OR is_rate_limited = true OR is_server_hopping = true;

-- Network events (time-series)
CREATE TABLE network_events (
    time TIMESTAMP NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- Network details
    carrier VARCHAR(100),
    connection_type VARCHAR(50),  -- wifi, cellular_5g, cellular_4g, etc.
    ip_address INET,
    dns_servers JSONB DEFAULT '[]',

    -- Traffic metrics
    total_bytes_sent BIGINT,
    total_bytes_received BIGINT,
    active_connections INTEGER,

    -- Anomalies
    is_dns_tampered BOOLEAN DEFAULT false,
    is_localhost_route BOOLEAN DEFAULT false,
    suspicious_connections JSONB DEFAULT '[]',

    metadata JSONB DEFAULT '{}'
);

SELECT create_hypertable('network_events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX idx_network_events_device_time ON network_events(device_id, time DESC);
CREATE INDEX idx_network_events_carrier ON network_events(carrier);
CREATE INDEX idx_network_events_anomalies ON network_events(time DESC)
    WHERE is_dns_tampered = true OR is_localhost_route = true;

-- API abuse events (time-series)
CREATE TABLE api_events (
    time TIMESTAMP NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- API details
    api_endpoint VARCHAR(500),
    api_provider VARCHAR(100),
    request_type VARCHAR(50),

    -- Request metrics
    request_count INTEGER DEFAULT 1,
    error_count INTEGER DEFAULT 0,
    rate_limit_hits INTEGER DEFAULT 0,

    -- Timing
    response_time_ms INTEGER,
    retry_after_seconds INTEGER,

    -- Anomalies
    is_rate_limited BOOLEAN DEFAULT false,
    is_burst_pattern BOOLEAN DEFAULT false,
    is_background_activity BOOLEAN DEFAULT false,

    metadata JSONB DEFAULT '{}'
);

SELECT create_hypertable('api_events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX idx_api_events_device_time ON api_events(device_id, time DESC);
CREATE INDEX idx_api_events_endpoint ON api_events(api_endpoint);
CREATE INDEX idx_api_events_anomalies ON api_events(time DESC)
    WHERE is_rate_limited = true OR is_burst_pattern = true;

-- ============================================================================
-- FORENSIC DATA
-- ============================================================================

-- Backup snapshots: Store metadata about iOS backups
CREATE TABLE backup_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    backup_date TIMESTAMP NOT NULL,
    backup_size_bytes BIGINT,
    file_count INTEGER,
    is_encrypted BOOLEAN DEFAULT false,

    -- Extracted profiles
    vpn_profiles JSONB DEFAULT '[]',
    mdm_profiles JSONB DEFAULT '[]',
    carrier_bundles JSONB DEFAULT '[]',
    certificates JSONB DEFAULT '[]',

    -- Analysis results
    threat_count INTEGER DEFAULT 0,
    analyzed_at TIMESTAMP,
    analysis_duration_ms INTEGER,

    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backup_snapshots_device ON backup_snapshots(device_id);
CREATE INDEX idx_backup_snapshots_date ON backup_snapshots(backup_date DESC);

-- Configuration profiles: Track all profiles found in backups
CREATE TABLE configuration_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    backup_snapshot_id UUID REFERENCES backup_snapshots(id) ON DELETE CASCADE,

    profile_type VARCHAR(50) NOT NULL,  -- vpn, mdm, wifi, certificate
    profile_name VARCHAR(255),
    profile_uuid VARCHAR(255),
    profile_data JSONB NOT NULL,

    -- Persistence tracking
    first_seen_backup_id UUID,
    first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    persistence_count INTEGER DEFAULT 1,
    survived_factory_reset BOOLEAN DEFAULT false,

    -- Threat indicators
    is_suspicious BOOLEAN DEFAULT false,
    suspicion_reasons JSONB DEFAULT '[]',
    threat_level VARCHAR(20),  -- NONE, LOW, MEDIUM, HIGH, CRITICAL

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_config_profiles_device ON configuration_profiles(device_id);
CREATE INDEX idx_config_profiles_type ON configuration_profiles(profile_type);
CREATE INDEX idx_config_profiles_suspicious ON configuration_profiles(is_suspicious);
CREATE INDEX idx_config_profiles_uuid ON configuration_profiles(profile_uuid);

-- ============================================================================
-- CERTIFICATES
-- ============================================================================

-- Certificate tracking
CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,

    -- Certificate details
    fingerprint VARCHAR(128) UNIQUE NOT NULL,  -- SHA-256
    subject VARCHAR(500),
    issuer VARCHAR(500),
    serial_number VARCHAR(255),

    -- Validity
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    is_expired BOOLEAN DEFAULT false,
    is_self_signed BOOLEAN DEFAULT false,

    -- Classification
    cert_type VARCHAR(50),  -- vpn, ssl, root_ca, intermediate_ca
    known_good BOOLEAN DEFAULT false,
    known_provider VARCHAR(100),  -- e.g., "ProtonVPN"

    -- Trust evaluation
    trust_status VARCHAR(50),  -- trusted, untrusted, suspicious, unknown
    validation_errors JSONB DEFAULT '[]',

    -- Tracking
    first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_certificates_fingerprint ON certificates(fingerprint);
CREATE INDEX idx_certificates_device ON certificates(device_id);
CREATE INDEX idx_certificates_status ON certificates(trust_status);
CREATE INDEX idx_certificates_expired ON certificates(is_expired);

-- Known good certificate fingerprints (baseline)
CREATE TABLE certificate_baseline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(100) NOT NULL,  -- ProtonVPN, NordVPN, etc.
    fingerprint VARCHAR(128) UNIQUE NOT NULL,
    certificate_type VARCHAR(50),
    description TEXT,
    added_at TIMESTAMP NOT NULL DEFAULT NOW(),
    verified_by VARCHAR(255),
    source VARCHAR(255)  -- official_api, manual_verification, community
);

CREATE INDEX idx_cert_baseline_provider ON certificate_baseline(provider);
CREATE INDEX idx_cert_baseline_fingerprint ON certificate_baseline(fingerprint);

-- ============================================================================
-- MONITORING & SYSTEM
-- ============================================================================

-- Monitor health/status
CREATE TABLE monitor_status (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_name VARCHAR(100) UNIQUE NOT NULL,
    is_running BOOLEAN DEFAULT false,
    last_heartbeat TIMESTAMP,
    status VARCHAR(50) DEFAULT 'stopped',  -- running, stopped, error, degraded

    -- Performance metrics
    events_processed BIGINT DEFAULT 0,
    threats_detected BIGINT DEFAULT 0,
    errors_count BIGINT DEFAULT 0,
    average_processing_ms INTEGER,

    -- Version
    version VARCHAR(50),
    config JSONB DEFAULT '{}',

    started_at TIMESTAMP,
    stopped_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_monitor_status_running ON monitor_status(is_running);
CREATE INDEX idx_monitor_status_heartbeat ON monitor_status(last_heartbeat DESC);

-- Alert notifications log
CREATE TABLE alert_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_id UUID REFERENCES threats(id) ON DELETE CASCADE,

    -- Notification details
    channel VARCHAR(50) NOT NULL,  -- telegram, email, webhook
    recipient VARCHAR(255),

    -- Delivery
    sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
    delivered BOOLEAN DEFAULT false,
    delivery_confirmed_at TIMESTAMP,
    error_message TEXT,

    -- Rate limiting
    throttled BOOLEAN DEFAULT false,
    retry_count INTEGER DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_notifications_threat ON alert_notifications(threat_id);
CREATE INDEX idx_alert_notifications_channel ON alert_notifications(channel);
CREATE INDEX idx_alert_notifications_sent ON alert_notifications(sent_at DESC);

-- ============================================================================
-- ANALYTICS & REPORTING
-- ============================================================================

-- Device baselines: 30-day normal behavior profiles
CREATE TABLE device_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID UNIQUE NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- VPN baseline
    typical_vpn_providers JSONB DEFAULT '[]',
    typical_vpn_protocol VARCHAR(20),
    avg_vpn_session_duration INTEGER,  -- seconds
    avg_daily_server_switches INTEGER,

    -- Network baseline
    typical_carriers JSONB DEFAULT '[]',
    typical_connection_types JSONB DEFAULT '[]',
    avg_daily_data_mb INTEGER,

    -- API baseline
    typical_api_endpoints JSONB DEFAULT '[]',
    avg_hourly_api_calls INTEGER,
    typical_active_hours JSONB DEFAULT '[]',  -- [0-23]

    -- Learning period
    baseline_start_date TIMESTAMP NOT NULL,
    baseline_end_date TIMESTAMP NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 0.0,  -- 0.0 to 1.0
    is_active BOOLEAN DEFAULT true,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_baselines_device ON device_baselines(device_id);
CREATE INDEX idx_device_baselines_active ON device_baselines(is_active);

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threats_updated_at BEFORE UPDATE ON threats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_config_profiles_updated_at BEFORE UPDATE ON configuration_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_certificates_updated_at BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_monitor_status_updated_at BEFORE UPDATE ON monitor_status
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_device_baselines_updated_at BEFORE UPDATE ON device_baselines
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- CONTINUOUS AGGREGATES (TimescaleDB)
-- ============================================================================

-- Hourly threat summary
CREATE MATERIALIZED VIEW threats_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    device_id,
    time_bucket('1 hour', detected_at) AS hour,
    COUNT(*) AS threat_count,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE severity = 'HIGH') AS high_count,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium_count,
    COUNT(*) FILTER (WHERE severity = 'LOW') AS low_count,
    array_agg(DISTINCT threat_type) AS threat_types
FROM threats
GROUP BY device_id, hour;

-- Daily VPN statistics
CREATE MATERIALIZED VIEW vpn_daily_stats
WITH (timescaledb.continuous) AS
SELECT
    device_id,
    time_bucket('1 day', time) AS day,
    COUNT(*) AS event_count,
    COUNT(DISTINCT server_location) AS unique_servers,
    SUM(server_switches) AS total_server_switches,
    COUNT(*) FILTER (WHERE is_tcp_fallback = true) AS tcp_fallback_count,
    AVG(latency_ms) AS avg_latency_ms,
    SUM(bytes_sent + bytes_received) AS total_bytes
FROM vpn_events
GROUP BY device_id, day;

-- ============================================================================
-- DATA RETENTION POLICIES (TimescaleDB)
-- ============================================================================

-- Retain raw VPN events for 90 days
SELECT add_retention_policy('vpn_events', INTERVAL '90 days');

-- Retain raw network events for 90 days
SELECT add_retention_policy('network_events', INTERVAL '90 days');

-- Retain raw API events for 90 days
SELECT add_retention_policy('api_events', INTERVAL '90 days');

-- Keep threats indefinitely (they're already summarized)
-- No retention policy on threats table

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert known good ProtonVPN certificates
INSERT INTO certificate_baseline (provider, fingerprint, certificate_type, description, verified_by, source) VALUES
('ProtonVPN', 'ABC123...', 'vpn_certificate', 'ProtonVPN root certificate', 'system', 'official_api'),
('ProtonVPN', 'DEF456...', 'vpn_certificate', 'ProtonVPN intermediate CA', 'system', 'official_api');
-- Add more as needed

-- Initialize monitor status entries
INSERT INTO monitor_status (monitor_name, version, status) VALUES
('VPNIntegrityMonitor', '0.3.0', 'stopped'),
('APIAbuseMonitor', '0.3.0', 'stopped'),
('CarrierCompromiseDetector', '0.3.0', 'stopped'),
('CertificateValidator', '0.3.0', 'stopped');

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active threats view
CREATE VIEW active_threats AS
SELECT
    t.*,
    d.device_name,
    d.device_model,
    d.ios_version
FROM threats t
JOIN devices d ON t.device_id = d.id
WHERE t.status = 'open'
ORDER BY t.severity DESC, t.detected_at DESC;

-- Recent high-severity threats (last 24 hours)
CREATE VIEW recent_critical_threats AS
SELECT
    t.*,
    d.device_name,
    d.device_model
FROM threats t
JOIN devices d ON t.device_id = d.id
WHERE t.severity IN ('CRITICAL', 'HIGH')
  AND t.detected_at > NOW() - INTERVAL '24 hours'
ORDER BY t.detected_at DESC;

-- Device health summary
CREATE VIEW device_health_summary AS
SELECT
    d.id,
    d.device_name,
    d.device_model,
    d.last_seen_at,
    COUNT(t.id) FILTER (WHERE t.status = 'open') AS open_threats,
    COUNT(t.id) FILTER (WHERE t.severity = 'CRITICAL' AND t.status = 'open') AS critical_threats,
    MAX(t.detected_at) AS last_threat_detected
FROM devices d
LEFT JOIN threats t ON d.id = t.device_id
GROUP BY d.id, d.device_name, d.device_model, d.last_seen_at;

COMMENT ON TABLE devices IS 'Monitored iOS devices';
COMMENT ON TABLE threats IS 'Detected security threats and alerts';
COMMENT ON TABLE vpn_events IS 'Time-series VPN monitoring events';
COMMENT ON TABLE network_events IS 'Time-series network activity events';
COMMENT ON TABLE api_events IS 'Time-series API abuse monitoring events';
COMMENT ON TABLE backup_snapshots IS 'iOS backup metadata and analysis results';
COMMENT ON TABLE configuration_profiles IS 'Extracted configuration profiles from backups';
COMMENT ON TABLE certificates IS 'SSL/TLS certificates found on devices';
COMMENT ON TABLE certificate_baseline IS 'Known good certificate fingerprints';
COMMENT ON TABLE monitor_status IS 'Health and status of monitoring components';
COMMENT ON TABLE alert_notifications IS 'Alert delivery tracking';
COMMENT ON TABLE device_baselines IS 'Normal behavior profiles for ML detection';
