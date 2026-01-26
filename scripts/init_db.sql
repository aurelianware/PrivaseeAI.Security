-- PrivaseeAI Security Database Initialization Script
-- This script initializes the TimescaleDB database with necessary extensions and tables

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Enable additional useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schema for organization
CREATE SCHEMA IF NOT EXISTS security;

-- Set search path
SET search_path TO security, public;

-- =====================================
-- Device Information Table
-- =====================================
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(255) UNIQUE NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(100),
    ios_version VARCHAR(50),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'active',
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================
-- Threat Events Table (Time-Series)
-- =====================================
CREATE TABLE IF NOT EXISTS threat_events (
    id UUID DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    threat_category VARCHAR(100),
    description TEXT,
    details JSONB,
    source VARCHAR(100),
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);

-- Convert threat_events to hypertable for time-series optimization
SELECT create_hypertable('threat_events', 'event_time', 
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =====================================
-- File Monitoring Table (Time-Series)
-- =====================================
CREATE TABLE IF NOT EXISTS file_events (
    id UUID DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    file_path TEXT NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    file_size BIGINT,
    file_hash VARCHAR(128),
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);

-- Convert file_events to hypertable
SELECT create_hypertable('file_events', 'event_time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =====================================
-- Backup Analysis Results
-- =====================================
CREATE TABLE IF NOT EXISTS backup_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    backup_time TIMESTAMPTZ NOT NULL,
    analysis_time TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(50) NOT NULL,
    threats_detected INTEGER DEFAULT 0,
    anomalies_detected INTEGER DEFAULT 0,
    analysis_details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================
-- Indexes for Performance
-- =====================================
CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_threat_events_device_time ON threat_events(device_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threat_events_type ON threat_events(event_type);
CREATE INDEX IF NOT EXISTS idx_threat_events_resolved ON threat_events(is_resolved);
CREATE INDEX IF NOT EXISTS idx_file_events_device_time ON file_events(device_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(file_path);
CREATE INDEX IF NOT EXISTS idx_backup_analysis_device ON backup_analysis(device_id);
CREATE INDEX IF NOT EXISTS idx_backup_analysis_time ON backup_analysis(backup_time DESC);

-- =====================================
-- Retention Policies
-- =====================================
-- Keep threat events for 1 year
SELECT add_retention_policy('threat_events', INTERVAL '365 days', if_not_exists => TRUE);

-- Keep file events for 90 days
SELECT add_retention_policy('file_events', INTERVAL '90 days', if_not_exists => TRUE);

-- =====================================
-- Continuous Aggregates for Analytics
-- =====================================
-- Daily threat summary
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_events_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', event_time) AS bucket,
    device_id,
    severity,
    threat_category,
    COUNT(*) as event_count,
    COUNT(CASE WHEN is_resolved THEN 1 END) as resolved_count
FROM threat_events
GROUP BY bucket, device_id, severity, threat_category
WITH NO DATA;

-- Refresh policy for continuous aggregate
SELECT add_continuous_aggregate_policy('threat_events_daily',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- =====================================
-- Functions and Triggers
-- =====================================
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for devices table
CREATE OR REPLACE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================
-- Initial Data (Optional)
-- =====================================
-- Add any seed data here if needed

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA security TO privaseeai;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA security TO privaseeai;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA security TO privaseeai;

-- Completion message
DO $$
BEGIN
    RAISE NOTICE 'PrivaseeAI Security database initialized successfully';
END $$;
