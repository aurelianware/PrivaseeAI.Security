"""Initial threat persistence schema with TimescaleDB hypertables

Revision ID: 001_initial_threat_persistence
Revises:
Create Date: 2026-02-04

Creates:
- devices table for monitored iOS devices
- threat_events table (TimescaleDB hypertable) for security threat detections
- Indexes for efficient querying
- TimescaleDB hypertable with daily partitioning on threat_events

"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_initial_threat_persistence"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Create initial threat persistence schema.
    """
    # Enable TimescaleDB extension if not already enabled
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

    # Create devices table
    op.create_table(
        "devices",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("udid", sa.String(length=255), nullable=False),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("baseline_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "device_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("udid"),
    )

    # Create indexes for devices table
    op.create_index("ix_devices_udid", "devices", ["udid"], unique=True)

    # Create threat_events table
    op.create_table(
        "threat_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "evidence_jsonb",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )

    # Create indexes for threat_events table (before converting to hypertable)
    op.create_index("ix_threat_events_timestamp", "threat_events", ["timestamp"])
    op.create_index("ix_threat_events_device_id", "threat_events", ["device_id"])
    op.create_index("ix_threat_events_severity", "threat_events", ["severity"])
    op.create_index("ix_threat_events_threat_type", "threat_events", ["threat_type"])
    op.create_index("ix_threat_events_fingerprint", "threat_events", ["fingerprint"], unique=True)

    # Convert threat_events to TimescaleDB hypertable with daily partitioning
    op.execute("""
        SELECT create_hypertable(
            'threat_events',
            'timestamp',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        );
    """)

    # Create foreign key constraint after hypertable creation
    # Note: We use a regular foreign key since devices is not a hypertable
    op.create_foreign_key(
        "fk_threat_events_device_id",
        "threat_events",
        "devices",
        ["device_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # Create trigger to auto-update updated_at on devices table
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    op.execute("""
        CREATE TRIGGER update_devices_updated_at
        BEFORE UPDATE ON devices
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    """)


def downgrade() -> None:
    """
    Drop threat persistence schema.
    """
    # Drop triggers first
    op.execute("DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column();")

    # Drop foreign key constraint
    op.drop_constraint("fk_threat_events_device_id", "threat_events", type_="foreignkey")

    # Drop indexes
    op.drop_index("ix_threat_events_fingerprint", "threat_events")
    op.drop_index("ix_threat_events_threat_type", "threat_events")
    op.drop_index("ix_threat_events_severity", "threat_events")
    op.drop_index("ix_threat_events_device_id", "threat_events")
    op.drop_index("ix_threat_events_timestamp", "threat_events")
    op.drop_index("ix_devices_udid", "devices")

    # Drop tables (TimescaleDB hypertable will be automatically handled)
    op.drop_table("threat_events")
    op.drop_table("devices")
