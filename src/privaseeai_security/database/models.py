"""
SQLAlchemy async models for threat persistence using PostgreSQL + TimescaleDB.

Modern SQLAlchemy 2.0 style with async support using asyncpg driver.
"""

import hashlib
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class Device(Base):
    """
    Device model representing monitored iOS devices.

    Stores device metadata and last seen information.
    """

    __tablename__ = "devices"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    udid: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now(), onupdate=func.now()
    )
    baseline_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_metadata: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    # Relationship to threat events
    threat_events: Mapped[list["ThreatEvent"]] = relationship(
        "ThreatEvent", back_populates="device", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Device(id={self.id}, name={self.name}, udid={self.udid})>"


class ThreatEvent(Base):
    """
    ThreatEvent model for storing security threat detections.

    This will be converted to a TimescaleDB hypertable partitioned by timestamp.
    Supports fingerprint-based deduplication using upsert logic.
    """

    __tablename__ = "threat_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now(), index=True
    )
    device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        sa.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # CRITICAL, HIGH, MEDIUM, LOW
    threat_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # VPN_MANIPULATION, CARRIER_COMPROMISE, etc.
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_jsonb: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    fingerprint: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )  # SHA256 hash for deduplication

    # Deduplication tracking
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now(), onupdate=func.now()
    )

    # Status tracking
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationship to device
    device: Mapped["Device"] = relationship("Device", back_populates="threat_events")

    def __repr__(self) -> str:
        return (
            f"<ThreatEvent(id={self.id}, severity={self.severity}, "
            f"threat_type={self.threat_type}, timestamp={self.timestamp})>"
        )

    @staticmethod
    def generate_fingerprint(device_id: UUID, threat_type: str, key_indicators: str) -> str:
        """
        Generate a unique fingerprint for deduplication.

        Args:
            device_id: UUID of the device
            threat_type: Type of threat detected
            key_indicators: Unique string representing the threat characteristics

        Returns:
            SHA256 hash as hex string
        """
        composite_key = f"{device_id}:{threat_type}:{key_indicators}"
        return hashlib.sha256(composite_key.encode()).hexdigest()
