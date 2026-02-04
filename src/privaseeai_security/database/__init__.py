"""
Database package for PrivaseeAI.Security threat persistence.

This package provides async SQLAlchemy models and repositories for storing
threat detection events in PostgreSQL with TimescaleDB hypertables.
"""

from .models import Base, Device, ThreatEvent
from .engine import AsyncEngine, get_async_session, init_db
from .repositories import DeviceRepository, ThreatEventRepository
from .queries import (
    get_threats_last_n_days_grouped_by_severity,
    get_top_threat_types,
    get_device_threat_summary,
    get_trending_threats,
    get_unacknowledged_critical_threats,
)

__all__ = [
    "Base",
    "Device",
    "ThreatEvent",
    "AsyncEngine",
    "get_async_session",
    "init_db",
    "DeviceRepository",
    "ThreatEventRepository",
    "get_threats_last_n_days_grouped_by_severity",
    "get_top_threat_types",
    "get_device_threat_summary",
    "get_trending_threats",
    "get_unacknowledged_critical_threats",
]
