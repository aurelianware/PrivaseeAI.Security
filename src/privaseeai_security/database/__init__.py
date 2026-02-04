"""
Database package for PrivaseeAI.Security threat persistence.

This package provides async SQLAlchemy models and repositories for storing
threat detection events in PostgreSQL with TimescaleDB hypertables.
"""

from .engine import AsyncEngine, get_async_session, init_db
from .models import Base, Device, ThreatEvent
from .queries import (
    get_device_threat_summary,
    get_threats_last_n_days_grouped_by_severity,
    get_top_threat_types,
    get_trending_threats,
    get_unacknowledged_critical_threats,
)
from .repositories import DeviceRepository, ThreatEventRepository

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
