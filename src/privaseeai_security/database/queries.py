"""
Example query utilities for threat analysis and reporting.

Demonstrates common query patterns for threat persistence layer.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Device, ThreatEvent


async def get_threats_last_n_days_grouped_by_severity(
    session: AsyncSession, days: int = 7, device_id: Optional[str] = None
) -> Dict[str, int]:
    """
    Get threat count for the last N days, grouped by severity.

    This is the example query requested in the requirements.

    Args:
        session: Active AsyncSession instance
        days: Number of days to look back (default: 7)
        device_id: Optional device UUID to filter by specific device

    Returns:
        Dictionary mapping severity levels to counts
        Example: {"CRITICAL": 5, "HIGH": 12, "MEDIUM": 8, "LOW": 3}

    Example:
        ```python
        async with get_async_session() as session:
            severity_counts = await get_threats_last_n_days_grouped_by_severity(
                session, days=7
            )
            print(f"Critical threats in last 7 days: {severity_counts.get('CRITICAL', 0)}")
        ```
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = select(ThreatEvent.severity, func.count(ThreatEvent.id).label("count")).where(
        ThreatEvent.timestamp >= cutoff_date
    )

    if device_id:
        query = query.where(ThreatEvent.device_id == device_id)

    query = query.group_by(ThreatEvent.severity).order_by(ThreatEvent.severity)

    result = await session.execute(query)
    return {row.severity: row.count for row in result.all()}


async def get_top_threat_types(
    session: AsyncSession, days: int = 30, limit: int = 10
) -> List[Dict[str, Any]]:
    """
    Get the most common threat types in the last N days.

    Args:
        session: Active AsyncSession instance
        days: Number of days to look back
        limit: Maximum number of threat types to return

    Returns:
        List of dictionaries with threat_type and count

    Example:
        ```python
        async with get_async_session() as session:
            top_threats = await get_top_threat_types(session, days=30, limit=5)
            for threat in top_threats:
                print(f"{threat['threat_type']}: {threat['count']} occurrences")
        ```
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = (
        select(
            ThreatEvent.threat_type,
            func.count(ThreatEvent.id).label("count"),
            func.sum(ThreatEvent.occurrence_count).label("total_occurrences"),
        )
        .where(ThreatEvent.timestamp >= cutoff_date)
        .group_by(ThreatEvent.threat_type)
        .order_by(func.count(ThreatEvent.id).desc())
        .limit(limit)
    )

    result = await session.execute(query)
    return [
        {
            "threat_type": row.threat_type,
            "count": row.count,
            "total_occurrences": row.total_occurrences,
        }
        for row in result.all()
    ]


async def get_device_threat_summary(session: AsyncSession, device_id: str) -> Dict[str, Any]:
    """
    Get a comprehensive threat summary for a specific device.

    Args:
        session: Active AsyncSession instance
        device_id: UUID of the device

    Returns:
        Dictionary with threat statistics for the device

    Example:
        ```python
        async with get_async_session() as session:
            summary = await get_device_threat_summary(session, device_id)
            print(f"Total threats: {summary['total_threats']}")
            print(f"Unresolved: {summary['unresolved_count']}")
        ```
    """
    # Get device info
    device_result = await session.execute(select(Device).where(Device.id == device_id))
    device = device_result.scalar_one_or_none()

    if not device:
        return {"error": "Device not found"}

    # Count total threats
    total_query = select(func.count(ThreatEvent.id)).where(ThreatEvent.device_id == device_id)
    total_result = await session.execute(total_query)
    total_threats = total_result.scalar()

    # Count unresolved threats
    unresolved_query = select(func.count(ThreatEvent.id)).where(
        and_(ThreatEvent.device_id == device_id, ~ThreatEvent.resolved)
    )
    unresolved_result = await session.execute(unresolved_query)
    unresolved_count = unresolved_result.scalar()

    # Get severity breakdown for unresolved threats
    severity_query = (
        select(ThreatEvent.severity, func.count(ThreatEvent.id).label("count"))
        .where(and_(ThreatEvent.device_id == device_id, ~ThreatEvent.resolved))
        .group_by(ThreatEvent.severity)
    )
    severity_result = await session.execute(severity_query)
    severity_breakdown = {row.severity: row.count for row in severity_result.all()}

    # Get most recent threat
    recent_query = (
        select(ThreatEvent)
        .where(ThreatEvent.device_id == device_id)
        .order_by(ThreatEvent.timestamp.desc())
        .limit(1)
    )
    recent_result = await session.execute(recent_query)
    most_recent = recent_result.scalar_one_or_none()

    return {
        "device_id": str(device_id),
        "device_name": device.name,
        "device_udid": device.udid,
        "total_threats": total_threats,
        "unresolved_count": unresolved_count,
        "resolved_count": total_threats - unresolved_count,
        "severity_breakdown": severity_breakdown,
        "most_recent_threat": (
            {
                "timestamp": most_recent.timestamp.isoformat() if most_recent else None,
                "severity": most_recent.severity if most_recent else None,
                "threat_type": most_recent.threat_type if most_recent else None,
                "description": most_recent.description if most_recent else None,
            }
            if most_recent
            else None
        ),
    }


async def get_trending_threats(session: AsyncSession, hours: int = 24) -> List[Dict[str, Any]]:
    """
    Get threats that are trending (increasing in frequency) in recent hours.

    Compares threat occurrence in the last N hours vs previous N hours.

    Args:
        session: Active AsyncSession instance
        hours: Number of hours for the comparison window

    Returns:
        List of threat types with increasing frequency

    Example:
        ```python
        async with get_async_session() as session:
            trending = await get_trending_threats(session, hours=24)
            for threat in trending:
                print(f"{threat['threat_type']}: {threat['recent_count']} recent")
        ```
    """
    now = datetime.utcnow()
    recent_cutoff = now - timedelta(hours=hours)
    previous_cutoff = now - timedelta(hours=hours * 2)

    # Count threats in recent period
    recent_query = (
        select(
            ThreatEvent.threat_type,
            func.count(ThreatEvent.id).label("recent_count"),
        )
        .where(ThreatEvent.timestamp >= recent_cutoff)
        .group_by(ThreatEvent.threat_type)
    )

    # Count threats in previous period
    previous_query = (
        select(
            ThreatEvent.threat_type,
            func.count(ThreatEvent.id).label("previous_count"),
        )
        .where(
            and_(
                ThreatEvent.timestamp >= previous_cutoff,
                ThreatEvent.timestamp < recent_cutoff,
            )
        )
        .group_by(ThreatEvent.threat_type)
    )

    recent_result = await session.execute(recent_query)
    previous_result = await session.execute(previous_query)

    recent_counts = {row.threat_type: row.recent_count for row in recent_result.all()}
    previous_counts = {row.threat_type: row.previous_count for row in previous_result.all()}

    # Find threats with increasing frequency
    trending = []
    for threat_type, recent_count in recent_counts.items():
        previous_count = previous_counts.get(threat_type, 0)
        if recent_count > previous_count:
            trending.append(
                {
                    "threat_type": threat_type,
                    "recent_count": recent_count,
                    "previous_count": previous_count,
                    "increase_pct": (
                        ((recent_count - previous_count) / previous_count * 100)
                        if previous_count > 0
                        else 100
                    ),
                }
            )

    # Sort by increase percentage
    trending.sort(key=lambda x: x["increase_pct"], reverse=True)
    return trending


async def get_unacknowledged_critical_threats(
    session: AsyncSession,
) -> List[ThreatEvent]:
    """
    Get all unacknowledged critical threats across all devices.

    This is useful for alerting and dashboard displays.

    Args:
        session: Active AsyncSession instance

    Returns:
        List of ThreatEvent instances

    Example:
        ```python
        async with get_async_session() as session:
            critical = await get_unacknowledged_critical_threats(session)
            if critical:
                print(f"WARNING: {len(critical)} unacknowledged critical threats!")
        ```
    """
    query = (
        select(ThreatEvent)
        .where(
            and_(
                ThreatEvent.severity == "CRITICAL",
                ~ThreatEvent.acknowledged,
                ~ThreatEvent.resolved,
            )
        )
        .order_by(ThreatEvent.timestamp.desc())
    )

    result = await session.execute(query)
    return list(result.scalars().all())
