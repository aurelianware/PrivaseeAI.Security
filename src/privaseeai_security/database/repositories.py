"""
Repository pattern for async CRUD operations on threat persistence models.

Implements clean separation of concerns with reusable data access patterns.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Device, ThreatEvent


class DeviceRepository:
    """
    Repository for Device CRUD operations.

    Provides async methods for managing device records.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with an async session.

        Args:
            session: Active AsyncSession instance
        """
        self.session = session

    async def create(
        self,
        name: str,
        udid: str,
        baseline_hash: Optional[str] = None,
        device_metadata: Optional[dict] = None,
    ) -> Device:
        """
        Create a new device record.

        Args:
            name: Human-readable device name
            udid: Unique device identifier
            baseline_hash: Optional baseline fingerprint
            device_metadata: Optional device metadata as JSONB dictionary

        Returns:
            Created Device instance

        Note:
            The parameter name `device_metadata` explicitly matches the model's column name
            to maintain API clarity and avoid confusion with SQLAlchemy's reserved `metadata`
            attribute (used for table definitions). This consistent naming makes the code
            more maintainable and prevents potential bugs.
        """
        device = Device(
            name=name,
            udid=udid,
            baseline_hash=baseline_hash,
            device_metadata=device_metadata or {},
        )
        self.session.add(device)
        await self.session.commit()
        await self.session.refresh(device)
        return device

    async def get_by_id(self, device_id: UUID) -> Optional[Device]:
        """
        Get device by ID.

        Args:
            device_id: UUID of the device

        Returns:
            Device instance or None if not found
        """
        result = await self.session.execute(select(Device).where(Device.id == device_id))
        return result.scalar_one_or_none()

    async def get_by_udid(self, udid: str) -> Optional[Device]:
        """
        Get device by UDID.

        Args:
            udid: Unique device identifier

        Returns:
            Device instance or None if not found
        """
        result = await self.session.execute(select(Device).where(Device.udid == udid))
        return result.scalar_one_or_none()

    async def update_last_seen(self, device_id: UUID) -> None:
        """
        Update the last_seen timestamp for a device.

        Args:
            device_id: UUID of the device
        """
        await self.session.execute(
            update(Device).where(Device.id == device_id).values(last_seen=func.now())
        )
        await self.session.commit()

    async def update_baseline(self, device_id: UUID, baseline_hash: str) -> None:
        """
        Update the baseline hash for a device.

        Args:
            device_id: UUID of the device
            baseline_hash: New baseline fingerprint
        """
        await self.session.execute(
            update(Device).where(Device.id == device_id).values(baseline_hash=baseline_hash)
        )
        await self.session.commit()

    async def list_all(self, limit: int = 100, offset: int = 0) -> List[Device]:
        """
        List all devices with pagination.

        Args:
            limit: Maximum number of devices to return
            offset: Number of devices to skip

        Returns:
            List of Device instances
        """
        result = await self.session.execute(
            select(Device).order_by(Device.last_seen.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def delete(self, device_id: UUID) -> bool:
        """
        Delete a device and all associated threat events (cascade).

        Args:
            device_id: UUID of the device

        Returns:
            True if device was deleted, False if not found
        """
        device = await self.get_by_id(device_id)
        if device:
            await self.session.delete(device)
            await self.session.commit()
            return True
        return False


class ThreatEventRepository:
    """
    Repository for ThreatEvent CRUD operations.

    Implements upsert logic for deduplication using fingerprints.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with an async session.

        Args:
            session: Active AsyncSession instance
        """
        self.session = session

    async def create_or_update(
        self,
        device_id: UUID,
        severity: str,
        threat_type: str,
        description: str,
        evidence_jsonb: dict,
        fingerprint: str,
    ) -> ThreatEvent:
        """
        Create a new threat event or update existing one if fingerprint exists.

        Uses PostgreSQL's INSERT ... ON CONFLICT to handle deduplication atomically.
        If fingerprint exists, increments occurrence_count and updates last_seen.

        Args:
            device_id: UUID of the device
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            threat_type: Type of threat
            description: Human-readable description
            evidence_jsonb: Supporting evidence as JSON
            fingerprint: Unique fingerprint for deduplication

        Returns:
            ThreatEvent instance (created or updated)
        """
        stmt = insert(ThreatEvent).values(
            device_id=device_id,
            severity=severity,
            threat_type=threat_type,
            description=description,
            evidence_jsonb=evidence_jsonb,
            fingerprint=fingerprint,
        )

        # On conflict, update occurrence count and last_seen
        stmt = stmt.on_conflict_do_update(
            index_elements=["fingerprint"],
            set_={
                "occurrence_count": ThreatEvent.occurrence_count + 1,
                "last_seen": func.now(),
                "severity": stmt.excluded.severity,  # Update severity in case it changed
                "description": stmt.excluded.description,
                "evidence_jsonb": stmt.excluded.evidence_jsonb,
            },
        ).returning(ThreatEvent)

        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.scalar_one()

    async def get_by_id(self, event_id: UUID) -> Optional[ThreatEvent]:
        """
        Get threat event by ID.

        Args:
            event_id: UUID of the threat event

        Returns:
            ThreatEvent instance or None if not found
        """
        result = await self.session.execute(select(ThreatEvent).where(ThreatEvent.id == event_id))
        return result.scalar_one_or_none()

    async def get_by_fingerprint(self, fingerprint: str) -> Optional[ThreatEvent]:
        """
        Get threat event by fingerprint.

        Args:
            fingerprint: Unique fingerprint hash

        Returns:
            ThreatEvent instance or None if not found
        """
        result = await self.session.execute(
            select(ThreatEvent).where(ThreatEvent.fingerprint == fingerprint)
        )
        return result.scalar_one_or_none()

    async def list_by_device(
        self,
        device_id: UUID,
        limit: int = 100,
        offset: int = 0,
        unresolved_only: bool = False,
    ) -> List[ThreatEvent]:
        """
        List threat events for a specific device.

        Args:
            device_id: UUID of the device
            limit: Maximum number of events to return
            offset: Number of events to skip
            unresolved_only: If True, only return unresolved threats

        Returns:
            List of ThreatEvent instances
        """
        query = select(ThreatEvent).where(ThreatEvent.device_id == device_id)

        if unresolved_only:
            query = query.where(~ThreatEvent.resolved)

        query = query.order_by(ThreatEvent.timestamp.desc()).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def list_recent(self, days: int = 7, severity: Optional[str] = None) -> List[ThreatEvent]:
        """
        List recent threat events within the specified time window.

        Args:
            days: Number of days to look back
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of ThreatEvent instances
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = select(ThreatEvent).where(ThreatEvent.timestamp >= cutoff_date)

        if severity:
            query = query.where(ThreatEvent.severity == severity)

        query = query.order_by(ThreatEvent.timestamp.desc())

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_threats_last_n_days_grouped_by_severity(self, days: int = 7) -> dict[str, int]:
        """
        Get threat count for the last N days, grouped by severity.

        This is the example query requested in the requirements.

        Args:
            days: Number of days to look back (default: 7)

        Returns:
            Dictionary mapping severity levels to counts
            Example: {"CRITICAL": 5, "HIGH": 12, "MEDIUM": 8, "LOW": 3}
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        query = (
            select(ThreatEvent.severity, func.count(ThreatEvent.id).label("count"))
            .where(ThreatEvent.timestamp >= cutoff_date)
            .group_by(ThreatEvent.severity)
            .order_by(ThreatEvent.severity)
        )

        result = await self.session.execute(query)
        return {row.severity: row.count for row in result.all()}

    async def acknowledge(self, event_id: UUID) -> bool:
        """
        Mark a threat event as acknowledged.

        Args:
            event_id: UUID of the threat event

        Returns:
            True if acknowledged, False if not found
        """
        result = await self.session.execute(
            update(ThreatEvent).where(ThreatEvent.id == event_id).values(acknowledged=True)
        )
        await self.session.commit()
        return result.rowcount > 0

    async def resolve(self, event_id: UUID) -> bool:
        """
        Mark a threat event as resolved.

        Args:
            event_id: UUID of the threat event

        Returns:
            True if resolved, False if not found
        """
        result = await self.session.execute(
            update(ThreatEvent).where(ThreatEvent.id == event_id).values(resolved=True)
        )
        await self.session.commit()
        return result.rowcount > 0

    async def delete(self, event_id: UUID) -> bool:
        """
        Delete a threat event.

        Args:
            event_id: UUID of the threat event

        Returns:
            True if deleted, False if not found
        """
        event = await self.get_by_id(event_id)
        if event:
            await self.session.delete(event)
            await self.session.commit()
            return True
        return False
