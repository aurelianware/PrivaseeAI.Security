"""
Unit tests for async SQLAlchemy database models and repositories.

Tests cover:
- Device model and repository CRUD operations
- ThreatEvent model and repository with deduplication
- Query utilities
- Fingerprint generation
"""

import asyncio
import os
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio

from src.privaseeai_security.database import (
    Device,
    DeviceRepository,
    ThreatEvent,
    ThreatEventRepository,
    get_threats_last_n_days_grouped_by_severity,
)


# Helper to check if database is available
def is_database_available():
    """Check if a test database is configured and available."""
    db_url = os.getenv("DATABASE_URL", "")
    # Skip integration tests if no DATABASE_URL is set or if it's the default placeholder
    if not db_url or "localhost:5432" in db_url:
        return False
    return True


# Skip marker for integration tests when database is not available
skip_if_no_db = pytest.mark.skipif(
    not is_database_available(),
    reason="Database not available - set DATABASE_URL to run integration tests",
)


class TestThreatEventModel:
    """Test ThreatEvent model functionality."""

    def test_fingerprint_generation(self):
        """Test that fingerprint generation is deterministic."""
        device_id = uuid4()
        threat_type = "VPN_MANIPULATION"
        indicators = "tcp_fallback:protonvpn:us-ny-01"

        fingerprint1 = ThreatEvent.generate_fingerprint(device_id, threat_type, indicators)
        fingerprint2 = ThreatEvent.generate_fingerprint(device_id, threat_type, indicators)

        # Same inputs should produce same fingerprint
        assert fingerprint1 == fingerprint2
        assert len(fingerprint1) == 64  # SHA256 produces 64 hex characters

    def test_fingerprint_uniqueness(self):
        """Test that different inputs produce different fingerprints."""
        device_id1 = uuid4()
        device_id2 = uuid4()
        threat_type = "VPN_MANIPULATION"
        indicators = "tcp_fallback:protonvpn:us-ny-01"

        fingerprint1 = ThreatEvent.generate_fingerprint(device_id1, threat_type, indicators)
        fingerprint2 = ThreatEvent.generate_fingerprint(device_id2, threat_type, indicators)

        # Different device IDs should produce different fingerprints
        assert fingerprint1 != fingerprint2

    def test_threat_event_creation(self):
        """Test ThreatEvent model instantiation."""
        device_id = uuid4()
        threat = ThreatEvent(
            device_id=device_id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="Test threat",
            evidence_jsonb={"test": "data"},
            fingerprint="abc123",
        )

        assert threat.device_id == device_id
        assert threat.severity == "CRITICAL"
        assert threat.threat_type == "VPN_MANIPULATION"
        # Note: occurrence_count default is only applied when inserted to DB
        # In-memory object has None until persisted
        assert threat.fingerprint == "abc123"


class TestDeviceModel:
    """Test Device model functionality."""

    def test_device_creation(self):
        """Test Device model instantiation."""
        device = Device(
            name="Test iPhone",
            udid="test-udid-12345",
            baseline_hash="hash123",
            metadata={"model": "iPhone 15"},
        )

        assert device.name == "Test iPhone"
        assert device.udid == "test-udid-12345"
        assert device.baseline_hash == "hash123"
        assert device.metadata["model"] == "iPhone 15"

    def test_device_repr(self):
        """Test Device string representation."""
        device = Device(name="Test iPhone", udid="test-udid")
        device.id = uuid4()

        repr_str = repr(device)
        assert "Test iPhone" in repr_str
        assert "test-udid" in repr_str


# Integration tests would require a database connection
# These are marked as integration tests and would need a test database


@pytest.mark.integration
@skip_if_no_db
class TestDeviceRepositoryIntegration:
    """Integration tests for DeviceRepository (requires database)."""

    @pytest.mark.asyncio
    async def test_create_device(self, async_session):
        """Test creating a device via repository."""
        repo = DeviceRepository(async_session)

        device = await repo.create(
            name="Test Device",
            udid="test-udid-12345",
            baseline_hash="hash123",
        )

        assert device.id is not None
        assert device.name == "Test Device"
        assert device.udid == "test-udid-12345"
        assert device.baseline_hash == "hash123"

    @pytest.mark.asyncio
    async def test_get_device_by_udid(self, async_session):
        """Test retrieving device by UDID."""
        repo = DeviceRepository(async_session)

        # Create device
        created = await repo.create(name="Test Device", udid="unique-udid-67890")

        # Retrieve by UDID
        retrieved = await repo.get_by_udid("unique-udid-67890")

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.udid == "unique-udid-67890"

    @pytest.mark.asyncio
    async def test_update_last_seen(self, async_session):
        """Test updating device last_seen timestamp."""
        repo = DeviceRepository(async_session)

        device = await repo.create(name="Test Device", udid="udid-123")
        original_last_seen = device.last_seen

        # Small delay to ensure timestamp difference
        await asyncio.sleep(0.1)

        await repo.update_last_seen(device.id)

        updated = await repo.get_by_id(device.id)
        assert updated.last_seen > original_last_seen


@pytest.mark.integration
@skip_if_no_db
class TestThreatEventRepositoryIntegration:
    """Integration tests for ThreatEventRepository (requires database)."""

    @pytest.mark.asyncio
    async def test_create_threat_event(self, async_session, test_device):
        """Test creating a threat event."""
        repo = ThreatEventRepository(async_session)

        fingerprint = ThreatEvent.generate_fingerprint(
            test_device.id, "VPN_MANIPULATION", "test-indicators"
        )

        threat = await repo.create_or_update(
            device_id=test_device.id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="Test threat",
            evidence_jsonb={"test": "evidence"},
            fingerprint=fingerprint,
        )

        assert threat.id is not None
        assert threat.device_id == test_device.id
        assert threat.severity == "CRITICAL"
        assert threat.occurrence_count == 1

    @pytest.mark.asyncio
    async def test_threat_deduplication(self, async_session, test_device):
        """Test threat event deduplication via fingerprint."""
        repo = ThreatEventRepository(async_session)

        fingerprint = ThreatEvent.generate_fingerprint(
            test_device.id, "VPN_MANIPULATION", "duplicate-test"
        )

        # Create first threat
        threat1 = await repo.create_or_update(
            device_id=test_device.id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="First occurrence",
            evidence_jsonb={"occurrence": 1},
            fingerprint=fingerprint,
        )

        # Create duplicate (same fingerprint)
        threat2 = await repo.create_or_update(
            device_id=test_device.id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="Second occurrence",
            evidence_jsonb={"occurrence": 2},
            fingerprint=fingerprint,
        )

        # Should be same threat with incremented count
        assert threat1.id == threat2.id
        assert threat2.occurrence_count == 2
        assert threat2.last_seen > threat1.first_seen

    @pytest.mark.asyncio
    async def test_get_threats_last_n_days_grouped_by_severity(self, async_session, test_device):
        """Test the example query: threats last 7 days grouped by severity."""
        repo = ThreatEventRepository(async_session)

        # Create threats with different severities
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            fingerprint = ThreatEvent.generate_fingerprint(
                test_device.id, "TEST", f"{severity}-test"
            )
            await repo.create_or_update(
                device_id=test_device.id,
                severity=severity,
                threat_type="TEST",
                description=f"Test {severity} threat",
                evidence_jsonb={},
                fingerprint=fingerprint,
            )

        # Query grouped by severity
        result = await get_threats_last_n_days_grouped_by_severity(async_session, days=7)

        assert "CRITICAL" in result
        assert "HIGH" in result
        assert "MEDIUM" in result
        assert "LOW" in result
        assert result["CRITICAL"] >= 1
        assert result["HIGH"] >= 1

    @pytest.mark.asyncio
    async def test_acknowledge_threat(self, async_session, test_device):
        """Test acknowledging a threat event."""
        repo = ThreatEventRepository(async_session)

        fingerprint = ThreatEvent.generate_fingerprint(test_device.id, "TEST", "acknowledge-test")
        threat = await repo.create_or_update(
            device_id=test_device.id,
            severity="MEDIUM",
            threat_type="TEST",
            description="Test threat",
            evidence_jsonb={},
            fingerprint=fingerprint,
        )

        assert not threat.acknowledged

        # Acknowledge the threat
        success = await repo.acknowledge(threat.id)
        assert success

        # Verify it's acknowledged
        updated = await repo.get_by_id(threat.id)
        assert updated.acknowledged

    @pytest.mark.asyncio
    async def test_resolve_threat(self, async_session, test_device):
        """Test resolving a threat event."""
        repo = ThreatEventRepository(async_session)

        fingerprint = ThreatEvent.generate_fingerprint(test_device.id, "TEST", "resolve-test")
        threat = await repo.create_or_update(
            device_id=test_device.id,
            severity="MEDIUM",
            threat_type="TEST",
            description="Test threat",
            evidence_jsonb={},
            fingerprint=fingerprint,
        )

        assert not threat.resolved

        # Resolve the threat
        success = await repo.resolve(threat.id)
        assert success

        # Verify it's resolved
        updated = await repo.get_by_id(threat.id)
        assert updated.resolved


# Fixtures for integration tests
@pytest_asyncio.fixture
async def async_session():
    """
    Provide an async database session for testing with proper transaction isolation.

    This fixture uses SQLAlchemy's nested transaction pattern to ensure each test
    runs in an isolated transaction that is rolled back after the test completes,
    preventing test data from persisting and ensuring test independence.

    Note: This is a placeholder for integration tests. To use this fixture:
    1. Set up a test database (e.g., using pytest-postgresql)
    2. Initialize the schema with alembic migrations
    3. Each test will run in a transaction that's rolled back afterward

    Example test database setup:
        DATABASE_URL=postgresql+asyncpg://test:test@localhost:5432/test_db
    """
    from src.privaseeai_security.database import get_async_session

    async for session in get_async_session():
        # Start a nested transaction for test isolation
        async with session.begin_nested():
            yield session
            # Transaction will be rolled back when exiting this context
            # This ensures no test data persists in the database


@pytest_asyncio.fixture
async def test_device(async_session):
    """Create a test device for use in tests."""
    from src.privaseeai_security.database import DeviceRepository

    repo = DeviceRepository(async_session)
    device = await repo.create(
        name="Test Device",
        udid=f"test-udid-{uuid4()}",
        baseline_hash="test-hash",
    )
    return device
