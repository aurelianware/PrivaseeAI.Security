"""
Example usage of the async SQLAlchemy threat persistence layer.

This script demonstrates:
1. Database initialization
2. Device management
3. Threat event creation with deduplication
4. Example queries including "threats last 7 days grouped by severity"
5. Repository pattern usage

Run with:
    python examples/database_usage_example.py

Requires:
    - PostgreSQL with TimescaleDB extension
    - DATABASE_URL environment variable set (optional)
"""

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from src.privaseeai_security.database import (
    Device,
    ThreatEvent,
    DeviceRepository,
    ThreatEventRepository,
    get_async_session,
    init_db,
    get_threats_last_n_days_grouped_by_severity,
    get_device_threat_summary,
)


async def main():
    """
    Demonstrate async database operations for threat persistence.
    """
    print("=" * 70)
    print("PrivaseeAI.Security - Async SQLAlchemy Threat Persistence Demo")
    print("=" * 70)
    print()

    # Step 1: Initialize database schema (only needed once)
    print("Step 1: Initializing database schema...")
    # Note: In production, use alembic migrations instead
    # await init_db()
    print("✓ Database schema ready (use 'alembic upgrade head' in production)")
    print()

    # Step 2: Create a device
    print("Step 2: Creating a test device...")
    async for session in get_async_session():
        device_repo = DeviceRepository(session)
        
        # Check if device already exists
        device = await device_repo.get_by_udid("test-iphone-12345")
        if not device:
            device = await device_repo.create(
                name="Test iPhone 15 Pro",
                udid="test-iphone-12345",
                baseline_hash="abc123def456",
                metadata={
                    "model": "iPhone 15 Pro",
                    "ios_version": "18.2",
                    "carrier": "Verizon",
                },
            )
            print(f"✓ Created device: {device.name} (ID: {device.id})")
        else:
            print(f"✓ Found existing device: {device.name} (ID: {device.id})")
        
        device_id = device.id
        break  # Exit async generator
    print()

    # Step 3: Create threat events with deduplication
    print("Step 3: Creating threat events...")
    async for session in get_async_session():
        threat_repo = ThreatEventRepository(session)
        
        # Create first threat event
        fingerprint1 = ThreatEvent.generate_fingerprint(
            device_id=device_id,
            threat_type="VPN_MANIPULATION",
            key_indicators="tcp_fallback:protonvpn:us-ny-01",
        )
        
        threat1 = await threat_repo.create_or_update(
            device_id=device_id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="VPN forced to TCP fallback - possible blocking",
            evidence_jsonb={
                "vpn_provider": "ProtonVPN",
                "server": "us-ny-01",
                "protocol_before": "UDP",
                "protocol_after": "TCP",
                "detection_time": datetime.utcnow().isoformat(),
            },
            fingerprint=fingerprint1,
        )
        print(f"✓ Created threat event: {threat1.threat_type} (Occurrence: {threat1.occurrence_count})")
        
        # Create duplicate threat (should increment occurrence_count)
        threat1_dup = await threat_repo.create_or_update(
            device_id=device_id,
            severity="CRITICAL",
            threat_type="VPN_MANIPULATION",
            description="VPN forced to TCP fallback - possible blocking (duplicate)",
            evidence_jsonb={
                "vpn_provider": "ProtonVPN",
                "server": "us-ny-01",
                "protocol_before": "UDP",
                "protocol_after": "TCP",
                "detection_time": datetime.utcnow().isoformat(),
            },
            fingerprint=fingerprint1,  # Same fingerprint = deduplication
        )
        print(f"✓ Deduplicated threat: {threat1_dup.threat_type} (Occurrence: {threat1_dup.occurrence_count})")
        
        # Create different threat types
        fingerprint2 = ThreatEvent.generate_fingerprint(
            device_id=device_id,
            threat_type="CARRIER_COMPROMISE",
            key_indicators="localhost_routing:dns_tampering",
        )
        
        threat2 = await threat_repo.create_or_update(
            device_id=device_id,
            severity="HIGH",
            threat_type="CARRIER_COMPROMISE",
            description="Localhost routing detected in carrier bundle",
            evidence_jsonb={
                "carrier": "Verizon",
                "localhost_routes": ["127.0.0.1:8080"],
                "dns_servers": ["8.8.8.8", "1.1.1.1"],
            },
            fingerprint=fingerprint2,
        )
        print(f"✓ Created threat event: {threat2.threat_type} (Severity: {threat2.severity})")
        
        fingerprint3 = ThreatEvent.generate_fingerprint(
            device_id=device_id,
            threat_type="API_ABUSE",
            key_indicators="location_api:rate_limited",
        )
        
        threat3 = await threat_repo.create_or_update(
            device_id=device_id,
            severity="MEDIUM",
            threat_type="API_ABUSE",
            description="Location API rate limiting detected",
            evidence_jsonb={
                "api_endpoint": "/api/location",
                "request_count": 150,
                "rate_limit": 100,
                "time_window": "1 hour",
            },
            fingerprint=fingerprint3,
        )
        print(f"✓ Created threat event: {threat3.threat_type} (Severity: {threat3.severity})")
        
        break  # Exit async generator
    print()

    # Step 4: Query threats last 7 days grouped by severity (REQUIRED EXAMPLE)
    print("Step 4: Querying threats last 7 days grouped by severity...")
    async for session in get_async_session():
        severity_counts = await get_threats_last_n_days_grouped_by_severity(
            session, days=7
        )
        print("Threat counts by severity (last 7 days):")
        for severity, count in severity_counts.items():
            print(f"  {severity:10s}: {count}")
        break
    print()

    # Step 5: Get device threat summary
    print("Step 5: Getting device threat summary...")
    async for session in get_async_session():
        summary = await get_device_threat_summary(session, str(device_id))
        print(f"Device: {summary['device_name']} (UDID: {summary['device_udid']})")
        print(f"  Total threats: {summary['total_threats']}")
        print(f"  Unresolved: {summary['unresolved_count']}")
        print(f"  Resolved: {summary['resolved_count']}")
        print(f"  Severity breakdown: {summary['severity_breakdown']}")
        if summary.get('most_recent_threat'):
            recent = summary['most_recent_threat']
            print(f"  Most recent: {recent['threat_type']} ({recent['severity']}) at {recent['timestamp']}")
        break
    print()

    # Step 6: Demonstrate repository methods
    print("Step 6: Using repository methods...")
    async for session in get_async_session():
        threat_repo = ThreatEventRepository(session)
        device_repo = DeviceRepository(session)
        
        # List all threats for device
        threats = await threat_repo.list_by_device(device_id, unresolved_only=True)
        print(f"✓ Found {len(threats)} unresolved threats for device")
        
        # Acknowledge a threat
        if threats:
            await threat_repo.acknowledge(threats[0].id)
            print(f"✓ Acknowledged threat: {threats[0].threat_type}")
        
        # Update device last_seen
        await device_repo.update_last_seen(device_id)
        print(f"✓ Updated device last_seen timestamp")
        
        # List all devices
        devices = await device_repo.list_all(limit=10)
        print(f"✓ Total devices in database: {len(devices)}")
        
        break
    print()

    print("=" * 70)
    print("Demo completed successfully!")
    print()
    print("Next steps:")
    print("1. Run alembic migrations: alembic upgrade head")
    print("2. Set DATABASE_URL environment variable")
    print("3. Integrate with threat detection monitors")
    print("4. Set up TimescaleDB retention policies")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
