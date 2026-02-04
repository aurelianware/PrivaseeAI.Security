"""
Example script demonstrating the Benefit Plan Configuration Module.

This script shows how to:
1. Initialize the database
2. Create benefit plans
3. Query and update plans
4. Handle business logic validation

To run this example:
    python examples/benefit_plan_example.py
"""

import asyncio
from datetime import date
from decimal import Decimal
from uuid import uuid4

from src.privaseeai_security.application.benefit_plans import BenefitPlanService
from src.privaseeai_security.database import init_db
from src.privaseeai_security.database.engine import get_async_session
from src.privaseeai_security.domain.benefit_plans import (
    BenefitPlanCreate,
    BenefitPlanType,
    BenefitPlanUpdate,
    NetworkType,
)
from src.privaseeai_security.infrastructure.persistence.repositories.benefit_plan_repository import (
    BenefitPlanRepository,
)


async def example_create_plans():
    """Example: Create multiple benefit plans for an organization."""
    print("\n" + "=" * 60)
    print("Example 1: Creating Benefit Plans")
    print("=" * 60)

    org_id = uuid4()
    print(f"Organization ID: {org_id}")

    # Get database session
    async for session in get_async_session():
        repository = BenefitPlanRepository(session)
        service = BenefitPlanService(repository)

        # Create a PPO plan
        print("\n📋 Creating Blue Cross PPO Plan...")
        ppo_plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Blue Cross PPO Gold",
            payer_id="BC001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.BOTH,
            effective_date=date(2024, 1, 1),
            termination_date=date(2024, 12, 31),
            deductible_individual=Decimal("1500.00"),
            deductible_family=Decimal("3000.00"),
            out_of_pocket_max_individual=Decimal("5000.00"),
            out_of_pocket_max_family=Decimal("10000.00"),
            office_visit_copay=Decimal("25.00"),
            specialist_visit_copay=Decimal("50.00"),
            emergency_room_copay=Decimal("200.00"),
            preventive_care_covered=True,
            prescription_tier1_copay=Decimal("10.00"),
            prescription_tier2_copay=Decimal("30.00"),
        )

        created_ppo = await service.create_plan(ppo_plan)
        print(f"✅ Created: {created_ppo.name} (ID: {created_ppo.id})")
        print(f"   - Deductible: ${created_ppo.deductible_individual}")
        print(f"   - Office Visit Copay: ${created_ppo.office_visit_copay}")

        # Create an HMO plan
        print("\n📋 Creating Kaiser HMO Plan...")
        hmo_plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Kaiser HMO Silver",
            payer_id="KP001",
            plan_type=BenefitPlanType.HMO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
            deductible_individual=Decimal("500.00"),
            deductible_family=Decimal("1000.00"),
            office_visit_copay=Decimal("20.00"),
            specialist_visit_copay=Decimal("40.00"),
            preventive_care_covered=True,
        )

        created_hmo = await service.create_plan(hmo_plan)
        print(f"✅ Created: {created_hmo.name} (ID: {created_hmo.id})")
        print(f"   - Deductible: ${created_hmo.deductible_individual}")
        print(f"   - Office Visit Copay: ${created_hmo.office_visit_copay}")

        # Create a Medicare plan
        print("\n📋 Creating Medicare Part B Plan...")
        medicare_plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Medicare Part B",
            payer_id="CMS001",
            plan_type=BenefitPlanType.MEDICARE,
            network_type=NetworkType.BOTH,
            effective_date=date(2024, 1, 1),
            deductible_individual=Decimal("226.00"),
            hospital_inpatient_coinsurance_percent=Decimal("20.00"),
            preventive_care_covered=True,
        )

        created_medicare = await service.create_plan(medicare_plan)
        print(f"✅ Created: {created_medicare.name} (ID: {created_medicare.id})")

        return org_id, created_ppo.id, created_hmo.id, created_medicare.id


async def example_list_and_filter():
    """Example: List and filter benefit plans."""
    print("\n" + "=" * 60)
    print("Example 2: Listing Active Plans")
    print("=" * 60)

    # Reuse org_id from previous example
    org_id, ppo_id, hmo_id, medicare_id = await example_create_plans()

    async for session in get_async_session():
        repository = BenefitPlanRepository(session)
        service = BenefitPlanService(repository)

        # List all active plans
        print("\n📋 Listing all active plans...")
        plans = await service.list_plans(org_id)

        print(f"\nFound {len(plans)} active plans:")
        for plan in plans:
            print(f"  - {plan.name} ({plan.plan_type.value})")
            print(f"    Payer: {plan.payer_id}")
            print(f"    Active: {plan.is_active}")


async def example_update_plan():
    """Example: Update a benefit plan."""
    print("\n" + "=" * 60)
    print("Example 3: Updating a Plan")
    print("=" * 60)

    org_id, ppo_id, _, _ = await example_create_plans()

    async for session in get_async_session():
        repository = BenefitPlanRepository(session)
        service = BenefitPlanService(repository)

        # Get the current plan
        current_plan = await service.get_plan(ppo_id, org_id)
        print(f"\n📋 Current plan: {current_plan.name}")
        print(f"   - Office Visit Copay: ${current_plan.office_visit_copay}")
        print(f"   - Specialist Copay: ${current_plan.specialist_visit_copay}")

        # Update copays
        print("\n🔄 Updating copays...")
        update_data = BenefitPlanUpdate(
            office_visit_copay=Decimal("30.00"),
            specialist_visit_copay=Decimal("60.00"),
        )

        updated_plan = await service.update_plan(ppo_id, org_id, update_data)
        print(f"✅ Updated: {updated_plan.name}")
        print(f"   - New Office Visit Copay: ${updated_plan.office_visit_copay}")
        print(f"   - New Specialist Copay: ${updated_plan.specialist_visit_copay}")


async def example_validation():
    """Example: Business rule validation."""
    print("\n" + "=" * 60)
    print("Example 4: Business Rule Validation")
    print("=" * 60)

    org_id = uuid4()

    async for session in get_async_session():
        repository = BenefitPlanRepository(session)
        service = BenefitPlanService(repository)

        # Try to create a plan with invalid dates
        print("\n⚠️  Attempting to create plan with invalid dates...")
        try:
            invalid_plan = BenefitPlanCreate(
                organization_id=org_id,
                name="Invalid Plan",
                payer_id="INV001",
                plan_type=BenefitPlanType.PPO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 12, 1),
                termination_date=date(2024, 1, 1),  # Before effective_date!
            )
            await service.create_plan(invalid_plan)
        except Exception as e:
            print(f"❌ Validation failed (as expected): {e}")

        # Create first plan
        print("\n✅ Creating first plan...")
        first_plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Duplicate Test Plan",
            payer_id="DUP001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
        )
        await service.create_plan(first_plan)
        print("   Plan created successfully")

        # Try to create duplicate
        print("\n⚠️  Attempting to create duplicate plan...")
        try:
            duplicate_plan = BenefitPlanCreate(
                organization_id=org_id,
                name="Duplicate Test Plan",  # Same name, same payer
                payer_id="DUP001",
                plan_type=BenefitPlanType.HMO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 1, 1),
            )
            await service.create_plan(duplicate_plan)
        except ValueError as e:
            print(f"❌ Duplicate prevention worked: {e}")


async def example_soft_delete():
    """Example: Soft delete a plan."""
    print("\n" + "=" * 60)
    print("Example 5: Soft Delete")
    print("=" * 60)

    org_id, ppo_id, _, _ = await example_create_plans()

    async for session in get_async_session():
        repository = BenefitPlanRepository(session)
        service = BenefitPlanService(repository)

        # Get plan before deletion
        plan = await service.get_plan(ppo_id, org_id)
        print(f"\n📋 Plan before deletion: {plan.name}")
        print(f"   Deleted at: {plan.deleted_at}")

        # Soft delete
        print("\n🗑️  Soft deleting plan...")
        deleted = await service.deactivate_plan(ppo_id, org_id)
        print(f"✅ Deletion successful: {deleted}")

        # Try to get deleted plan
        print("\n🔍 Attempting to retrieve deleted plan...")
        deleted_plan = await service.get_plan(ppo_id, org_id)
        if deleted_plan is None:
            print("❌ Plan not found (correctly filtered out)")
        else:
            print(f"⚠️  Plan still accessible: {deleted_plan.name}")


async def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("BENEFIT PLAN CONFIGURATION MODULE - EXAMPLES")
    print("=" * 60)

    # Initialize database (creates tables if they don't exist)
    print("\n🔧 Initializing database...")
    try:
        await init_db()
        print("✅ Database initialized")
    except Exception as e:
        print(f"⚠️  Database already initialized or error: {e}")

    # Run examples
    try:
        await example_create_plans()
        await example_list_and_filter()
        await example_update_plan()
        await example_validation()
        await example_soft_delete()

        print("\n" + "=" * 60)
        print("✅ All examples completed successfully!")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
