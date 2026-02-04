"""
Unit tests for benefit plan repository.

Tests cover:
- Repository CRUD operations
- Query filtering
- Soft delete functionality
- Organization-based access control
"""

import os
from datetime import date, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from src.privaseeai_security.database import BenefitPlan
from src.privaseeai_security.domain.benefit_plans import (
    BenefitPlanCreate,
    BenefitPlanType,
    BenefitPlanUpdate,
    NetworkType,
)
from src.privaseeai_security.infrastructure.persistence.repositories.benefit_plan_repository import (
    BenefitPlanRepository,
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


class TestBenefitPlanModel:
    """Test BenefitPlan ORM model."""

    def test_model_instantiation(self):
        """Test creating BenefitPlan model instance."""
        org_id = uuid4()
        plan = BenefitPlan(
            organization_id=org_id,
            name="Test Plan",
            payer_id="TEST001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
        )

        assert plan.organization_id == org_id
        assert plan.name == "Test Plan"
        assert plan.payer_id == "TEST001"
        assert plan.plan_type == "PPO"

    def test_model_repr(self):
        """Test model string representation."""
        org_id = uuid4()
        plan = BenefitPlan(
            organization_id=org_id,
            name="Test Plan",
            payer_id="TEST001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
        )

        repr_str = repr(plan)
        assert "BenefitPlan" in repr_str
        assert "Test Plan" in repr_str


# The repository tests below require a real database connection
# They are skipped if no database is available


@skip_if_no_db
class TestBenefitPlanRepository:
    """Test BenefitPlanRepository with real database (integration tests)."""

    @pytest.fixture
    async def repository(self, db_session):
        """Fixture providing repository instance with test database session."""
        return BenefitPlanRepository(db_session)

    @pytest.fixture
    def sample_plan_data(self):
        """Fixture providing sample plan creation data."""
        return BenefitPlanCreate(
            organization_id=uuid4(),
            name="Blue Cross PPO",
            payer_id="BC001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
            deductible_individual=Decimal("1500.00"),
            office_visit_copay=Decimal("25.00"),
        )

    async def test_create_plan(self, repository, sample_plan_data):
        """Test creating a new benefit plan."""
        plan = await repository.create(sample_plan_data)

        assert plan.id is not None
        assert plan.name == "Blue Cross PPO"
        assert plan.payer_id == "BC001"
        assert plan.deductible_individual == Decimal("1500.00")
        assert plan.created_at is not None
        assert plan.deleted_at is None

    async def test_get_by_id(self, repository, sample_plan_data):
        """Test retrieving plan by ID."""
        created = await repository.create(sample_plan_data)
        retrieved = await repository.get_by_id(created.id, sample_plan_data.organization_id)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == created.name

    async def test_get_by_id_wrong_org(self, repository, sample_plan_data):
        """Test that getting plan with wrong org ID returns None."""
        created = await repository.create(sample_plan_data)
        wrong_org_id = uuid4()
        retrieved = await repository.get_by_id(created.id, wrong_org_id)

        assert retrieved is None

    async def test_get_all_active(self, repository):
        """Test retrieving all active plans for organization."""
        org_id = uuid4()

        # Create multiple plans
        plan1 = BenefitPlanCreate(
            organization_id=org_id,
            name="Plan 1",
            payer_id="P001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
            is_active=True,
        )
        plan2 = BenefitPlanCreate(
            organization_id=org_id,
            name="Plan 2",
            payer_id="P002",
            plan_type=BenefitPlanType.HMO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
            is_active=True,
        )
        plan3 = BenefitPlanCreate(
            organization_id=org_id,
            name="Plan 3",
            payer_id="P003",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
            is_active=False,  # Inactive
        )

        await repository.create(plan1)
        await repository.create(plan2)
        await repository.create(plan3)

        active_plans = await repository.get_all_active(org_id)

        assert len(active_plans) == 2
        assert all(p.is_active for p in active_plans)
        assert all(p.organization_id == org_id for p in active_plans)

    async def test_update_plan(self, repository, sample_plan_data):
        """Test updating plan fields."""
        created = await repository.create(sample_plan_data)

        update_data = BenefitPlanUpdate(
            name="Updated Plan Name",
            office_visit_copay=Decimal("30.00"),
            is_active=False,
        )

        updated = await repository.update(created.id, update_data)

        assert updated is not None
        assert updated.name == "Updated Plan Name"
        assert updated.office_visit_copay == Decimal("30.00")
        assert updated.is_active is False
        assert updated.payer_id == "BC001"  # Unchanged

    async def test_soft_delete(self, repository, sample_plan_data):
        """Test soft deleting a plan."""
        created = await repository.create(sample_plan_data)

        deleted = await repository.soft_delete(created.id)
        assert deleted is True

        # Should not be retrievable after soft delete
        retrieved = await repository.get_by_id(created.id, sample_plan_data.organization_id)
        assert retrieved is None

    async def test_soft_delete_nonexistent(self, repository):
        """Test soft deleting non-existent plan returns False."""
        fake_id = uuid4()
        deleted = await repository.soft_delete(fake_id)
        assert deleted is False

    async def test_find_by_payer_and_name(self, repository, sample_plan_data):
        """Test finding plan by payer ID and name."""
        created = await repository.create(sample_plan_data)

        found = await repository.find_by_payer_and_name(
            payer_id="BC001",
            name="Blue Cross PPO",
            org_id=sample_plan_data.organization_id,
        )

        assert found is not None
        assert found.id == created.id

    async def test_find_by_payer_and_name_not_found(self, repository, sample_plan_data):
        """Test finding non-existent plan returns None."""
        await repository.create(sample_plan_data)

        found = await repository.find_by_payer_and_name(
            payer_id="NONEXISTENT",
            name="Blue Cross PPO",
            org_id=sample_plan_data.organization_id,
        )

        assert found is None
