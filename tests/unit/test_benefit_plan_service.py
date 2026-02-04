"""
Unit tests for benefit plan service layer.

Tests cover:
- Service business logic
- Validation rules
- Error handling
"""

from datetime import date
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from src.privaseeai_security.application.benefit_plans import BenefitPlanService
from src.privaseeai_security.database import BenefitPlan
from src.privaseeai_security.domain.benefit_plans import (
    BenefitPlanCreate,
    BenefitPlanType,
    BenefitPlanUpdate,
    NetworkType,
)


class TestBenefitPlanService:
    """Test BenefitPlanService business logic."""

    @pytest.fixture
    def mock_repository(self):
        """Fixture providing mock repository."""
        return AsyncMock()

    @pytest.fixture
    def service(self, mock_repository):
        """Fixture providing service with mock repository."""
        return BenefitPlanService(mock_repository)

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
        )

    async def test_create_plan_success(self, service, mock_repository, sample_plan_data):
        """Test successfully creating a plan."""
        # Mock no existing plan
        mock_repository.find_by_org_and_name.return_value = None

        # Mock created plan
        from datetime import datetime

        mock_plan = BenefitPlan(
            id=uuid4(),
            organization_id=sample_plan_data.organization_id,
            name=sample_plan_data.name,
            payer_id=sample_plan_data.payer_id,
            plan_type=sample_plan_data.plan_type.value,
            network_type=sample_plan_data.network_type.value,
            effective_date=sample_plan_data.effective_date,
            is_active=True,
            preventive_care_covered=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        mock_repository.create.return_value = mock_plan

        result = await service.create_plan(sample_plan_data)

        assert result.name == "Blue Cross PPO"
        mock_repository.create.assert_called_once()

    async def test_create_plan_duplicate_raises_error(
        self, service, mock_repository, sample_plan_data
    ):
        """Test that creating duplicate plan raises ValueError."""
        # Mock existing plan
        existing_plan = BenefitPlan(
            id=uuid4(),
            organization_id=sample_plan_data.organization_id,
            name=sample_plan_data.name,
            payer_id=sample_plan_data.payer_id,
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
        )
        mock_repository.find_by_org_and_name.return_value = existing_plan

        with pytest.raises(ValueError, match="already exists"):
            await service.create_plan(sample_plan_data)

        mock_repository.create.assert_not_called()

    async def test_create_plan_invalid_dates_raises_error(self, service, mock_repository):
        """Test that invalid date range raises ValueError."""
        from pydantic import ValidationError as PydanticValidationError

        mock_repository.find_by_org_and_name.return_value = None

        # This should raise a Pydantic ValidationError during model creation
        with pytest.raises(
            PydanticValidationError, match="termination_date must be on or after effective_date"
        ):
            BenefitPlanCreate(
                organization_id=uuid4(),
                name="Invalid Plan",
                payer_id="INV001",
                plan_type=BenefitPlanType.PPO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 12, 1),
                termination_date=date(2024, 1, 1),  # Before effective_date
            )

    async def test_update_plan_success(self, service, mock_repository):
        """Test successfully updating a plan."""
        from datetime import datetime

        plan_id = uuid4()
        org_id = uuid4()

        # Mock existing plan
        existing_plan = BenefitPlan(
            id=plan_id,
            organization_id=org_id,
            name="Original Name",
            payer_id="BC001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
            is_active=True,
            preventive_care_covered=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        mock_repository.get_by_id.return_value = existing_plan
        mock_repository.find_by_org_and_name.return_value = None  # No duplicate

        # Mock updated plan
        updated_plan = BenefitPlan(
            id=plan_id,
            organization_id=org_id,
            name="Updated Name",
            payer_id="BC001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
            is_active=False,
            preventive_care_covered=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        mock_repository.update.return_value = updated_plan

        update_data = BenefitPlanUpdate(name="Updated Name", is_active=False)
        result = await service.update_plan(plan_id, org_id, update_data)

        assert result is not None
        assert result.name == "Updated Name"
        mock_repository.update.assert_called_once()

    async def test_update_plan_not_found(self, service, mock_repository):
        """Test updating non-existent plan returns None."""
        plan_id = uuid4()
        org_id = uuid4()

        mock_repository.get_by_id.return_value = None

        update_data = BenefitPlanUpdate(name="Updated Name")
        result = await service.update_plan(plan_id, org_id, update_data)

        assert result is None
        mock_repository.update.assert_not_called()

    async def test_update_plan_invalid_dates_raises_error(self, service, mock_repository):
        """Test that updating with invalid dates raises ValueError."""
        plan_id = uuid4()
        org_id = uuid4()

        existing_plan = BenefitPlan(
            id=plan_id,
            organization_id=org_id,
            name="Test Plan",
            payer_id="BC001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 6, 1),
            is_active=True,
            preventive_care_covered=True,
        )
        mock_repository.get_by_id.return_value = existing_plan

        update_data = BenefitPlanUpdate(
            effective_date=date(2024, 12, 1),
            termination_date=date(2024, 1, 1),  # Before new effective_date
        )

        with pytest.raises(
            ValueError, match="effective_date must be on or before termination_date"
        ):
            await service.update_plan(plan_id, org_id, update_data)

    async def test_list_plans(self, service, mock_repository):
        """Test listing active plans."""
        from datetime import datetime

        org_id = uuid4()

        mock_plans = [
            BenefitPlan(
                id=uuid4(),
                organization_id=org_id,
                name="Plan 1",
                payer_id="P001",
                plan_type="PPO",
                network_type="In-Network",
                effective_date=date(2024, 1, 1),
                is_active=True,
                preventive_care_covered=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
            BenefitPlan(
                id=uuid4(),
                organization_id=org_id,
                name="Plan 2",
                payer_id="P002",
                plan_type="HMO",
                network_type="In-Network",
                effective_date=date(2024, 1, 1),
                is_active=True,
                preventive_care_covered=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            ),
        ]
        mock_repository.get_all_active.return_value = mock_plans

        results = await service.list_plans(org_id)

        assert len(results) == 2
        assert results[0].name == "Plan 1"
        assert results[1].name == "Plan 2"

    async def test_get_plan_success(self, service, mock_repository):
        """Test getting a specific plan."""
        from datetime import datetime

        plan_id = uuid4()
        org_id = uuid4()

        mock_plan = BenefitPlan(
            id=plan_id,
            organization_id=org_id,
            name="Test Plan",
            payer_id="TEST001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
            is_active=True,
            preventive_care_covered=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        mock_repository.get_by_id.return_value = mock_plan

        result = await service.get_plan(plan_id, org_id)

        assert result is not None
        assert result.name == "Test Plan"

    async def test_get_plan_not_found(self, service, mock_repository):
        """Test getting non-existent plan returns None."""
        plan_id = uuid4()
        org_id = uuid4()

        mock_repository.get_by_id.return_value = None

        result = await service.get_plan(plan_id, org_id)

        assert result is None

    async def test_deactivate_plan_success(self, service, mock_repository):
        """Test successfully deactivating a plan."""
        plan_id = uuid4()
        org_id = uuid4()

        mock_plan = BenefitPlan(
            id=plan_id,
            organization_id=org_id,
            name="Test Plan",
            payer_id="TEST001",
            plan_type="PPO",
            network_type="In-Network",
            effective_date=date(2024, 1, 1),
            is_active=True,
            preventive_care_covered=True,
        )
        mock_repository.get_by_id.return_value = mock_plan
        mock_repository.soft_delete.return_value = True

        result = await service.deactivate_plan(plan_id, org_id)

        assert result is True
        mock_repository.soft_delete.assert_called_once_with(plan_id, org_id)

    async def test_deactivate_plan_not_found(self, service, mock_repository):
        """Test deactivating non-existent plan returns False."""
        plan_id = uuid4()
        org_id = uuid4()

        mock_repository.get_by_id.return_value = None

        result = await service.deactivate_plan(plan_id, org_id)

        assert result is False
        mock_repository.soft_delete.assert_not_called()
