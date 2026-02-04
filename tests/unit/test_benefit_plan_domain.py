"""
Unit tests for benefit plan domain models.

Tests cover:
- Pydantic model validation
- Enum types
- Field constraints
- Date validation
"""

from datetime import date, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from src.privaseeai_security.domain.benefit_plans import (
    BenefitPlanCreate,
    BenefitPlanRead,
    BenefitPlanType,
    BenefitPlanUpdate,
    NetworkType,
)


class TestBenefitPlanEnums:
    """Test benefit plan enumerations."""

    def test_benefit_plan_types(self):
        """Test all benefit plan type enum values."""
        assert BenefitPlanType.PPO.value == "PPO"
        assert BenefitPlanType.HMO.value == "HMO"
        assert BenefitPlanType.MEDICARE.value == "Medicare"
        assert BenefitPlanType.OTHER.value == "Other"

    def test_network_types(self):
        """Test all network type enum values."""
        assert NetworkType.IN_NETWORK.value == "In-Network"
        assert NetworkType.OUT_OF_NETWORK.value == "Out-of-Network"
        assert NetworkType.BOTH.value == "Both"


class TestBenefitPlanCreate:
    """Test BenefitPlanCreate model."""

    def test_minimal_valid_plan(self):
        """Test creating plan with minimal required fields."""
        org_id = uuid4()
        plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Blue Cross PPO",
            payer_id="BC001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.IN_NETWORK,
            effective_date=date(2024, 1, 1),
        )

        assert plan.organization_id == org_id
        assert plan.name == "Blue Cross PPO"
        assert plan.payer_id == "BC001"
        assert plan.plan_type == BenefitPlanType.PPO
        assert plan.network_type == NetworkType.IN_NETWORK
        assert plan.is_active is True
        assert plan.preventive_care_covered is True

    def test_full_plan_with_all_fields(self):
        """Test creating plan with all fields populated."""
        org_id = uuid4()
        plan = BenefitPlanCreate(
            organization_id=org_id,
            name="Comprehensive Plan",
            payer_id="CP001",
            plan_type=BenefitPlanType.PPO,
            network_type=NetworkType.BOTH,
            is_active=True,
            effective_date=date(2024, 1, 1),
            termination_date=date(2024, 12, 31),
            deductible_individual=Decimal("1500.00"),
            deductible_family=Decimal("3000.00"),
            out_of_pocket_max_individual=Decimal("5000.00"),
            out_of_pocket_max_family=Decimal("10000.00"),
            office_visit_copay=Decimal("25.00"),
            specialist_visit_copay=Decimal("50.00"),
            emergency_room_copay=Decimal("200.00"),
            hospital_inpatient_coinsurance_percent=Decimal("20.00"),
            preventive_care_covered=True,
            prescription_tier1_copay=Decimal("10.00"),
            prescription_tier2_copay=Decimal("30.00"),
            annual_maximum=Decimal("50000.00"),
            waiting_period_months=3,
        )

        assert plan.deductible_individual == Decimal("1500.00")
        assert plan.office_visit_copay == Decimal("25.00")
        assert plan.waiting_period_months == 3

    def test_termination_before_effective_raises_error(self):
        """Test that termination_date before effective_date raises validation error."""
        org_id = uuid4()
        with pytest.raises(ValueError, match="termination_date must be on or after effective_date"):
            BenefitPlanCreate(
                organization_id=org_id,
                name="Invalid Plan",
                payer_id="INV001",
                plan_type=BenefitPlanType.PPO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 12, 1),
                termination_date=date(2024, 1, 1),  # Before effective_date
            )

    def test_negative_amounts_rejected(self):
        """Test that negative monetary amounts are rejected."""
        org_id = uuid4()
        with pytest.raises(ValueError):
            BenefitPlanCreate(
                organization_id=org_id,
                name="Invalid Plan",
                payer_id="INV001",
                plan_type=BenefitPlanType.PPO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 1, 1),
                deductible_individual=Decimal("-100.00"),  # Negative
            )

    def test_coinsurance_over_100_rejected(self):
        """Test that coinsurance percentage over 100 is rejected."""
        org_id = uuid4()
        with pytest.raises(ValueError):
            BenefitPlanCreate(
                organization_id=org_id,
                name="Invalid Plan",
                payer_id="INV001",
                plan_type=BenefitPlanType.PPO,
                network_type=NetworkType.IN_NETWORK,
                effective_date=date(2024, 1, 1),
                hospital_inpatient_coinsurance_percent=Decimal("150.00"),  # Over 100
            )


class TestBenefitPlanUpdate:
    """Test BenefitPlanUpdate model."""

    def test_empty_update(self):
        """Test creating update with no fields."""
        update = BenefitPlanUpdate()
        assert update.model_dump(exclude_unset=True) == {}

    def test_partial_update(self):
        """Test creating update with some fields."""
        update = BenefitPlanUpdate(
            name="Updated Plan Name",
            is_active=False,
            office_visit_copay=Decimal("30.00"),
        )

        update_dict = update.model_dump(exclude_unset=True)
        assert update_dict["name"] == "Updated Plan Name"
        assert update_dict["is_active"] is False
        assert update_dict["office_visit_copay"] == Decimal("30.00")
        assert "payer_id" not in update_dict

    def test_update_with_enum_values(self):
        """Test update with enum type changes."""
        update = BenefitPlanUpdate(
            plan_type=BenefitPlanType.HMO,
            network_type=NetworkType.OUT_OF_NETWORK,
        )

        assert update.plan_type == BenefitPlanType.HMO
        assert update.network_type == NetworkType.OUT_OF_NETWORK


class TestBenefitPlanRead:
    """Test BenefitPlanRead model."""

    def test_read_model_from_attributes(self):
        """Test creating read model from ORM attributes."""

        # Simulate ORM object
        class MockORM:
            id = uuid4()
            organization_id = uuid4()
            name = "Test Plan"
            payer_id = "TEST001"
            plan_type = "PPO"
            network_type = "In-Network"
            is_active = True
            effective_date = date(2024, 1, 1)
            termination_date = None
            deductible_individual = Decimal("1000.00")
            deductible_family = None
            out_of_pocket_max_individual = None
            out_of_pocket_max_family = None
            office_visit_copay = Decimal("25.00")
            specialist_visit_copay = None
            emergency_room_copay = None
            hospital_inpatient_coinsurance_percent = None
            preventive_care_covered = True
            prescription_tier1_copay = None
            prescription_tier2_copay = None
            annual_maximum = None
            waiting_period_months = None
            created_at = datetime(2024, 1, 1, 0, 0, 0)
            updated_at = datetime(2024, 1, 1, 0, 0, 0)
            deleted_at = None

        orm_obj = MockORM()
        read_model = BenefitPlanRead.model_validate(orm_obj)

        assert read_model.id == orm_obj.id
        assert read_model.name == "Test Plan"
        assert read_model.deductible_individual == Decimal("1000.00")
        assert read_model.deleted_at is None
