"""Pydantic domain entities for benefit plans.

These entities define the shape of data for benefit plan operations:
- BenefitPlanCreate: Input for creating new plans
- BenefitPlanUpdate: Input for updating existing plans (all fields optional)
- BenefitPlanRead: Output representation with all fields
"""

from datetime import date, datetime
from decimal import Decimal
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import BenefitPlanType, NetworkType


class BenefitPlanBase(BaseModel):
    """Base model with common benefit plan fields."""

    name: str = Field(..., min_length=1, max_length=255, description="Plan name")
    payer_id: str = Field(..., min_length=1, max_length=255, description="Insurance company identifier")
    plan_type: BenefitPlanType = Field(..., description="Type of insurance plan")
    network_type: NetworkType = Field(..., description="Network coverage type")
    is_active: bool = Field(default=True, description="Whether the plan is active")
    effective_date: date = Field(..., description="Plan effective start date")
    termination_date: Optional[date] = Field(None, description="Plan termination date")
    
    # Deductibles
    deductible_individual: Optional[Decimal] = Field(None, ge=0, description="Individual deductible amount")
    deductible_family: Optional[Decimal] = Field(None, ge=0, description="Family deductible amount")
    
    # Out-of-pocket maximums
    out_of_pocket_max_individual: Optional[Decimal] = Field(None, ge=0, description="Individual OOP max")
    out_of_pocket_max_family: Optional[Decimal] = Field(None, ge=0, description="Family OOP max")
    
    # Copays
    office_visit_copay: Optional[Decimal] = Field(None, ge=0, description="Office visit copay")
    specialist_visit_copay: Optional[Decimal] = Field(None, ge=0, description="Specialist visit copay")
    emergency_room_copay: Optional[Decimal] = Field(None, ge=0, description="Emergency room copay")
    
    # Coinsurance
    hospital_inpatient_coinsurance_percent: Optional[Decimal] = Field(
        None, ge=0, le=100, description="Hospital inpatient coinsurance percentage (0-100)"
    )
    
    # Preventive care
    preventive_care_covered: bool = Field(default=True, description="Whether preventive care is covered")
    
    # Prescription tiers
    prescription_tier1_copay: Optional[Decimal] = Field(None, ge=0, description="Tier 1 prescription copay")
    prescription_tier2_copay: Optional[Decimal] = Field(None, ge=0, description="Tier 2 prescription copay")
    
    # Additional limits
    annual_maximum: Optional[Decimal] = Field(None, ge=0, description="Annual benefit maximum")
    waiting_period_months: Optional[int] = Field(None, ge=0, description="Waiting period in months")

    @field_validator("termination_date")
    @classmethod
    def validate_termination_date(cls, v: Optional[date], info) -> Optional[date]:
        """Validate that termination_date is after effective_date if both are set."""
        if v is not None and "effective_date" in info.data:
            effective_date = info.data["effective_date"]
            if v < effective_date:
                raise ValueError("termination_date must be on or after effective_date")
        return v


class BenefitPlanCreate(BenefitPlanBase):
    """Input model for creating a new benefit plan."""

    organization_id: UUID = Field(..., description="Organization that owns this plan")


class BenefitPlanUpdate(BaseModel):
    """Input model for updating an existing benefit plan.
    
    All fields are optional to support partial updates.
    """

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    payer_id: Optional[str] = Field(None, min_length=1, max_length=255)
    plan_type: Optional[BenefitPlanType] = None
    network_type: Optional[NetworkType] = None
    is_active: Optional[bool] = None
    effective_date: Optional[date] = None
    termination_date: Optional[date] = None
    deductible_individual: Optional[Decimal] = Field(None, ge=0)
    deductible_family: Optional[Decimal] = Field(None, ge=0)
    out_of_pocket_max_individual: Optional[Decimal] = Field(None, ge=0)
    out_of_pocket_max_family: Optional[Decimal] = Field(None, ge=0)
    office_visit_copay: Optional[Decimal] = Field(None, ge=0)
    specialist_visit_copay: Optional[Decimal] = Field(None, ge=0)
    emergency_room_copay: Optional[Decimal] = Field(None, ge=0)
    hospital_inpatient_coinsurance_percent: Optional[Decimal] = Field(None, ge=0, le=100)
    preventive_care_covered: Optional[bool] = None
    prescription_tier1_copay: Optional[Decimal] = Field(None, ge=0)
    prescription_tier2_copay: Optional[Decimal] = Field(None, ge=0)
    annual_maximum: Optional[Decimal] = Field(None, ge=0)
    waiting_period_months: Optional[int] = Field(None, ge=0)


class BenefitPlanRead(BenefitPlanBase):
    """Output model for benefit plan with all fields including timestamps."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Unique plan identifier")
    organization_id: UUID = Field(..., description="Organization that owns this plan")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    deleted_at: Optional[datetime] = Field(None, description="Soft deletion timestamp")
