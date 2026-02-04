"""
Service layer for benefit plan business logic.

Contains business rules and orchestrates repository operations.
"""

from typing import List, Optional
from uuid import UUID

from ...domain.benefit_plans import BenefitPlanCreate, BenefitPlanRead, BenefitPlanUpdate
from ...infrastructure.persistence.repositories.benefit_plan_repository import (
    BenefitPlanRepository,
)


class BenefitPlanService:
    """
    Service layer for benefit plan operations.

    Implements business rules and orchestrates data access.
    """

    def __init__(self, repository: BenefitPlanRepository):
        """
        Initialize service with repository.

        Args:
            repository: BenefitPlanRepository instance
        """
        self.repository = repository

    async def create_plan(self, plan_data: BenefitPlanCreate) -> BenefitPlanRead:
        """
        Create a new benefit plan.

        Business rules:
        - Prevents duplicate plan names per organization
        - Validates effective_date <= termination_date

        Args:
            plan_data: BenefitPlanCreate schema

        Returns:
            Created BenefitPlanRead instance

        Raises:
            ValueError: If validation fails or duplicate exists
        """
        # Check for duplicate plan name in organization
        existing = await self.repository.find_by_payer_and_name(
            payer_id=plan_data.payer_id,
            name=plan_data.name,
            org_id=plan_data.organization_id,
        )
        if existing:
            raise ValueError(
                f"Benefit plan '{plan_data.name}' with payer '{plan_data.payer_id}' "
                f"already exists for this organization"
            )

        # Validate date range
        if plan_data.termination_date and plan_data.effective_date > plan_data.termination_date:
            raise ValueError("effective_date must be on or before termination_date")

        # Create plan
        db_plan = await self.repository.create(plan_data)
        return BenefitPlanRead.model_validate(db_plan)

    async def update_plan(
        self, plan_id: UUID, org_id: UUID, update_data: BenefitPlanUpdate
    ) -> Optional[BenefitPlanRead]:
        """
        Update an existing benefit plan.

        Business rules:
        - Preserves audit timestamps
        - Validates date ranges if both dates are provided

        Args:
            plan_id: UUID of plan to update
            org_id: Organization UUID for authorization
            update_data: BenefitPlanUpdate schema with updates

        Returns:
            Updated BenefitPlanRead or None if not found

        Raises:
            ValueError: If validation fails
        """
        # Get existing plan to validate org ownership
        existing = await self.repository.get_by_id(plan_id, org_id)
        if not existing:
            return None

        # Validate date range if both are being updated or one is updated
        update_dict = update_data.model_dump(exclude_unset=True)
        effective = update_dict.get("effective_date", existing.effective_date)
        termination = update_dict.get("termination_date", existing.termination_date)

        if termination and effective and effective > termination:
            raise ValueError("effective_date must be on or before termination_date")

        # Perform update
        updated_plan = await self.repository.update(plan_id, update_data)
        if updated_plan:
            return BenefitPlanRead.model_validate(updated_plan)
        return None

    async def list_plans(self, org_id: UUID) -> List[BenefitPlanRead]:
        """
        List all active benefit plans for an organization.

        Args:
            org_id: Organization UUID

        Returns:
            List of BenefitPlanRead instances
        """
        plans = await self.repository.get_all_active(org_id)
        return [BenefitPlanRead.model_validate(plan) for plan in plans]

    async def get_plan(self, plan_id: UUID, org_id: UUID) -> Optional[BenefitPlanRead]:
        """
        Get a specific benefit plan.

        Args:
            plan_id: Plan UUID
            org_id: Organization UUID for authorization

        Returns:
            BenefitPlanRead or None if not found
        """
        plan = await self.repository.get_by_id(plan_id, org_id)
        if plan:
            return BenefitPlanRead.model_validate(plan)
        return None

    async def deactivate_plan(self, plan_id: UUID, org_id: UUID) -> bool:
        """
        Soft delete (deactivate) a benefit plan.

        Business rules:
        - For MVP, we skip checking if plan is referenced by active patients
        - In production, would prevent deletion if referenced

        Args:
            plan_id: Plan UUID to deactivate
            org_id: Organization UUID for authorization

        Returns:
            True if deactivated, False if not found

        Raises:
            ValueError: If plan is referenced by active patients (future implementation)
        """
        # Verify org ownership before deleting
        existing = await self.repository.get_by_id(plan_id, org_id)
        if not existing:
            return False

        # TODO: Check if plan is referenced by active patients
        # For now, we allow deletion
        # In production:
        # if await self._is_referenced_by_patients(plan_id):
        #     raise ValueError("Cannot delete plan that is referenced by active patients")

        return await self.repository.soft_delete(plan_id)
