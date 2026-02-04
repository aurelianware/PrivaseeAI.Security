"""
Repository pattern for BenefitPlan CRUD operations.

Provides async methods for managing benefit plan records with proper
separation of concerns and auditability.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import BenefitPlan
from ....domain.benefit_plans import BenefitPlanCreate, BenefitPlanUpdate


class BenefitPlanRepository:
    """
    Repository for BenefitPlan CRUD operations.

    Provides async methods for managing benefit plan records.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with an async session.

        Args:
            session: Active AsyncSession instance
        """
        self.session = session

    async def create(self, plan: BenefitPlanCreate) -> BenefitPlan:
        """
        Create a new benefit plan record.

        Args:
            plan: BenefitPlanCreate schema with plan data

        Returns:
            Created BenefitPlan instance
        """
        db_plan = BenefitPlan(
            organization_id=plan.organization_id,
            name=plan.name,
            payer_id=plan.payer_id,
            plan_type=plan.plan_type.value,
            network_type=plan.network_type.value,
            is_active=plan.is_active,
            effective_date=plan.effective_date,
            termination_date=plan.termination_date,
            deductible_individual=plan.deductible_individual,
            deductible_family=plan.deductible_family,
            out_of_pocket_max_individual=plan.out_of_pocket_max_individual,
            out_of_pocket_max_family=plan.out_of_pocket_max_family,
            office_visit_copay=plan.office_visit_copay,
            specialist_visit_copay=plan.specialist_visit_copay,
            emergency_room_copay=plan.emergency_room_copay,
            hospital_inpatient_coinsurance_percent=plan.hospital_inpatient_coinsurance_percent,
            preventive_care_covered=plan.preventive_care_covered,
            prescription_tier1_copay=plan.prescription_tier1_copay,
            prescription_tier2_copay=plan.prescription_tier2_copay,
            annual_maximum=plan.annual_maximum,
            waiting_period_months=plan.waiting_period_months,
        )
        self.session.add(db_plan)
        await self.session.commit()
        await self.session.refresh(db_plan)
        return db_plan

    async def get_by_id(self, plan_id: UUID, org_id: UUID) -> Optional[BenefitPlan]:
        """
        Get benefit plan by ID for a specific organization.

        Args:
            plan_id: UUID of the plan
            org_id: UUID of the organization

        Returns:
            BenefitPlan instance or None if not found or soft-deleted
        """
        result = await self.session.execute(
            select(BenefitPlan).where(
                and_(
                    BenefitPlan.id == plan_id,
                    BenefitPlan.organization_id == org_id,
                    BenefitPlan.deleted_at.is_(None),
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_all_active(self, org_id: UUID) -> List[BenefitPlan]:
        """
        Get all active benefit plans for an organization.

        Args:
            org_id: UUID of the organization

        Returns:
            List of active BenefitPlan instances
        """
        result = await self.session.execute(
            select(BenefitPlan)
            .where(
                and_(
                    BenefitPlan.organization_id == org_id,
                    BenefitPlan.is_active.is_(True),
                    BenefitPlan.deleted_at.is_(None),
                )
            )
            .order_by(BenefitPlan.name)
        )
        return list(result.scalars().all())

    async def update(self, plan_id: UUID, data: BenefitPlanUpdate) -> Optional[BenefitPlan]:
        """
        Update an existing benefit plan.

        Args:
            plan_id: UUID of the plan to update
            data: BenefitPlanUpdate schema with updated fields

        Returns:
            Updated BenefitPlan instance or None if not found
        """
        result = await self.session.execute(
            select(BenefitPlan).where(
                and_(BenefitPlan.id == plan_id, BenefitPlan.deleted_at.is_(None))
            )
        )
        db_plan = result.scalar_one_or_none()
        if not db_plan:
            return None

        # Update only provided fields
        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            # Convert enum values to strings
            if hasattr(value, "value"):
                value = value.value
            setattr(db_plan, field, value)

        await self.session.commit()
        await self.session.refresh(db_plan)
        return db_plan

    async def soft_delete(self, plan_id: UUID) -> bool:
        """
        Soft delete a benefit plan by setting deleted_at timestamp.

        Args:
            plan_id: UUID of the plan to delete

        Returns:
            True if deleted successfully, False if not found
        """
        result = await self.session.execute(
            select(BenefitPlan).where(
                and_(BenefitPlan.id == plan_id, BenefitPlan.deleted_at.is_(None))
            )
        )
        db_plan = result.scalar_one_or_none()
        if not db_plan:
            return False

        db_plan.deleted_at = datetime.utcnow()
        await self.session.commit()
        return True

    async def find_by_payer_and_name(
        self, payer_id: str, name: str, org_id: UUID
    ) -> Optional[BenefitPlan]:
        """
        Find a benefit plan by payer ID and name for an organization.

        Args:
            payer_id: Insurance company identifier
            name: Plan name
            org_id: Organization UUID

        Returns:
            BenefitPlan instance or None if not found
        """
        result = await self.session.execute(
            select(BenefitPlan).where(
                and_(
                    BenefitPlan.organization_id == org_id,
                    BenefitPlan.payer_id == payer_id,
                    BenefitPlan.name == name,
                    BenefitPlan.deleted_at.is_(None),
                )
            )
        )
        return result.scalar_one_or_none()
