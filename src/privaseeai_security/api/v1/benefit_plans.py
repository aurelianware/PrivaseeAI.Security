"""
FastAPI router for benefit plan endpoints.

Provides REST API for managing insurance benefit plan configurations.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...application.benefit_plans import BenefitPlanService
from ...database.engine import get_async_session
from ...domain.benefit_plans import BenefitPlanCreate, BenefitPlanRead, BenefitPlanUpdate
from ...infrastructure.persistence.repositories.benefit_plan_repository import (
    BenefitPlanRepository,
)

router = APIRouter(prefix="/api/v1/benefit-plans", tags=["benefit-plans"])


# Dependency to get current organization
# In a real implementation, this would extract org_id from JWT token or session
async def get_current_organization() -> UUID:
    """
    Get current organization context from request.

    This is a stub implementation. In production, this would:
    - Extract organization from JWT token claims
    - Verify user has access to the organization
    - Return the organization UUID

    For testing purposes, returns a fixed UUID.
    """
    # TODO: Implement proper authentication and organization context
    # Example: org_id = request.state.user.organization_id
    from uuid import uuid4

    return uuid4()  # Placeholder


async def get_benefit_plan_service(
    session: AsyncSession = Depends(get_async_session),
) -> BenefitPlanService:
    """
    Dependency injection for BenefitPlanService.

    Args:
        session: Async database session

    Returns:
        BenefitPlanService instance
    """
    repository = BenefitPlanRepository(session)
    return BenefitPlanService(repository)


@router.post(
    "/",
    response_model=BenefitPlanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create new benefit plan",
)
async def create_benefit_plan(
    plan_data: BenefitPlanCreate,
    service: BenefitPlanService = Depends(get_benefit_plan_service),
) -> BenefitPlanRead:
    """
    Create a new benefit plan configuration.

    Args:
        plan_data: Benefit plan creation data
        service: Injected service instance

    Returns:
        Created benefit plan

    Raises:
        HTTPException: 400 if validation fails or duplicate exists
    """
    try:
        return await service.create_plan(plan_data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/",
    response_model=List[BenefitPlanRead],
    summary="List active benefit plans",
)
async def list_benefit_plans(
    org_id: UUID = Depends(get_current_organization),
    service: BenefitPlanService = Depends(get_benefit_plan_service),
) -> List[BenefitPlanRead]:
    """
    List all active benefit plans for current organization.

    Args:
        org_id: Current organization UUID
        service: Injected service instance

    Returns:
        List of active benefit plans
    """
    return await service.list_plans(org_id)


@router.get(
    "/{plan_id}",
    response_model=BenefitPlanRead,
    summary="Get benefit plan by ID",
)
async def get_benefit_plan(
    plan_id: UUID,
    org_id: UUID = Depends(get_current_organization),
    service: BenefitPlanService = Depends(get_benefit_plan_service),
) -> BenefitPlanRead:
    """
    Get a specific benefit plan.

    Args:
        plan_id: Plan UUID
        org_id: Current organization UUID
        service: Injected service instance

    Returns:
        Benefit plan details

    Raises:
        HTTPException: 404 if plan not found
    """
    plan = await service.get_plan(plan_id, org_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benefit plan {plan_id} not found",
        )
    return plan


@router.patch(
    "/{plan_id}",
    response_model=BenefitPlanRead,
    summary="Update benefit plan",
)
async def update_benefit_plan(
    plan_id: UUID,
    update_data: BenefitPlanUpdate,
    org_id: UUID = Depends(get_current_organization),
    service: BenefitPlanService = Depends(get_benefit_plan_service),
) -> BenefitPlanRead:
    """
    Partially update an existing benefit plan.

    Args:
        plan_id: Plan UUID to update
        update_data: Fields to update
        org_id: Current organization UUID
        service: Injected service instance

    Returns:
        Updated benefit plan

    Raises:
        HTTPException: 404 if plan not found, 400 if validation fails
    """
    try:
        updated = await service.update_plan(plan_id, org_id, update_data)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Benefit plan {plan_id} not found",
            )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete(
    "/{plan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete benefit plan",
)
async def delete_benefit_plan(
    plan_id: UUID,
    org_id: UUID = Depends(get_current_organization),
    service: BenefitPlanService = Depends(get_benefit_plan_service),
) -> None:
    """
    Soft delete a benefit plan.

    Args:
        plan_id: Plan UUID to delete
        org_id: Current organization UUID
        service: Injected service instance

    Raises:
        HTTPException: 404 if plan not found, 400 if plan is in use
    """
    try:
        deleted = await service.deactivate_plan(plan_id, org_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Benefit plan {plan_id} not found",
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
