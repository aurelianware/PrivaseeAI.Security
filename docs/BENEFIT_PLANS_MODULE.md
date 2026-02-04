# Benefit Plan Configuration Module

A production-ready benefit plan configuration system for healthcare SaaS platforms, built with modern Python practices using FastAPI, SQLAlchemy 2.0, and Pydantic v2.

## Overview

This module provides a complete solution for managing insurance benefit plan configurations in a healthcare environment. It follows domain-driven design (DDD) principles with clear separation of concerns across domain, application, infrastructure, and API layers.

## Features

- ✅ **Complete CRUD Operations**: Create, Read, Update, and soft-delete benefit plans
- ✅ **Type Safety**: Full type hints with Pydantic v2 validation
- ✅ **Async/Await**: Modern async patterns throughout with SQLAlchemy 2.0
- ✅ **Soft Deletes**: Audit-friendly soft deletion with `deleted_at` timestamps
- ✅ **Business Rules**: Duplicate prevention, date validation, organization-based access control
- ✅ **Comprehensive Testing**: 24 unit tests covering all layers
- ✅ **RESTful API**: FastAPI endpoints with proper HTTP status codes
- ✅ **Database Migrations**: Alembic migration included for schema management

## Architecture

```
src/privaseeai_security/
├── domain/benefit_plans/          # Domain models and business logic
│   ├── entities.py                # Pydantic schemas
│   └── enums.py                   # BenefitPlanType, NetworkType
├── application/benefit_plans/     # Application services
│   └── services.py                # BenefitPlanService with business rules
├── infrastructure/persistence/    # Data access layer
│   └── repositories/
│       └── benefit_plan_repository.py  # BenefitPlanRepository
└── api/v1/                        # API endpoints
    └── benefit_plans.py           # FastAPI router
```

## Data Model

### BenefitPlan Fields

**Identifiers:**
- `id` (UUID) - Unique plan identifier
- `organization_id` (UUID) - Organization owner
- `name` (str) - Plan name (unique per organization)
- `payer_id` (str) - Insurance company identifier

**Plan Configuration:**
- `plan_type` (enum) - PPO, HMO, EPO, POS, Indemnity, Medicare, Medicaid, Other
- `network_type` (enum) - In-Network, Out-of-Network, Both
- `is_active` (bool) - Active status
- `effective_date` (date) - Plan start date
- `termination_date` (date, optional) - Plan end date

**Financial Parameters:**
- Deductibles (individual, family)
- Out-of-pocket maximums (individual, family)
- Copays (office visit, specialist, emergency room)
- Coinsurance percentages
- Prescription tier copays
- Annual maximums
- Waiting periods

**Audit Fields:**
- `created_at` (datetime)
- `updated_at` (datetime)
- `deleted_at` (datetime, nullable) - Soft delete timestamp

## API Endpoints

### Create Plan
```http
POST /api/v1/benefit-plans
Content-Type: application/json

{
  "organization_id": "uuid",
  "name": "Blue Cross PPO",
  "payer_id": "BC001",
  "plan_type": "PPO",
  "network_type": "In-Network",
  "effective_date": "2024-01-01",
  "deductible_individual": 1500.00,
  "office_visit_copay": 25.00
}
```

### List Active Plans
```http
GET /api/v1/benefit-plans
```

### Get Specific Plan
```http
GET /api/v1/benefit-plans/{plan_id}
```

### Update Plan
```http
PATCH /api/v1/benefit-plans/{plan_id}
Content-Type: application/json

{
  "name": "Updated Plan Name",
  "office_visit_copay": 30.00
}
```

### Delete Plan (Soft Delete)
```http
DELETE /api/v1/benefit-plans/{plan_id}
```

## Usage Examples

### Using the Service Layer

```python
from uuid import UUID
from datetime import date
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession

from src.privaseeai_security.domain.benefit_plans import (
    BenefitPlanCreate,
    BenefitPlanType,
    NetworkType,
)
from src.privaseeai_security.application.benefit_plans import BenefitPlanService
from src.privaseeai_security.infrastructure.persistence.repositories.benefit_plan_repository import (
    BenefitPlanRepository,
)

async def create_new_plan(session: AsyncSession, org_id: UUID):
    # Initialize repository and service
    repository = BenefitPlanRepository(session)
    service = BenefitPlanService(repository)
    
    # Create plan data
    plan_data = BenefitPlanCreate(
        organization_id=org_id,
        name="Medicare Part B",
        payer_id="CMS001",
        plan_type=BenefitPlanType.MEDICARE,
        network_type=NetworkType.BOTH,
        effective_date=date(2024, 1, 1),
        deductible_individual=Decimal("226.00"),
        preventive_care_covered=True,
    )
    
    # Create plan
    plan = await service.create_plan(plan_data)
    print(f"Created plan: {plan.name} with ID {plan.id}")
    return plan
```

### Using the Repository Directly

```python
async def update_plan_copays(session: AsyncSession, plan_id: UUID):
    repository = BenefitPlanRepository(session)
    
    # Get existing plan
    plan = await repository.get_by_id(plan_id, org_id)
    
    if plan:
        # Update specific fields
        from src.privaseeai_security.domain.benefit_plans import BenefitPlanUpdate
        update_data = BenefitPlanUpdate(
            office_visit_copay=Decimal("30.00"),
            specialist_visit_copay=Decimal("60.00"),
        )
        
        updated = await repository.update(plan_id, update_data)
        print(f"Updated plan copays: {updated.name}")
```

## Database Migration

Run the migration to create the `benefit_plans` table:

```bash
# Apply migration
alembic upgrade head

# Rollback if needed
alembic downgrade -1
```

## Testing

Run all benefit plan tests:

```bash
# All tests
pytest tests/unit/test_benefit_plan*.py -v

# Domain tests only
pytest tests/unit/test_benefit_plan_domain.py -v

# Service tests only
pytest tests/unit/test_benefit_plan_service.py -v

# Repository tests (requires database)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db pytest tests/unit/test_benefit_plan_repository.py -v
```

## Business Rules

### Duplicate Prevention
- Plan names must be unique per organization (excluding soft-deleted plans)
- Combination of `organization_id` + `name` enforced by unique index

### Date Validation
- `termination_date` must be on or after `effective_date`
- Validated both at Pydantic model level and service level

### Soft Delete
- Plans are never hard-deleted from the database
- Soft deletion sets `deleted_at` timestamp
- Soft-deleted plans excluded from queries
- Unique constraint excludes soft-deleted records

### Organization Isolation
- All operations require organization context
- Cross-organization access prevented at repository level
- Organization ID verified before updates/deletes

## Security Considerations

✅ **No SQL Injection**: Parameterized queries via SQLAlchemy
✅ **Input Validation**: Pydantic v2 validation on all inputs
✅ **Type Safety**: Full type hints prevent type-related bugs
✅ **Access Control**: Organization-based isolation
✅ **Audit Trail**: Automatic timestamps on all changes
✅ **CodeQL Scanned**: Zero security vulnerabilities detected

## Dependencies

- Python 3.11+
- FastAPI 0.104+
- SQLAlchemy 2.0+
- Pydantic 2.5+
- asyncpg 0.29+
- PostgreSQL 12+

## Future Enhancements

- [ ] Patient plan associations
- [ ] Plan versioning history
- [ ] Bulk import/export functionality
- [ ] Plan comparison tools
- [ ] Benefit verification workflows
- [ ] Claims integration
- [ ] Analytics and reporting

## License

Apache-2.0

## Author

AurelianWare - PrivaseeAI Security Project
