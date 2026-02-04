"""Add benefit_plans table for insurance plan configuration

Revision ID: 002_add_benefit_plans
Revises: 001_initial_threat_persistence
Create Date: 2026-02-04

Creates:
- benefit_plans table for storing insurance benefit plan configurations
- Indexes for efficient querying by organization, payer, and active status
- Unique constraint for plan name per organization (excluding soft-deleted)
- Soft delete support via deleted_at timestamp

"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_add_benefit_plans"
down_revision: Union[str, None] = "001_initial_threat_persistence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Create benefit_plans table and related indexes.
    """
    # Create benefit_plans table
    op.create_table(
        "benefit_plans",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("payer_id", sa.String(length=255), nullable=False),
        sa.Column("plan_type", sa.String(length=50), nullable=False),
        sa.Column("network_type", sa.String(length=50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("effective_date", sa.Date(), nullable=False),
        sa.Column("termination_date", sa.Date(), nullable=True),
        # Deductibles
        sa.Column("deductible_individual", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("deductible_family", sa.Numeric(precision=10, scale=2), nullable=True),
        # Out-of-pocket maximums
        sa.Column("out_of_pocket_max_individual", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("out_of_pocket_max_family", sa.Numeric(precision=10, scale=2), nullable=True),
        # Copays
        sa.Column("office_visit_copay", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("specialist_visit_copay", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("emergency_room_copay", sa.Numeric(precision=10, scale=2), nullable=True),
        # Coinsurance
        sa.Column(
            "hospital_inpatient_coinsurance_percent",
            sa.Numeric(precision=5, scale=2),
            nullable=True,
        ),
        # Preventive care
        sa.Column(
            "preventive_care_covered",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        # Prescription tiers
        sa.Column("prescription_tier1_copay", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("prescription_tier2_copay", sa.Numeric(precision=10, scale=2), nullable=True),
        # Additional limits
        sa.Column("annual_maximum", sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column("waiting_period_months", sa.Integer(), nullable=True),
        # Audit timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Create indexes
    op.create_index(
        "idx_benefit_plans_organization_id",
        "benefit_plans",
        ["organization_id"],
    )
    op.create_index(
        "idx_benefit_plans_payer_id",
        "benefit_plans",
        ["payer_id"],
    )
    op.create_index(
        "idx_benefit_plans_is_active",
        "benefit_plans",
        ["is_active"],
    )
    op.create_index(
        "idx_benefit_plans_deleted_at",
        "benefit_plans",
        ["deleted_at"],
    )

    # Create composite index for organization and active status
    op.create_index(
        "idx_benefit_plans_org_active",
        "benefit_plans",
        ["organization_id", "is_active"],
    )

    # Create unique constraint for name per organization (excluding soft-deleted)
    op.create_index(
        "idx_benefit_plans_org_name_unique",
        "benefit_plans",
        ["organization_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    """
    Drop benefit_plans table and related indexes.
    """
    op.drop_index("idx_benefit_plans_org_name_unique", table_name="benefit_plans")
    op.drop_index("idx_benefit_plans_org_active", table_name="benefit_plans")
    op.drop_index("idx_benefit_plans_deleted_at", table_name="benefit_plans")
    op.drop_index("idx_benefit_plans_is_active", table_name="benefit_plans")
    op.drop_index("idx_benefit_plans_payer_id", table_name="benefit_plans")
    op.drop_index("idx_benefit_plans_organization_id", table_name="benefit_plans")
    op.drop_table("benefit_plans")
