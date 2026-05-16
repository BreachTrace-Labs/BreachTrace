"""add_gcp_azure_fields

Revision ID: b3c4d5e6f7a8
Revises: a1b2c3d4e5f6
Create Date: 2026-05-16

Adds multi-platform columns required for GCP and Azure forensic pipelines:

incident_records:
  - gcp_project_id   VARCHAR(100)  — GCP project of the leaked service account
  - azure_tenant_id  VARCHAR(50)   — Azure AD tenant
  - azure_subscription_id VARCHAR(50) — Azure subscription
  - principal_id     VARCHAR(300)  — unified identity (GCP email or Azure client ID)

forensic_events:
  - principal_id     VARCHAR(300)  — per-event identity (GCP principalEmail / Azure caller)
  - location         VARCHAR(200)  — GCP region/zone or Azure resource group

Also updates the platform CHECK constraints on forensic_events and
collection_status to include 'azure'.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # incident_records — new multi-platform columns
    # ------------------------------------------------------------------
    op.add_column(
        "incident_records",
        sa.Column("gcp_project_id", sa.VARCHAR(100), nullable=True,
                  comment="GCP project where the leaked service account lives"),
    )
    op.add_column(
        "incident_records",
        sa.Column("azure_tenant_id", sa.VARCHAR(50), nullable=True,
                  comment="Azure Active Directory tenant ID"),
    )
    op.add_column(
        "incident_records",
        sa.Column("azure_subscription_id", sa.VARCHAR(50), nullable=True,
                  comment="Azure subscription ID"),
    )
    op.add_column(
        "incident_records",
        sa.Column("principal_id", sa.VARCHAR(300), nullable=True,
                  comment="GCP service account email or Azure client ID"),
    )

    # ------------------------------------------------------------------
    # forensic_events — principal_id + location
    # ------------------------------------------------------------------
    op.add_column(
        "forensic_events",
        sa.Column("principal_id", sa.VARCHAR(300), nullable=True,
                  comment="GCP principalEmail or Azure caller field"),
    )
    op.add_column(
        "forensic_events",
        sa.Column("location", sa.VARCHAR(200), nullable=True,
                  comment="GCP region/zone or Azure resource group"),
    )

    # ------------------------------------------------------------------
    # Update platform CHECK constraint on forensic_events to add 'azure'
    # ------------------------------------------------------------------
    op.drop_constraint("ck_forensic_events_platform_valid", "forensic_events")
    op.create_check_constraint(
        "ck_forensic_events_platform_valid",
        "forensic_events",
        "platform IN ('aws', 'gcp', 'azure', 'stripe', 'github', 'twilio', 'db', 'npm')",
    )

    # ------------------------------------------------------------------
    # Update platform CHECK constraint on collection_status to add 'azure'
    # ------------------------------------------------------------------
    op.drop_constraint("ck_collection_status_platform_valid", "collection_status")
    op.create_check_constraint(
        "ck_collection_status_platform_valid",
        "collection_status",
        "platform IN ('aws', 'gcp', 'azure', 'stripe', 'github', 'twilio', 'db', 'npm')",
    )


def downgrade() -> None:
    # Restore original CHECK constraints
    op.drop_constraint("ck_collection_status_platform_valid", "collection_status")
    op.create_check_constraint(
        "ck_collection_status_platform_valid",
        "collection_status",
        "platform IN ('aws', 'gcp', 'stripe', 'github', 'twilio', 'db', 'npm')",
    )

    op.drop_constraint("ck_forensic_events_platform_valid", "forensic_events")
    op.create_check_constraint(
        "ck_forensic_events_platform_valid",
        "forensic_events",
        "platform IN ('aws', 'gcp', 'stripe', 'github', 'twilio', 'db', 'npm')",
    )

    op.drop_column("forensic_events", "location")
    op.drop_column("forensic_events", "principal_id")
    op.drop_column("incident_records", "principal_id")
    op.drop_column("incident_records", "azure_subscription_id")
    op.drop_column("incident_records", "azure_tenant_id")
    op.drop_column("incident_records", "gcp_project_id")
