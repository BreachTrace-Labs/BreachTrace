"""initial_schema

Revision ID: e70a65e1a493
Revises:
Create Date: 2026-03-29 23:31:49.359506

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e70a65e1a493'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---------------------------------------------------------------------------
    # incident_records
    # ---------------------------------------------------------------------------
    op.create_table(
        "incident_records",
        sa.Column("incident_id", sa.VARCHAR(36), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("credential_type", sa.VARCHAR(50), nullable=False),
        sa.Column("credential_hint", sa.VARCHAR(50), nullable=False),
        sa.Column("access_key_id", sa.VARCHAR(30), nullable=True),
        sa.Column("principal_arn", sa.VARCHAR(200), nullable=True),
        sa.Column("repo_url", sa.Text(), nullable=False),
        sa.Column("commit_hash", sa.VARCHAR(40), nullable=True),
        sa.Column("exposure_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("exposure_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.VARCHAR(20), nullable=False, server_default="detecting"),
        sa.Column("overall_severity", sa.Integer(), nullable=True),
        sa.Column("report_text", sa.Text(), nullable=True),
        sa.Column("remediation_steps", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("gdpr_flag", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("financial_impact", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_incident_records_credential_type", "incident_records", ["credential_type"])
    op.create_index("ix_incident_records_exposure_start", "incident_records", ["exposure_start"])
    op.create_index("ix_incident_records_status", "incident_records", ["status"])

    # ---------------------------------------------------------------------------
    # forensic_events
    # ---------------------------------------------------------------------------
    op.create_table(
        "forensic_events",
        sa.Column("event_id", sa.VARCHAR(36), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", sa.VARCHAR(36), sa.ForeignKey("incident_records.incident_id", ondelete="CASCADE"), nullable=False),
        sa.Column("platform", sa.VARCHAR(20), nullable=False, server_default="aws"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("api_action", sa.VARCHAR(100), nullable=False),
        sa.Column("event_source", sa.VARCHAR(100), nullable=True),
        sa.Column("source_ip", sa.VARCHAR(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("affected_resource", sa.Text(), nullable=True),
        sa.Column("resource_type", sa.VARCHAR(100), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("error_code", sa.VARCHAR(50), nullable=True),
        sa.Column("is_denied", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("raw_data", sa.JSON(), nullable=False),
        sa.Column("impact_category", sa.VARCHAR(50), nullable=True),
        sa.Column("severity_weight", sa.Integer(), nullable=True),
        sa.CheckConstraint("severity_weight BETWEEN 1 AND 4", name="ck_forensic_events_severity_weight"),
        sa.CheckConstraint(
            "platform IN ('aws', 'gcp', 'stripe', 'github', 'twilio', 'db', 'npm')",
            name="ck_forensic_events_platform_valid",
        ),
    )
    op.create_index("ix_forensic_events_incident_id", "forensic_events", ["incident_id"])
    op.create_index("ix_forensic_events_timestamp", "forensic_events", ["timestamp"])
    op.create_index("ix_forensic_events_impact_category", "forensic_events", ["impact_category"])

    # ---------------------------------------------------------------------------
    # collection_status
    # ---------------------------------------------------------------------------
    op.create_table(
        "collection_status",
        sa.Column("id", sa.VARCHAR(36), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", sa.VARCHAR(36), sa.ForeignKey("incident_records.incident_id", ondelete="CASCADE"), nullable=False),
        sa.Column("platform", sa.VARCHAR(20), nullable=False, server_default="aws"),
        sa.Column("status", sa.VARCHAR(20), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("queried_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "platform IN ('aws', 'gcp', 'stripe', 'github', 'twilio', 'db', 'npm')",
            name="ck_collection_status_platform_valid",
        ),
        sa.CheckConstraint(
            "status IN ('success', 'no_activity', 'error')",
            name="ck_collection_status_status_valid",
        ),
    )
    op.create_index("ix_collection_status_incident_id", "collection_status", ["incident_id"])

    # ---------------------------------------------------------------------------
    # experiment_runs
    # ---------------------------------------------------------------------------
    op.create_table(
        "experiment_runs",
        sa.Column("run_id", sa.VARCHAR(36), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("incident_id", sa.VARCHAR(36), sa.ForeignKey("incident_records.incident_id", ondelete="SET NULL"), nullable=True),
        sa.Column("run_number", sa.Integer(), nullable=False),
        sa.Column("group_label", sa.VARCHAR(1), nullable=False),
        sa.Column("access_key_id", sa.VARCHAR(30), nullable=False),
        sa.Column("commit_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_latency_ms", sa.Integer(), nullable=True),
        sa.Column("report_latency_ms", sa.Integer(), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=True),
        sa.Column("worst_category", sa.VARCHAR(50), nullable=True),
        sa.Column("overall_severity", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_experiment_runs_run_number", "experiment_runs", ["run_number"])
    op.create_index("ix_experiment_runs_incident_id", "experiment_runs", ["incident_id"])


def downgrade() -> None:
    op.drop_table("experiment_runs")
    op.drop_table("collection_status")
    op.drop_table("forensic_events")
    op.drop_table("incident_records")
