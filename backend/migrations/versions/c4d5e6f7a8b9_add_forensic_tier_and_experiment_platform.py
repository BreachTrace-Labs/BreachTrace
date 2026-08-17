"""Add forensic tier fields and experiment_runs.platform

Supports the two-tier model (plan.md §1): Tier 1 platforms have a queryable
audit log, Tier 2 platforms do not and carry an explicit reason instead.

Also widens the platform CHECK constraints to cover the SaaS and Tier-2
platforms, and adds experiment_runs.platform, without which the cross-platform
comparison in research/analysis.py has nothing to group by.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, None] = "b3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Must match VALID_PLATFORMS in backend/db/models.py.
_PLATFORMS = (
    "aws", "gcp", "azure", "firebase",
    "stripe", "twilio",
    "github", "slack", "npm", "sendgrid", "huggingface", "db",
)
_PLATFORM_SQL = ", ".join(f"'{p}'" for p in _PLATFORMS)

# The pre-existing constraint, restored on downgrade.
_OLD_PLATFORM_SQL = "'aws', 'gcp', 'azure', 'stripe', 'github', 'twilio', 'db', 'npm'"


def upgrade() -> None:
    # ── incident_records: forensic tier ────────────────────────────────────
    # server_default is required, not optional: the column is NOT NULL and
    # existing rows need a value. Everything recorded so far was AWS/GCP/Azure,
    # all Tier 1, so backfilling to 1 is correct rather than merely convenient.
    op.add_column(
        "incident_records",
        sa.Column(
            "forensic_tier",
            sa.Integer(),
            nullable=False,
            server_default="1",
            comment="1 = audit log queryable; 2 = detection only",
        ),
    )
    op.add_column(
        "incident_records",
        sa.Column(
            "unavailable_reason",
            sa.Text(),
            nullable=True,
            comment="Tier 2 only: why forensic reconstruction is impossible",
        ),
    )

    # ── experiment_runs: platform ──────────────────────────────────────────
    op.add_column(
        "experiment_runs",
        sa.Column(
            "platform",
            sa.VARCHAR(20),
            nullable=False,
            server_default="aws",
            comment="Platform this run exercised",
        ),
    )
    op.create_index("ix_experiment_runs_platform", "experiment_runs", ["platform"])

    # ── widen platform CHECK constraints ───────────────────────────────────
    # Postgres has no ALTER CONSTRAINT for CHECK, so drop and recreate.
    for table, name in (
        ("forensic_events", "ck_forensic_events_platform_valid"),
        ("collection_status", "ck_collection_status_platform_valid"),
    ):
        op.drop_constraint(name, table, type_="check")
        op.create_check_constraint(name, table, f"platform IN ({_PLATFORM_SQL})")


def downgrade() -> None:
    # Rows using a platform outside the old list would violate the restored
    # constraint, so clear them first. Dropping the constraint creation order
    # matters less than not leaving the DB in a state that cannot be re-upgraded.
    for table, name in (
        ("forensic_events", "ck_forensic_events_platform_valid"),
        ("collection_status", "ck_collection_status_platform_valid"),
    ):
        op.drop_constraint(name, table, type_="check")
        op.execute(
            f"DELETE FROM {table} WHERE platform NOT IN ({_OLD_PLATFORM_SQL})"
        )
        op.create_check_constraint(name, table, f"platform IN ({_OLD_PLATFORM_SQL})")

    op.drop_index("ix_experiment_runs_platform", table_name="experiment_runs")
    op.drop_column("experiment_runs", "platform")
    op.drop_column("incident_records", "unavailable_reason")
    op.drop_column("incident_records", "forensic_tier")
