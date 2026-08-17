"""Widen experiment_runs latency columns from Integer to Float

The harness measures latency to one decimal (`round(time.time() - t0, 1)`).
Posting 14.2 into an integer column raises, so POST /research/record could
never have worked against the previous schema.

Truncating to whole seconds would also be a poor trade for the paper: 1.4s ->
1s is a ~30% error, and the fastest platform is precisely the interesting
result. Research.tsx already calls .toFixed(1) on these values.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LATENCY_COLUMNS = ("detection_time_s", "report_time_s", "first_external_use_s")


def upgrade() -> None:
    for column in _LATENCY_COLUMNS:
        op.alter_column(
            "experiment_runs",
            column,
            type_=sa.Float(),
            existing_type=sa.Integer(),
            existing_nullable=True,
        )


def downgrade() -> None:
    for column in _LATENCY_COLUMNS:
        op.alter_column(
            "experiment_runs",
            column,
            type_=sa.Integer(),
            existing_type=sa.Float(),
            existing_nullable=True,
            # Postgres refuses an implicit float -> integer cast; round rather
            # than truncate so 1.6s becomes 2s, not 1s. Precision is lost either
            # way, which is the point of not going back.
            postgresql_using=f"round({column})::integer",
        )
