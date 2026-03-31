"""add principal_arn to forensic_events

Revision ID: a1b2c3d4e5f6
Revises: e70a65e1a493
Create Date: 2026-03-31

The initial migration created the forensic_events table without the
principal_arn column that the ORM model defines.  This migration adds it.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "e70a65e1a493"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "forensic_events",
        sa.Column("principal_arn", sa.VARCHAR(200), nullable=True,
                  comment="IAM ARN of the actor who made this API call"),
    )


def downgrade() -> None:
    op.drop_column("forensic_events", "principal_arn")
