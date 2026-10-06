"""Add incident_records.report_source and the knowledge_chunks search index

report_source records who wrote a report's prose (deterministic template,
local model, or Gemini) so the UI can label it and the quality evaluation can
compare writers on real incidents.

knowledge_chunks backs the natural-language search. Embeddings are plain bytes
searched in-process, so no pgvector extension is required.

Revision ID: e8f9a0b1c2d3
Revises: d5e6f7a8b9c0
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e8f9a0b1c2d3"
down_revision: Union[str, None] = "d5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "incident_records",
        sa.Column("report_source", sa.VARCHAR(length=20), nullable=True),
    )
    op.create_table(
        "knowledge_chunks",
        sa.Column("id", sa.String(length=120), primary_key=True),
        sa.Column("source_type", sa.VARCHAR(length=10), nullable=False),
        sa.Column("source_id", sa.String(length=120), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("embedding", sa.LargeBinary(), nullable=True),
        sa.Column("content_hash", sa.VARCHAR(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "source_type IN ('kb', 'incident')", name="ck_knowledge_chunks_source_type"
        ),
    )
    op.create_index(
        "ix_knowledge_chunks_source", "knowledge_chunks", ["source_type", "source_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_knowledge_chunks_source", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")
    op.drop_column("incident_records", "report_source")
