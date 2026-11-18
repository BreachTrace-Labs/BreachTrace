"""Store operator-reported GCP key association without private key material."""
from alembic import op
import sqlalchemy as sa
from migrations.schema_reconcile import ensure_table

revision = '59e0ba3f1a22'
down_revision = '4c83a21d9f10'
branch_labels = None
depends_on = None


def upgrade():
    ensure_table('gcp_key_associations',
        sa.Column('incident_id', sa.String(36), sa.ForeignKey('incident_records.incident_id', ondelete='CASCADE'), primary_key=True),
        sa.Column('key_digest', sa.String(64), nullable=False),
        sa.Column('key_hint', sa.String(20), nullable=False),
        sa.Column('recorded_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table('gcp_key_associations')
