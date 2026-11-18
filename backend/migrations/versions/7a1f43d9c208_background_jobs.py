"""Persist background work and notification delivery outcomes."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = '7a1f43d9c208'
down_revision = '9ce72a4b631d'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'background_jobs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('kind', sa.String(40), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=True),
        sa.Column('payload', JSONB(), nullable=False),
        sa.Column('result', JSONB(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='queued'),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_attempts', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('available_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('lease_until', sa.DateTime(timezone=True)),
        sa.Column('lease_token', sa.String(36)),
        sa.Column('last_error', sa.String(300)),
        sa.Column('dedupe_key', sa.String(160), unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('queued','running','complete','failed')", name='ck_background_job_status'),
    )
    op.create_index('ix_background_jobs_project_id', 'background_jobs', ['project_id'])
    op.create_index('ix_background_jobs_due', 'background_jobs', ['status', 'available_at'])


def downgrade():
    op.drop_table('background_jobs')
