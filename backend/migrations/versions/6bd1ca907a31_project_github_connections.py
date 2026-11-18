"""Encrypted GitHub connections configured in the application."""
from alembic import op
import sqlalchemy as sa
from migrations.schema_reconcile import ensure_table
revision = '6bd1ca907a31'
down_revision = '59e0ba3f1a22'
branch_labels = None
depends_on = None


def upgrade():
    ensure_table('project_github_connections',
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), primary_key=True),
        sa.Column('encrypted_blob', sa.Text(), nullable=False),
        sa.Column('iv', sa.String(24), nullable=False),
        sa.Column('updated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table('project_github_connections')
