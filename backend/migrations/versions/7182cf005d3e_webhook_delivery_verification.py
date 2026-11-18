"""Track signed webhook deliveries independently of registration."""
from alembic import op
import sqlalchemy as sa
revision = '7182cf005d3e'
down_revision = '6bd1ca907a31'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('projects', sa.Column('webhook_last_verified_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('projects', 'webhook_last_verified_at')
