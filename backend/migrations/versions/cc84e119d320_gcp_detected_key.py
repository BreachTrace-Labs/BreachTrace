"""Track whether a GCP key association came from detection or an operator."""
from alembic import op
import sqlalchemy as sa

revision = 'cc84e119d320'
down_revision = '98b31ef6b712'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('gcp_key_associations') as batch:
        batch.add_column(sa.Column('source', sa.String(30), nullable=False, server_default='operator_reported'))
        batch.alter_column('recorded_by', existing_type=sa.String(36), nullable=True)


def downgrade():
    # Automatic associations have no operator; they cannot fit the old schema.
    op.execute("DELETE FROM gcp_key_associations WHERE recorded_by IS NULL")
    with op.batch_alter_table('gcp_key_associations') as batch:
        batch.alter_column('recorded_by', existing_type=sa.String(36), nullable=False)
        batch.drop_column('source')
