"""Enforce one organisation without changing existing customer data."""
from alembic import context, op
import sqlalchemy as sa

revision = "9ce72a4b631d"
down_revision = "f2b31ad59101"
branch_labels = None
depends_on = None


def upgrade():
    if not context.is_offline_mode():
        connection = op.get_bind()
        if connection.execute(sa.text("SELECT COUNT(*) FROM organisations")).scalar_one() > 1:
            raise RuntimeError(
                "BreachTrace supports one organisation per installation. "
                "This database contains multiple organisations; back it up and resolve them before migrating."
            )
    op.create_index('uq_organisation_singleton', 'organisations', [sa.text('(1)')], unique=True)


def downgrade():
    op.drop_index('uq_organisation_singleton', table_name='organisations')
