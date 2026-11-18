"""Store incident-scoped provider record identities for safe deduplication."""
from alembic import op
import sqlalchemy as sa

revision = 'd52a0f18b721'
down_revision = 'cc84e119d320'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('forensic_events', sa.Column('source_record_id', sa.String(64), nullable=True))
    op.create_index('uq_forensic_event_source_per_incident', 'forensic_events', ['incident_id', 'source_record_id'], unique=True)


def downgrade():
    op.drop_index('uq_forensic_event_source_per_incident', table_name='forensic_events')
    op.drop_column('forensic_events', 'source_record_id')
