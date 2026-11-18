"""Track repeated Azure secret exposure without storing secret values."""
from alembic import op
import sqlalchemy as sa
revision = '98b31ef6b712'
down_revision = '7182cf005d3e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('incident_records', sa.Column('azure_secret_fingerprint', sa.String(64)))
    op.create_index('uq_incident_azure_secret_project', 'incident_records', ['project_id', 'azure_secret_fingerprint'], unique=True)
    op.create_table('azure_secret_occurrences',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('incident_id', sa.String(36), sa.ForeignKey('incident_records.incident_id', ondelete='CASCADE'), nullable=False),
        sa.Column('commit_hash', sa.String(40), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('incident_id', 'commit_hash', name='uq_azure_secret_occurrence_commit'))
    op.create_index('ix_azure_secret_occurrences_incident_id', 'azure_secret_occurrences', ['incident_id'])


def downgrade():
    op.drop_table('azure_secret_occurrences')
    op.drop_index('uq_incident_azure_secret_project', table_name='incident_records')
    op.drop_column('incident_records', 'azure_secret_fingerprint')
