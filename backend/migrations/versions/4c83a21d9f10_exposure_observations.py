"""Record attributable, operator-reported credential lifecycle observations."""
from alembic import op
import sqlalchemy as sa

revision = '4c83a21d9f10'
down_revision = '7a1f43d9c208'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'exposure_observations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('incident_id', sa.String(36), sa.ForeignKey('incident_records.incident_id', ondelete='CASCADE'), nullable=False),
        sa.Column('recorded_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('kind', sa.String(30), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('source', sa.String(200), nullable=False),
        sa.Column('confidence', sa.String(20), nullable=False),
        sa.Column('credential_hint', sa.String(50), nullable=False),
        sa.CheckConstraint("kind IN ('revoked', 'rotated', 'expired', 'active', 'inconclusive')", name='ck_exposure_observation_kind'),
        sa.CheckConstraint("confidence IN ('low', 'medium', 'high')", name='ck_exposure_observation_confidence'),
    )
    op.create_index('ix_exposure_observations_incident_id', 'exposure_observations', ['incident_id'])


def downgrade():
    op.drop_index('ix_exposure_observations_incident_id', table_name='exposure_observations')
    op.drop_table('exposure_observations')
