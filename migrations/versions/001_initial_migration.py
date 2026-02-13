"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create roles table
    op.create_table('roles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create permissions table
    op.create_table('permissions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(length=50), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create role_permissions association table
    op.create_table('role_permissions',
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )

    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=100), nullable=False),
        sa.Column('full_name', sa.String(length=100), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('role_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )

    # Create saas_applications table
    op.create_table('saas_applications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('provider', sa.Enum('MICROSOFT_365', 'GOOGLE_WORKSPACE', 'SALESFORCE', name='saasprovider'), nullable=False),
        sa.Column('tenant_id', sa.String(length=100), nullable=False),
        sa.Column('client_id', sa.String(length=200), nullable=True),
        sa.Column('client_secret', sa.String(length=500), nullable=True),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create access_logs table
    op.create_table('access_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.String(length=100), nullable=False),
        sa.Column('user_email', sa.String(length=200), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource', sa.String(length=200), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('application_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['saas_applications.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create policies table
    op.create_table('policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('actions', sa.JSON(), nullable=False),
        sa.Column('status', sa.Enum('ACTIVE', 'INACTIVE', 'DRAFT', name='policystatus'), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('application_id', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['saas_applications.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create policy_violations table
    op.create_table('policy_violations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.String(length=100), nullable=False),
        sa.Column('user_email', sa.String(length=200), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('violation_details', sa.JSON(), nullable=True),
        sa.Column('severity', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='alertseverity'), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('policy_id', sa.Integer(), nullable=True),
        sa.Column('application_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['saas_applications.id'], ),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create alerts table
    op.create_table('alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='alertseverity'), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('source_id', sa.Integer(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('assigned_to', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('old_values', sa.JSON(), nullable=True),
        sa.Column('new_values', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create anomaly_detection table
    op.create_table('anomaly_detection',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.String(length=100), nullable=False),
        sa.Column('user_email', sa.String(length=200), nullable=False),
        sa.Column('anomaly_type', sa.String(length=100), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('threshold', sa.Integer(), nullable=False),
        sa.Column('features', sa.JSON(), nullable=True),
        sa.Column('context', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('is_false_positive', sa.Boolean(), nullable=True),
        sa.Column('reviewed_by', sa.Integer(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_access_logs_timestamp', 'access_logs', ['timestamp'])
    op.create_index('ix_access_logs_user_email', 'access_logs', ['user_email'])
    op.create_index('ix_access_logs_application_id', 'access_logs', ['application_id'])
    op.create_index('ix_alerts_created_at', 'alerts', ['created_at'])
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    op.create_index('ix_alerts_status', 'alerts', ['status'])
    op.create_index('ix_policy_violations_timestamp', 'policy_violations', ['timestamp'])
    op.create_index('ix_policy_violations_user_email', 'policy_violations', ['user_email'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_policy_violations_user_email', table_name='policy_violations')
    op.drop_index('ix_policy_violations_timestamp', table_name='policy_violations')
    op.drop_index('ix_alerts_status', table_name='alerts')
    op.drop_index('ix_alerts_severity', table_name='alerts')
    op.drop_index('ix_alerts_created_at', table_name='alerts')
    op.drop_index('ix_access_logs_application_id', table_name='access_logs')
    op.drop_index('ix_access_logs_user_email', table_name='access_logs')
    op.drop_index('ix_access_logs_timestamp', table_name='access_logs')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_username', table_name='users')

    # Drop tables
    op.drop_table('anomaly_detection')
    op.drop_table('audit_logs')
    op.drop_table('alerts')
    op.drop_table('policy_violations')
    op.drop_table('policies')
    op.drop_table('access_logs')
    op.drop_table('saas_applications')
    op.drop_table('users')
    op.drop_table('role_permissions')
    op.drop_table('permissions')
    op.drop_table('roles')
