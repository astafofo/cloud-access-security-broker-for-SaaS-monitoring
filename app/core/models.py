"""
Database models for the CASB system.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum

from .database import Base


class UserRole(enum.Enum):
    """User roles."""
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_OFFICER = "compliance_officer"
    VIEWER = "viewer"


class AlertSeverity(enum.Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyStatus(enum.Enum):
    """Policy status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class SaaSProvider(enum.Enum):
    """SaaS providers."""
    MICROSOFT_365 = "microsoft_365"
    GOOGLE_WORKSPACE = "google_workspace"
    SALESFORCE = "salesforce"


class User(Base):
    """User model."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    
    # Foreign keys
    role_id = Column(Integer, ForeignKey("roles.id"))
    
    # Relationships
    role = relationship("Role", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")


class Role(Base):
    """Role model."""
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    users = relationship("User", back_populates="role")
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")


class Permission(Base):
    """Permission model."""
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    resource = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")


class RolePermission(Base):
    """Role-Permission association table."""
    __tablename__ = "role_permissions"
    
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), primary_key=True)


class SaaSApplication(Base):
    """SaaS application configuration."""
    __tablename__ = "saas_applications"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    provider = Column(Enum(SaaSProvider), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    client_id = Column(String(200))
    client_secret = Column(String(500))  # Encrypted
    configuration = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    access_logs = relationship("AccessLog", back_populates="application")
    policies = relationship("Policy", back_populates="application")


class AccessLog(Base):
    """Access log for SaaS applications."""
    __tablename__ = "access_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), nullable=False)  # External user ID
    user_email = Column(String(200), nullable=False)
    action = Column(String(100), nullable=False)
    resource = Column(String(200))
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    status_code = Column(Integer)
    response_time_ms = Column(Integer)
    metadata = Column(JSON)
    
    # Foreign keys
    application_id = Column(Integer, ForeignKey("saas_applications.id"))
    
    # Relationships
    application = relationship("SaaSApplication", back_populates="access_logs")


class Policy(Base):
    """Security policy."""
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    type = Column(String(50), nullable=False)  # data_transfer, authentication, compliance
    conditions = Column(JSON, nullable=False)
    actions = Column(JSON, nullable=False)  # block, alert, log
    status = Column(Enum(PolicyStatus), default=PolicyStatus.ACTIVE)
    priority = Column(Integer, default=5)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Foreign keys
    application_id = Column(Integer, ForeignKey("saas_applications.id"))
    created_by = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    application = relationship("SaaSApplication", back_populates="policies")
    creator = relationship("User")
    policy_violations = relationship("PolicyViolation", back_populates="policy")


class PolicyViolation(Base):
    """Policy violation records."""
    __tablename__ = "policy_violations"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), nullable=False)
    user_email = Column(String(200), nullable=False)
    action = Column(String(100), nullable=False)
    violation_details = Column(JSON)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM)
    status = Column(String(20), default="open")  # open, investigating, resolved
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(Integer, ForeignKey("users.id"))
    
    # Foreign keys
    policy_id = Column(Integer, ForeignKey("policies.id"))
    application_id = Column(Integer, ForeignKey("saas_applications.id"))
    
    # Relationships
    policy = relationship("Policy", back_populates="policy_violations")
    resolver = relationship("User")


class Alert(Base):
    """Security alerts."""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(Enum(AlertSeverity), nullable=False)
    source = Column(String(100), nullable=False)  # policy_violation, anomaly_detection
    source_id = Column(Integer)  # ID of the source record
    details = Column(JSON)
    status = Column(String(20), default="open")  # open, acknowledged, resolved
    assigned_to = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    assignee = relationship("User")


class AuditLog(Base):
    """Audit log for system activities."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer)
    old_values = Column(JSON)
    new_values = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Foreign keys
    user_id = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")


class AnomalyDetection(Base):
    """Anomaly detection results."""
    __tablename__ = "anomaly_detection"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), nullable=False)
    user_email = Column(String(200), nullable=False)
    anomaly_type = Column(String(100), nullable=False)
    score = Column(Integer, nullable=False)  # 0-100
    threshold = Column(Integer, nullable=False)
    features = Column(JSON)
    context = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_false_positive = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"))
    reviewed_at = Column(DateTime(timezone=True))
    
    # Relationships
    reviewer = relationship("User")
