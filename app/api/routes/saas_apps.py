"""
SaaS application management API routes.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, SecretStr
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.core.models import User, SaaSApplication, SaaSProvider, AccessLog

router = APIRouter()


class SaaSAppCreate(BaseModel):
    """SaaS application creation request."""
    name: str
    provider: SaaSProvider
    tenant_id: str
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None
    configuration: Optional[dict] = None


class SaaSAppUpdate(BaseModel):
    """SaaS application update request."""
    name: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None
    configuration: Optional[dict] = None
    is_active: Optional[bool] = None


class SaaSAppResponse(BaseModel):
    """SaaS application response model."""
    id: int
    name: str
    provider: SaaSProvider
    tenant_id: str
    client_id: Optional[str]
    configuration: Optional[dict]
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    last_sync: Optional[datetime]
    access_log_count: int
    
    class Config:
        from_attributes = True


class SaaSAppStats(BaseModel):
    """SaaS application statistics."""
    total_applications: int
    active_applications: int
    by_provider: dict
    total_access_logs: int
    unique_users: int


@router.post("/", response_model=SaaSAppResponse)
async def create_saas_application(
    app_data: SaaSAppCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new SaaS application configuration."""
    # Check if application with same name and provider already exists
    existing_app = db.query(SaaSApplication).filter(
        SaaSApplication.name == app_data.name,
        SaaSApplication.provider == app_data.provider
    ).first()
    
    if existing_app:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Application with this name and provider already exists"
        )
    
    # Create application
    application = SaaSApplication(
        name=app_data.name,
        provider=app_data.provider,
        tenant_id=app_data.tenant_id,
        client_id=app_data.client_id,
        client_secret=app_data.client_secret.get_secret_value() if app_data.client_secret else None,
        configuration=app_data.configuration
    )
    
    db.add(application)
    db.commit()
    db.refresh(application)
    
    # Get access log count
    access_log_count = db.query(AccessLog).filter(AccessLog.application_id == application.id).count()
    
    return {
        **application.__dict__,
        "last_sync": None,
        "access_log_count": access_log_count
    }


@router.get("/", response_model=List[SaaSAppResponse])
async def get_saas_applications(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    provider: Optional[SaaSProvider] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get SaaS applications with filtering."""
    query = db.query(SaaSApplication)
    
    if provider:
        query = query.filter(SaaSApplication.provider == provider)
    
    if is_active is not None:
        query = query.filter(SaaSApplication.is_active == is_active)
    
    applications = query.order_by(SaaSApplication.created_at.desc()).offset(skip).limit(limit).all()
    
    # Format response with additional data
    response = []
    for app in applications:
        access_log_count = db.query(AccessLog).filter(AccessLog.application_id == app.id).count()
        
        # Get last sync timestamp (simplified - in real implementation, this would be from sync logs)
        last_log = db.query(AccessLog).filter(AccessLog.application_id == app.id).order_by(AccessLog.timestamp.desc()).first()
        last_sync = last_log.timestamp if last_log else None
        
        response.append({
            **app.__dict__,
            "last_sync": last_sync,
            "access_log_count": access_log_count
        })
    
    return response


@router.get("/{app_id}", response_model=SaaSAppResponse)
async def get_saas_application(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific SaaS application."""
    application = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    access_log_count = db.query(AccessLog).filter(AccessLog.application_id == application.id).count()
    last_log = db.query(AccessLog).filter(AccessLog.application_id == application.id).order_by(AccessLog.timestamp.desc()).first()
    last_sync = last_log.timestamp if last_log else None
    
    return {
        **application.__dict__,
        "last_sync": last_sync,
        "access_log_count": access_log_count
    }


@router.put("/{app_id}", response_model=SaaSAppResponse)
async def update_saas_application(
    app_id: int,
    app_update: SaaSAppUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a SaaS application."""
    application = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    # Update fields
    update_data = app_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        if field == "client_secret" and value:
            setattr(application, field, value.get_secret_value())
        else:
            setattr(application, field, value)
    
    db.commit()
    db.refresh(application)
    
    access_log_count = db.query(AccessLog).filter(AccessLog.application_id == application.id).count()
    last_log = db.query(AccessLog).filter(AccessLog.application_id == application.id).order_by(AccessLog.timestamp.desc()).first()
    last_sync = last_log.timestamp if last_log else None
    
    return {
        **application.__dict__,
        "last_sync": last_sync,
        "access_log_count": access_log_count
    }


@router.delete("/{app_id}")
async def delete_saas_application(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a SaaS application."""
    application = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    db.delete(application)
    db.commit()
    
    return {"message": "Application deleted successfully"}


@router.post("/{app_id}/sync")
async def sync_saas_application(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Trigger synchronization for a SaaS application."""
    application = db.query(SaaSApplication).filter(SaaSApplication.id == app_id).first()
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    # Trigger sync task (simplified - in real implementation, this would queue a Celery task)
    from app.services.monitoring import sync_application_data
    sync_application_data.delay(app_id)
    
    return {"message": "Synchronization started"}


@router.get("/stats/summary", response_model=SaaSAppStats)
async def get_saas_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get SaaS applications statistics."""
    total = db.query(SaaSApplication).count()
    active = db.query(SaaSApplication).filter(SaaSApplication.is_active == True).count()
    
    # Count by provider
    provider_counts = {}
    for provider in SaaSProvider:
        count = db.query(SaaSApplication).filter(SaaSApplication.provider == provider).count()
        provider_counts[provider.value] = count
    
    # Get access log stats
    total_access_logs = db.query(AccessLog).count()
    unique_users = db.query(AccessLog.user_email).distinct().count()
    
    return SaaSAppStats(
        total_applications=total,
        active_applications=active,
        by_provider=provider_counts,
        total_access_logs=total_access_logs,
        unique_users=unique_users
    )
