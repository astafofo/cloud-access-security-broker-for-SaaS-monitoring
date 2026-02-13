"""
Alert management API routes.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.core.models import User, Alert, AlertSeverity

router = APIRouter()


class AlertCreate(BaseModel):
    """Alert creation request."""
    title: str
    description: str
    severity: AlertSeverity
    source: str
    source_id: Optional[int] = None
    details: Optional[dict] = None


class AlertUpdate(BaseModel):
    """Alert update request."""
    status: Optional[str] = None
    assigned_to: Optional[int] = None


class AlertResponse(BaseModel):
    """Alert response model."""
    id: int
    title: str
    description: str
    severity: AlertSeverity
    source: str
    source_id: Optional[int]
    details: Optional[dict]
    status: str
    assigned_to: Optional[int]
    assignee_name: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class AlertStats(BaseModel):
    """Alert statistics."""
    total: int
    open: int
    acknowledged: int
    resolved: int
    by_severity: dict


@router.post("/", response_model=AlertResponse)
async def create_alert(
    alert_data: AlertCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new alert."""
    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        source=alert_data.source,
        source_id=alert_data.source_id,
        details=alert_data.details
    )
    
    db.add(alert)
    db.commit()
    db.refresh(alert)
    
    return alert


@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    severity: Optional[AlertSeverity] = None,
    status: Optional[str] = None,
    assigned_to: Optional[int] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get alerts with filtering."""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if status:
        query = query.filter(Alert.status == status)
    
    if assigned_to:
        query = query.filter(Alert.assigned_to == assigned_to)
    
    alerts = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit).all()
    
    # Format response with assignee names
    response = []
    for alert in alerts:
        assignee_name = None
        if alert.assignee:
            assignee_name = alert.assignee.full_name
        
        response.append({
            **alert.__dict__,
            "assignee_name": assignee_name
        })
    
    return response


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    assignee_name = None
    if alert.assignee:
        assignee_name = alert.assignee.full_name
    
    return {
        **alert.__dict__,
        "assignee_name": assignee_name
    }


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Update fields
    update_data = alert_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(alert, field, value)
    
    db.commit()
    db.refresh(alert)
    
    assignee_name = None
    if alert.assignee:
        assignee_name = alert.assignee.full_name
    
    return {
        **alert.__dict__,
        "assignee_name": assignee_name
    }


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = "acknowledged"
    alert.assigned_to = current_user.id
    
    db.commit()
    
    return {"message": "Alert acknowledged successfully"}


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Resolve an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = "resolved"
    alert.assigned_to = current_user.id
    
    db.commit()
    
    return {"message": "Alert resolved successfully"}


@router.get("/stats/summary", response_model=AlertStats)
async def get_alert_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get alert statistics."""
    total = db.query(Alert).count()
    open_count = db.query(Alert).filter(Alert.status == "open").count()
    acknowledged_count = db.query(Alert).filter(Alert.status == "acknowledged").count()
    resolved_count = db.query(Alert).filter(Alert.status == "resolved").count()
    
    # Count by severity
    severity_counts = {}
    for severity in AlertSeverity:
        count = db.query(Alert).filter(Alert.severity == severity).count()
        severity_counts[severity.value] = count
    
    return AlertStats(
        total=total,
        open=open_count,
        acknowledged=acknowledged_count,
        resolved=resolved_count,
        by_severity=severity_counts
    )
