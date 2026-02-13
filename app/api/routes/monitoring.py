"""
Monitoring API routes.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_active_user, check_permission
from app.core.models import (
    User, AccessLog, SaaSApplication, AnomalyDetection, Alert
)

router = APIRouter()


class AccessLogResponse(BaseModel):
    """Access log response model."""
    id: int
    user_id: str
    user_email: str
    action: str
    resource: Optional[str]
    ip_address: Optional[str]
    timestamp: datetime
    status_code: Optional[int]
    response_time_ms: Optional[int]
    application_name: str
    
    class Config:
        from_attributes = True


class AnomalyResponse(BaseModel):
    """Anomaly detection response model."""
    id: int
    user_id: str
    user_email: str
    anomaly_type: str
    score: int
    threshold: int
    timestamp: datetime
    is_false_positive: bool
    
    class Config:
        from_attributes = True


class MonitoringStats(BaseModel):
    """Monitoring statistics."""
    total_access_logs: int
    total_anomalies: int
    active_alerts: int
    unique_users: int
    top_applications: List[dict]


@router.get("/access-logs", response_model=List[AccessLogResponse])
async def get_access_logs(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    application_id: Optional[int] = Query(None),
    user_email: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None)
):
    """Get access logs with filtering."""
    query = db.query(AccessLog).join(SaaSApplication)
    
    # Apply filters
    if application_id:
        query = query.filter(AccessLog.application_id == application_id)
    
    if user_email:
        query = query.filter(AccessLog.user_email.ilike(f"%{user_email}%"))
    
    if start_date:
        query = query.filter(AccessLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AccessLog.timestamp <= end_date)
    
    # Order and paginate
    logs = query.order_by(desc(AccessLog.timestamp)).offset(skip).limit(limit).all()
    
    # Format response
    response = []
    for log in logs:
        response.append({
            "id": log.id,
            "user_id": log.user_id,
            "user_email": log.user_email,
            "action": log.action,
            "resource": log.resource,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp,
            "status_code": log.status_code,
            "response_time_ms": log.response_time_ms,
            "application_name": log.application.name
        })
    
    return response


@router.get("/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_email: Optional[str] = Query(None),
    anomaly_type: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None)
):
    """Get anomaly detection results."""
    query = db.query(AnomalyDetection)
    
    # Apply filters
    if user_email:
        query = query.filter(AnomalyDetection.user_email.ilike(f"%{user_email}%"))
    
    if anomaly_type:
        query = query.filter(AnomalyDetection.anomaly_type == anomaly_type)
    
    if min_score:
        query = query.filter(AnomalyDetection.score >= min_score)
    
    # Order and paginate
    anomalies = query.order_by(desc(AnomalyDetection.timestamp)).offset(skip).limit(limit).all()
    
    return anomalies


@router.get("/stats", response_model=MonitoringStats)
async def get_monitoring_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get monitoring statistics."""
    # Get counts
    total_access_logs = db.query(AccessLog).count()
    total_anomalies = db.query(AnomalyDetection).count()
    active_alerts = db.query(Alert).filter(Alert.status == "open").count()
    unique_users = db.query(AccessLog.user_email).distinct().count()
    
    # Get top applications
    top_apps = (
        db.query(
            SaaSApplication.name,
            db.func.count(AccessLog.id).label("access_count")
        )
        .join(AccessLog)
        .group_by(SaaSApplication.name)
        .order_by(desc(db.func.count(AccessLog.id)))
        .limit(5)
        .all()
    )
    
    return MonitoringStats(
        total_access_logs=total_access_logs,
        total_anomalies=total_anomalies,
        active_alerts=active_alerts,
        unique_users=unique_users,
        top_applications=[{"name": app[0], "count": app[1]} for app in top_apps]
    )


@router.get("/user-activity/{user_email}")
async def get_user_activity(
    user_email: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    days: int = Query(7, ge=1, le=90)
):
    """Get activity summary for a specific user."""
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get access logs
    access_logs = (
        db.query(AccessLog)
        .filter(
            and_(
                AccessLog.user_email == user_email,
                AccessLog.timestamp >= start_date
            )
        )
        .order_by(desc(AccessLog.timestamp))
        .limit(50)
        .all()
    )
    
    # Get anomalies
    anomalies = (
        db.query(AnomalyDetection)
        .filter(
            and_(
                AnomalyDetection.user_email == user_email,
                AnomalyDetection.timestamp >= start_date
            )
        )
        .order_by(desc(AnomalyDetection.timestamp))
        .limit(20)
        .all()
    )
    
    return {
        "user_email": user_email,
        "period_days": days,
        "access_logs": [
            {
                "action": log.action,
                "resource": log.resource,
                "timestamp": log.timestamp,
                "application": log.application.name
            }
            for log in access_logs
        ],
        "anomalies": [
            {
                "type": anomaly.anomaly_type,
                "score": anomaly.score,
                "timestamp": anomaly.timestamp
            }
            for anomaly in anomalies
        ]
    }
