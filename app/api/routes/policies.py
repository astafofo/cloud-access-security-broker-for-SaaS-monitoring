"""
Policy management API routes.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_active_user, check_permission
from app.core.models import User, Policy, SaaSApplication, PolicyViolation, PolicyStatus

router = APIRouter()


class PolicyCreate(BaseModel):
    """Policy creation request."""
    name: str
    description: Optional[str] = None
    type: str
    conditions: dict
    actions: dict
    priority: int = 5
    application_id: int


class PolicyUpdate(BaseModel):
    """Policy update request."""
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[dict] = None
    actions: Optional[dict] = None
    status: Optional[PolicyStatus] = None
    priority: Optional[int] = None


class PolicyResponse(BaseModel):
    """Policy response model."""
    id: int
    name: str
    description: Optional[str]
    type: str
    conditions: dict
    actions: dict
    status: PolicyStatus
    priority: int
    application_id: int
    application_name: str
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class PolicyViolationResponse(BaseModel):
    """Policy violation response model."""
    id: int
    user_id: str
    user_email: str
    action: str
    violation_details: dict
    severity: str
    status: str
    timestamp: datetime
    policy_name: str
    application_name: str
    
    class Config:
        from_attributes = True


@router.post("/", response_model=PolicyResponse)
async def create_policy(
    policy_data: PolicyCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new security policy."""
    # Check if application exists
    application = db.query(SaaSApplication).filter(SaaSApplication.id == policy_data.application_id).first()
    if not application:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found"
        )
    
    # Create policy
    policy = Policy(
        name=policy_data.name,
        description=policy_data.description,
        type=policy_data.type,
        conditions=policy_data.conditions,
        actions=policy_data.actions,
        priority=policy_data.priority,
        application_id=policy_data.application_id,
        created_by=current_user.id
    )
    
    db.add(policy)
    db.commit()
    db.refresh(policy)
    
    # Format response
    response = {
        **policy.__dict__,
        "application_name": application.name
    }
    
    return response


@router.get("/", response_model=List[PolicyResponse])
async def get_policies(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    application_id: Optional[int] = None,
    status: Optional[PolicyStatus] = None,
    skip: int = 0,
    limit: int = 100
):
    """Get policies with filtering."""
    query = db.query(Policy).join(SaaSApplication)
    
    if application_id:
        query = query.filter(Policy.application_id == application_id)
    
    if status:
        query = query.filter(Policy.status == status)
    
    policies = query.order_by(Policy.priority.desc(), Policy.created_at.desc()).offset(skip).limit(limit).all()
    
    # Format response
    response = []
    for policy in policies:
        response.append({
            **policy.__dict__,
            "application_name": policy.application.name
        })
    
    return response


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific policy."""
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    return {
        **policy.__dict__,
        "application_name": policy.application.name
    }


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: int,
    policy_update: PolicyUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a policy."""
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    # Update fields
    update_data = policy_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)
    
    db.commit()
    db.refresh(policy)
    
    return {
        **policy.__dict__,
        "application_name": policy.application.name
    }


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a policy."""
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    db.delete(policy)
    db.commit()
    
    return {"message": "Policy deleted successfully"}


@router.get("/{policy_id}/violations", response_model=List[PolicyViolationResponse])
async def get_policy_violations(
    policy_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """Get violations for a specific policy."""
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    violations = (
        db.query(PolicyViolation)
        .filter(PolicyViolation.policy_id == policy_id)
        .order_by(PolicyViolation.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    
    # Format response
    response = []
    for violation in violations:
        response.append({
            **violation.__dict__,
            "policy_name": violation.policy.name,
            "application_name": violation.policy.application.name
        })
    
    return response


@router.post("/{policy_id}/test")
async def test_policy(
    policy_id: int,
    test_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test a policy against sample data."""
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    # Simple policy evaluation logic
    conditions = policy.conditions
    actions = policy.actions
    
    # Evaluate conditions (simplified)
    violated = False
    for condition_key, condition_value in conditions.items():
        if condition_key in test_data:
            if isinstance(condition_value, dict):
                # Handle operators like >, <, ==
                for operator, expected_value in condition_value.items():
                    actual_value = test_data[condition_key]
                    if operator == ">" and actual_value > expected_value:
                        violated = True
                    elif operator == "<" and actual_value < expected_value:
                        violated = True
                    elif operator == "==" and actual_value == expected_value:
                        violated = True
            elif test_data[condition_key] != condition_value:
                violated = True
    
    return {
        "policy_id": policy_id,
        "test_data": test_data,
        "violated": violated,
        "actions": actions if violated else None
    }
