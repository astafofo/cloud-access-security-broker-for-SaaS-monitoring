"""
Real-time monitoring service for SaaS applications.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc
import structlog
from celery import current_app

from app.core.database import get_db
from app.core.models import (
    SaaSApplication, AccessLog, Policy, PolicyViolation, 
    AnomalyDetection, Alert, AlertSeverity
)
from app.connectors import get_connector
from app.services.alerts import AlertService

logger = structlog.get_logger()


class MonitoringService:
    """Service for real-time monitoring of SaaS applications."""
    
    def __init__(self, db: Session):
        self.db = db
        self.alert_service = AlertService(db)
    
    async def monitor_all_applications(self):
        """Monitor all active SaaS applications."""
        applications = self.db.query(SaaSApplication).filter(SaaSApplication.is_active == True).all()
        
        for app in applications:
            try:
                await self.monitor_application(app.id)
            except Exception as e:
                logger.error(f"Failed to monitor application {app.id}", error=str(e))
    
    async def monitor_application(self, application_id: int):
        """Monitor a specific SaaS application."""
        application = self.db.query(SaaSApplication).filter(SaaSApplication.id == application_id).first()
        if not application:
            logger.error(f"Application {application_id} not found")
            return
        
        # Get connector
        connector = get_connector(application.provider, application.configuration)
        if not connector:
            logger.error(f"No connector found for provider {application.provider}")
            return
        
        # Authenticate
        if not await connector.authenticate():
            logger.error(f"Failed to authenticate with {application.provider}")
            return
        
        # Get recent logs
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=5)  # Last 5 minutes
        
        logs = await connector.get_access_logs(start_time, end_time)
        
        # Process logs
        for log in logs:
            await self.process_log_entry(log, application)
        
        logger.info(f"Processed {len(logs)} logs for {application.name}")
    
    async def process_log_entry(self, log_entry: Dict, application: SaaSApplication):
        """Process a single log entry."""
        try:
            # Store in database
            access_log = AccessLog(
                user_id=log_entry.get("user_id"),
                user_email=log_entry.get("user_email"),
                action=log_entry.get("action"),
                resource=log_entry.get("resource"),
                ip_address=log_entry.get("ip_address"),
                user_agent=log_entry.get("user_agent"),
                timestamp=log_entry.get("timestamp"),
                status_code=log_entry.get("status_code"),
                response_time_ms=log_entry.get("response_time_ms"),
                metadata=log_entry.get("metadata", {}),
                application_id=application.id
            )
            
            self.db.add(access_log)
            self.db.commit()
            
            # Check for policy violations
            await self.check_policy_violations(access_log, application)
            
            # Extract risk indicators
            risk_indicators = connector.extract_risk_indicators(log_entry)
            if risk_indicators:
                await self.handle_risk_indicators(access_log, risk_indicators)
            
        except Exception as e:
            logger.error("Failed to process log entry", error=str(e))
            self.db.rollback()
    
    async def check_policy_violations(self, access_log: AccessLog, application: SaaSApplication):
        """Check if log entry violates any policies."""
        policies = self.db.query(Policy).filter(
            and_(
                Policy.application_id == application.id,
                Policy.status == "active"
            )
        ).all()
        
        for policy in policies:
            violation = await self.evaluate_policy(policy, access_log)
            if violation:
                await self.create_policy_violation(violation, policy, access_log, application)
    
    async def evaluate_policy(self, policy: Policy, access_log: AccessLog) -> Optional[Dict]:
        """Evaluate a policy against an access log."""
        conditions = policy.conditions
        violations = []
        
        # Check each condition
        for condition_key, condition_value in conditions.items():
            if condition_key == "action":
                if isinstance(condition_value, list):
                    if access_log.action not in condition_value:
                        violations.append(f"Action {access_log.action} not in allowed list")
                elif access_log.action != condition_value:
                    violations.append(f"Action {access_log.action} violates policy")
            
            elif condition_key == "time_range":
                start_hour = condition_value.get("start", 0)
                end_hour = condition_value.get("end", 23)
                current_hour = access_log.timestamp.hour
                if not (start_hour <= current_hour <= end_hour):
                    violations.append(f"Access outside allowed time range {start_hour}-{end_hour}")
            
            elif condition_key == "ip_whitelist":
                allowed_ips = condition_value
                if access_log.ip_address not in allowed_ips:
                    violations.append(f"IP {access_log.ip_address} not in whitelist")
            
            elif condition_key == "file_size":
                max_size = condition_value.get("max_mb", 100) * 1024 * 1024
                # Extract file size from metadata if available
                file_size = access_log.metadata.get("file_size", 0)
                if file_size > max_size:
                    violations.append(f"File size {file_size} exceeds limit {max_size}")
            
            elif condition_key == "data_classification":
                # Check if accessing sensitive data
                resource = access_log.resource or ""
                if "confidential" in resource.lower() or "restricted" in resource.lower():
                    violations.append("Access to sensitive data detected")
        
        return {
            "policy_id": policy.id,
            "violations": violations,
            "severity": "high" if len(violations) > 1 else "medium"
        } if violations else None
    
    async def create_policy_violation(self, violation: Dict, policy: Policy, access_log: AccessLog, application: SaaSApplication):
        """Create a policy violation record."""
        policy_violation = PolicyViolation(
            user_id=access_log.user_id,
            user_email=access_log.user_email,
            action=access_log.action,
            violation_details=violation,
            severity=AlertSeverity.MEDIUM,
            timestamp=access_log.timestamp,
            policy_id=policy.id,
            application_id=application.id
        )
        
        self.db.add(policy_violation)
        self.db.commit()
        
        # Create alert
        await self.alert_service.create_policy_violation_alert(policy_violation, policy, access_log)
        
        logger.warning(f"Policy violation created for user {access_log.user_email}")
    
    async def handle_risk_indicators(self, access_log: AccessLog, risk_indicators: List[str]):
        """Handle detected risk indicators."""
        for indicator in risk_indicators:
            if indicator == "suspicious_ip":
                await self.alert_service.create_suspicious_ip_alert(access_log)
            elif indicator == "unusual_time":
                await self.alert_service.create_unusual_time_alert(access_log)
            elif indicator == "high_risk_action":
                await self.alert_service.create_high_risk_action_alert(access_log)
    
    async def get_user_behavior_baseline(self, user_email: str, days: int = 30) -> Dict:
        """Get behavioral baseline for a user."""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = self.db.query(AccessLog).filter(
            and_(
                AccessLog.user_email == user_email,
                AccessLog.timestamp >= start_date
            )
        ).all()
        
        if not logs:
            return {}
        
        # Calculate baseline metrics
        actions = {}
        hourly_activity = [0] * 24
        ip_addresses = set()
        
        for log in logs:
            # Action frequency
            action = log.action or "unknown"
            actions[action] = actions.get(action, 0) + 1
            
            # Hourly activity
            hour = log.timestamp.hour
            hourly_activity[hour] += 1
            
            # IP addresses
            if log.ip_address:
                ip_addresses.add(log.ip_address)
        
        return {
            "total_actions": len(logs),
            "unique_actions": len(actions),
            "action_frequency": actions,
            "hourly_activity": hourly_activity,
            "unique_ips": len(ip_addresses),
            "common_ips": list(ip_addresses)[:5],  # Top 5 IPs
            "avg_actions_per_day": len(logs) / days
        }
    
    async def detect_anomalies(self, user_email: str, current_activity: Dict) -> List[Dict]:
        """Detect anomalies in user activity."""
        baseline = await self.get_user_behavior_baseline(user_email)
        if not baseline:
            return []
        
        anomalies = []
        
        # Check for unusual action frequency
        current_action = current_activity.get("action", "unknown")
        baseline_frequency = baseline.get("action_frequency", {})
        expected_frequency = baseline_frequency.get(current_action, 0)
        
        if expected_frequency == 0 and current_action != "unknown":
            anomalies.append({
                "type": "new_action",
                "description": f"User performed new action: {current_action}",
                "severity": "medium"
            })
        
        # Check for unusual time
        current_hour = datetime.utcnow().hour
        hourly_activity = baseline.get("hourly_activity", [0] * 24)
        expected_activity = hourly_activity[current_hour]
        
        if expected_activity == 0:
            anomalies.append({
                "type": "unusual_time",
                "description": f"Activity at unusual hour: {current_hour}",
                "severity": "medium"
            })
        
        # Check for new IP address
        current_ip = current_activity.get("ip_address")
        if current_ip:
            common_ips = baseline.get("common_ips", [])
            if current_ip not in common_ips:
                anomalies.append({
                    "type": "new_ip",
                    "description": f"Activity from new IP: {current_ip}",
                    "severity": "high"
                })
        
        return anomalies


# Celery tasks
@current_app.task
async def monitor_saas_applications():
    """Celery task to monitor all SaaS applications."""
    db = next(get_db())
    try:
        service = MonitoringService(db)
        await service.monitor_all_applications()
    finally:
        db.close()


@current_app.task
async def sync_application_data(application_id: int):
    """Celery task to sync data for a specific application."""
    db = next(get_db())
    try:
        service = MonitoringService(db)
        await service.monitor_application(application_id)
    finally:
        db.close()


@current_app.task
async def check_policy_violations():
    """Celery task to check for policy violations."""
    db = next(get_db())
    try:
        service = MonitoringService(db)
        await service.monitor_all_applications()
    finally:
        db.close()


@current_app.task
async def cleanup_old_logs():
    """Celery task to cleanup old logs."""
    db = next(get_db())
    try:
        # Delete logs older than 90 days
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        # Delete old access logs
        db.query(AccessLog).filter(AccessLog.timestamp < cutoff_date).delete()
        
        # Delete resolved violations older than 90 days
        db.query(PolicyViolation).filter(
            and_(
                PolicyViolation.timestamp < cutoff_date,
                PolicyViolation.status == "resolved"
            )
        ).delete()
        
        db.commit()
        logger.info("Cleaned up old logs")
    finally:
        db.close()
