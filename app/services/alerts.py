"""
Alert service for managing security alerts and notifications.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc
import structlog
import json
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from app.core.models import Alert, User, PolicyViolation, AccessLog, AlertSeverity
from app.core.config import settings

logger = structlog.get_logger()


class AlertService:
    """Service for managing security alerts and notifications."""
    
    def __init__(self, db: Session):
        self.db = db
        self.slack_client = None
        if settings.SLACK_BOT_TOKEN:
            self.slack_client = WebClient(token=settings.SLACK_BOT_TOKEN)
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        source_id: Optional[int] = None,
        details: Optional[Dict] = None
    ) -> Alert:
        """Create a new security alert."""
        alert = Alert(
            title=title,
            description=description,
            severity=severity,
            source=source,
            source_id=source_id,
            details=details or {}
        )
        
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        
        # Send notifications
        await self.send_alert_notifications(alert)
        
        logger.info(f"Created alert: {title} (Severity: {severity.value})")
        return alert
    
    async def create_policy_violation_alert(
        self,
        violation: PolicyViolation,
        policy,
        access_log: AccessLog
    ):
        """Create an alert for policy violation."""
        title = f"Policy Violation: {policy.name}"
        description = f"User {access_log.user_email} violated policy '{policy.name}' with action '{access_log.action}'"
        
        severity = AlertSeverity.HIGH
        if violation.severity == "high":
            severity = AlertSeverity.CRITICAL
        elif violation.severity == "low":
            severity = AlertSeverity.MEDIUM
        
        details = {
            "policy_id": policy.id,
            "policy_name": policy.name,
            "user_email": access_log.user_email,
            "action": access_log.action,
            "resource": access_log.resource,
            "ip_address": access_log.ip_address,
            "timestamp": access_log.timestamp.isoformat(),
            "violations": violation.violation_details
        }
        
        await self.create_alert(
            title=title,
            description=description,
            severity=severity,
            source="policy_violation",
            source_id=violation.id,
            details=details
        )
    
    async def create_suspicious_ip_alert(self, access_log: AccessLog):
        """Create an alert for suspicious IP address."""
        title = f"Suspicious IP Address Detected: {access_log.ip_address}"
        description = f"User {access_log.user_email} accessed from suspicious IP address {access_log.ip_address}"
        
        details = {
            "user_email": access_log.user_email,
            "ip_address": access_log.ip_address,
            "action": access_log.action,
            "resource": access_log.resource,
            "timestamp": access_log.timestamp.isoformat()
        }
        
        await self.create_alert(
            title=title,
            description=description,
            severity=AlertSeverity.MEDIUM,
            source="suspicious_ip",
            source_id=access_log.id,
            details=details
        )
    
    async def create_unusual_time_alert(self, access_log: AccessLog):
        """Create an alert for unusual access time."""
        title = f"Unusual Access Time: {access_log.user_email}"
        description = f"User {access_log.user_email} accessed resources at unusual time: {access_log.timestamp}"
        
        details = {
            "user_email": access_log.user_email,
            "access_time": access_log.timestamp.isoformat(),
            "action": access_log.action,
            "resource": access_log.resource,
            "ip_address": access_log.ip_address
        }
        
        await self.create_alert(
            title=title,
            description=description,
            severity=AlertSeverity.MEDIUM,
            source="unusual_time",
            source_id=access_log.id,
            details=details
        )
    
    async def create_high_risk_action_alert(self, access_log: AccessLog):
        """Create an alert for high-risk action."""
        title = f"High-Risk Action Detected: {access_log.action}"
        description = f"User {access_log.user_email} performed high-risk action: {access_log.action}"
        
        details = {
            "user_email": access_log.user_email,
            "action": access_log.action,
            "resource": access_log.resource,
            "ip_address": access_log.ip_address,
            "timestamp": access_log.timestamp.isoformat()
        }
        
        await self.create_alert(
            title=title,
            description=description,
            severity=AlertSeverity.HIGH,
            source="high_risk_action",
            source_id=access_log.id,
            details=details
        )
    
    async def create_dlp_alert(self, access_log: AccessLog, violation: Dict):
        """Create an alert for DLP violation."""
        title = f"DLP Violation Detected: {access_log.user_email}"
        description = f"User {access_log.user_email} triggered DLP violation with risk score {violation['risk_score']}"
        
        severity = AlertSeverity.CRITICAL if violation['risk_score'] >= 90 else AlertSeverity.HIGH
        
        details = {
            "user_email": access_log.user_email,
            "risk_score": violation['risk_score'],
            "violations": violation['violations'],
            "action_taken": violation['action_taken'],
            "action": access_log.action,
            "resource": access_log.resource,
            "timestamp": access_log.timestamp.isoformat()
        }
        
        await self.create_alert(
            title=title,
            description=description,
            severity=severity,
            source="dlp_violation",
            source_id=access_log.id,
            details=details
        )
    
    async def send_alert_notifications(self, alert: Alert):
        """Send notifications for an alert."""
        try:
            # Send Slack notification
            if self.slack_client:
                await self.send_slack_notification(alert)
            
            # Send email notification (placeholder for email service)
            await self.send_email_notification(alert)
            
        except Exception as e:
            logger.error(f"Failed to send notifications for alert {alert.id}", error=str(e))
    
    async def send_slack_notification(self, alert: Alert):
        """Send alert notification to Slack."""
        if not self.slack_client:
            return
        
        try:
            # Determine color based on severity
            color_map = {
                AlertSeverity.LOW: "good",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.HIGH: "danger",
                AlertSeverity.CRITICAL: "#ff0000"
            }
            
            color = color_map.get(alert.severity, "warning")
            
            # Create attachment
            attachment = {
                "color": color,
                "title": alert.title,
                "text": alert.description,
                "fields": [
                    {
                        "title": "Severity",
                        "value": alert.severity.value.upper(),
                        "short": True
                    },
                    {
                        "title": "Source",
                        "value": alert.source,
                        "short": True
                    },
                    {
                        "title": "Time",
                        "value": alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True
                    }
                ],
                "footer": "CASB Security Alert",
                "ts": int(alert.created_at.timestamp())
            }
            
            # Add details if available
            if alert.details:
                for key, value in alert.details.items():
                    if key not in ["user_email", "ip_address"]:
                        attachment["fields"].append({
                            "title": key.replace("_", " ").title(),
                            "value": str(value),
                            "short": True
                        })
            
            # Send message
            response = self.slack_client.chat_postMessage(
                channel=settings.SLACK_CHANNEL,
                text=f"🚨 Security Alert: {alert.title}",
                attachments=[attachment]
            )
            
            logger.info(f"Slack notification sent for alert {alert.id}")
            
        except SlackApiError as e:
            logger.error(f"Slack API error for alert {alert.id}", error=str(e))
    
    async def send_email_notification(self, alert: Alert):
        """Send email notification for alert (placeholder)."""
        # This would integrate with an email service like SendGrid, SES, etc.
        logger.info(f"Email notification would be sent for alert {alert.id}")
        
        # Placeholder for email implementation
        # email_service.send_alert_email(
        #     to=security_team_emails,
        #     subject=alert.title,
        #     body=alert.description,
        #     details=alert.details
        # )
    
    async def get_alert_statistics(self, days: int = 30) -> Dict:
        """Get alert statistics for the last N days."""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        total_alerts = self.db.query(Alert).filter(Alert.created_at >= start_date).count()
        
        # Count by severity
        severity_counts = {}
        for severity in AlertSeverity:
            count = self.db.query(Alert).filter(
                and_(
                    Alert.created_at >= start_date,
                    Alert.severity == severity
                )
            ).count()
            severity_counts[severity.value] = count
        
        # Count by status
        status_counts = {}
        for status in ["open", "acknowledged", "resolved"]:
            count = self.db.query(Alert).filter(
                and_(
                    Alert.created_at >= start_date,
                    Alert.status == status
                )
            ).count()
            status_counts[status] = count
        
        # Count by source
        source_counts = {}
        sources = self.db.query(Alert.source, func.count(Alert.id)).filter(
            Alert.created_at >= start_date
        ).group_by(Alert.source).all()
        
        for source, count in sources:
            source_counts[source] = count
        
        return {
            "total_alerts": total_alerts,
            "by_severity": severity_counts,
            "by_status": status_counts,
            "by_source": source_counts,
            "period_days": days
        }
    
    async def get_trending_alerts(self, hours: int = 24) -> List[Dict]:
        """Get trending alerts in the last N hours."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get alerts with similar patterns
        recent_alerts = self.db.query(Alert).filter(
            Alert.created_at >= start_time
        ).order_by(desc(Alert.created_at)).all()
        
        # Group by title pattern
        alert_groups = {}
        for alert in recent_alerts:
            # Simple grouping by first few words of title
            title_key = " ".join(alert.title.split()[:4])
            if title_key not in alert_groups:
                alert_groups[title_key] = {
                    "pattern": title_key,
                    "count": 0,
                    "alerts": [],
                    "severity": alert.severity
                }
            
            alert_groups[title_key]["count"] += 1
            alert_groups[title_key]["alerts"].append({
                "id": alert.id,
                "title": alert.title,
                "created_at": alert.created_at,
                "user_email": alert.details.get("user_email") if alert.details else None
            })
        
        # Sort by count
        trending = sorted(alert_groups.values(), key=lambda x: x["count"], reverse=True)
        
        return trending[:10]  # Top 10 trending patterns
    
    async def escalate_alert(self, alert_id: int, reason: str = ""):
        """Escalate an alert to higher severity."""
        alert = self.db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return False
        
        # Increase severity
        current_severity_order = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        current_index = current_severity_order.index(alert.severity)
        
        if current_index < len(current_severity_order) - 1:
            alert.severity = current_severity_order[current_index + 1]
            alert.details["escalation_reason"] = reason
            alert.details["escalated_at"] = datetime.utcnow().isoformat()
            
            self.db.commit()
            
            # Send new notifications
            await self.send_alert_notifications(alert)
            
            logger.info(f"Alert {alert_id} escalated to {alert.severity.value}")
            return True
        
        return False
    
    async def auto_resolve_alerts(self, hours: int = 24):
        """Auto-resolve low-severity alerts older than N hours."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        alerts_to_resolve = self.db.query(Alert).filter(
            and_(
                Alert.severity == AlertSeverity.LOW,
                Alert.status == "open",
                Alert.created_at <= cutoff_time
            )
        ).all()
        
        for alert in alerts_to_resolve:
            alert.status = "resolved"
            alert.details["auto_resolved"] = True
            alert.details["auto_resolved_at"] = datetime.utcnow().isoformat()
        
        self.db.commit()
        
        logger.info(f"Auto-resolved {len(alerts_to_resolve)} low-severity alerts")
        return len(alerts_to_resolve)
