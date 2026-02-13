"""
Anomaly detection service using machine learning.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc, func
import structlog
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import pandas as pd
from celery import current_app

from app.core.database import get_db
from app.core.models import AccessLog, AnomalyDetection, User, SaaSApplication, AlertSeverity

logger = structlog.get_logger()


class AnomalyDetectionService:
    """Service for detecting anomalies in user behavior."""
    
    def __init__(self, db: Session):
        self.db = db
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained = False
    
    async def run_anomaly_detection(self):
        """Run anomaly detection for all users."""
        # Get active users with recent activity
        recent_cutoff = datetime.utcnow() - timedelta(days=7)
        
        active_users = self.db.query(AccessLog.user_email).filter(
            AccessLog.timestamp >= recent_cutoff
        ).distinct().all()
        
        for user_tuple in active_users:
            user_email = user_tuple[0]
            try:
                await self.detect_user_anomalies(user_email)
            except Exception as e:
                logger.error(f"Failed to detect anomalies for user {user_email}", error=str(e))
    
    async def detect_user_anomalies(self, user_email: str):
        """Detect anomalies for a specific user."""
        # Get user activity data
        user_data = await self.get_user_activity_features(user_email)
        if user_data.empty:
            return
        
        # Extract features
        features = self.extract_features(user_data)
        if len(features) == 0:
            return
        
        # Detect anomalies
        anomalies = await self.detect_anomalies_in_features(features, user_email)
        
        # Store anomaly results
        for anomaly in anomalies:
            await self.store_anomaly(anomaly, user_email)
    
    async def get_user_activity_features(self, user_email: str, days: int = 30) -> pd.DataFrame:
        """Get user activity data for feature extraction."""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = self.db.query(AccessLog).filter(
            and_(
                AccessLog.user_email == user_email,
                AccessLog.timestamp >= start_date
            )
        ).order_by(AccessLog.timestamp).all()
        
        if not logs:
            return pd.DataFrame()
        
        # Convert to DataFrame
        data = []
        for log in logs:
            data.append({
                "timestamp": log.timestamp,
                "action": log.action,
                "resource": log.resource,
                "ip_address": log.ip_address,
                "status_code": log.status_code or 200,
                "response_time_ms": log.response_time_ms or 0,
                "hour": log.timestamp.hour,
                "day_of_week": log.timestamp.weekday(),
                "is_weekend": log.timestamp.weekday() >= 5
            })
        
        return pd.DataFrame(data)
    
    def extract_features(self, user_data: pd.DataFrame) -> np.ndarray:
        """Extract features for anomaly detection."""
        features = []
        
        # Group by day for feature extraction
        user_data['date'] = user_data['timestamp'].dt.date
        
        for date, day_data in user_data.groupby('date'):
            # Time-based features
            hour_counts = day_data['hour'].value_counts().to_dict()
            hourly_pattern = [hour_counts.get(h, 0) for h in range(24)]
            
            # Action-based features
            action_counts = day_data['action'].value_counts().to_dict()
            unique_actions = len(action_counts)
            total_actions = len(day_data)
            
            # IP-based features
            unique_ips = day_data['ip_address'].nunique()
            
            # Response time features
            avg_response_time = day_data['response_time_ms'].mean()
            max_response_time = day_data['response_time_ms'].max()
            
            # Status code features
            error_rate = (day_data['status_code'] >= 400).mean()
            
            # Weekend activity
            weekend_activity = day_data['is_weekend'].sum()
            
            # Combine features
            feature_vector = [
                total_actions,
                unique_actions,
                unique_ips,
                avg_response_time,
                max_response_time,
                error_rate,
                weekend_activity
            ] + hourly_pattern
            
            features.append(feature_vector)
        
        return np.array(features) if features else np.array([])
    
    async def detect_anomalies_in_features(self, features: np.ndarray, user_email: str) -> List[Dict]:
        """Detect anomalies using machine learning models."""
        if len(features) < 10:  # Need minimum data points
            return []
        
        # Train model if not already trained
        if not self.model_trained:
            await self.train_anomaly_model(features)
        
        # Normalize features
        features_scaled = self.scaler.transform(features)
        
        # Predict anomalies
        predictions = self.isolation_forest.predict(features_scaled)
        scores = self.isolation_forest.decision_function(features_scaled)
        
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly detected
                # Calculate anomaly score (0-100)
                anomaly_score = int(abs(score) * 100)
                threshold = 50  # Default threshold
                
                anomalies.append({
                    "day_index": i,
                    "score": anomaly_score,
                    "threshold": threshold,
                    "features": features[i].tolist(),
                    "is_anomaly": anomaly_score > threshold
                })
        
        return anomalies
    
    async def train_anomaly_model(self, features: np.ndarray):
        """Train the anomaly detection model."""
        if len(features) < 10:
            return
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train Isolation Forest
        self.isolation_forest.fit(features_scaled)
        self.model_trained = True
        
        logger.info("Anomaly detection model trained successfully")
    
    async def store_anomaly(self, anomaly: Dict, user_email: str):
        """Store anomaly detection result."""
        # Check if similar anomaly already exists
        existing_anomaly = self.db.query(AnomalyDetection).filter(
            and_(
                AnomalyDetection.user_email == user_email,
                AnomalyDetection.anomaly_type == "behavioral_pattern",
                AnomalyDetection.timestamp >= datetime.utcnow() - timedelta(hours=1)
            )
        ).first()
        
        if existing_anomaly:
            return  # Avoid duplicate anomalies
        
        # Create anomaly record
        anomaly_record = AnomalyDetection(
            user_id=user_email.split('@')[0],  # Extract username
            user_email=user_email,
            anomaly_type="behavioral_pattern",
            score=anomaly["score"],
            threshold=anomaly["threshold"],
            features=anomaly["features"],
            context={
                "detection_method": "isolation_forest",
                "day_index": anomaly["day_index"]
            },
            timestamp=datetime.utcnow()
        )
        
        self.db.add(anomaly_record)
        self.db.commit()
        
        # Create alert if score is high
        if anomaly["score"] > 70:
            await self.create_anomaly_alert(anomaly_record, user_email)
        
        logger.info(f"Anomaly detected for user {user_email} with score {anomaly['score']}")
    
    async def create_anomaly_alert(self, anomaly: AnomalyDetection, user_email: str):
        """Create an alert for high-score anomalies."""
        from app.services.alerts import AlertService
        
        alert_service = AlertService(self.db)
        
        severity = AlertSeverity.CRITICAL if anomaly.score > 85 else AlertSeverity.HIGH
        
        await alert_service.create_alert(
            title=f"Behavioral Anomaly Detected - {user_email}",
            description=f"Unusual behavior pattern detected for user {user_email}. Anomaly score: {anomaly.score}",
            severity=severity,
            source="anomaly_detection",
            source_id=anomaly.id,
            details={
                "user_email": user_email,
                "anomaly_score": anomaly.score,
                "threshold": anomaly.threshold,
                "features": anomaly.features,
                "context": anomaly.context
            }
        )
    
    async def detect_login_anomalies(self, user_email: str, login_data: Dict) -> List[Dict]:
        """Detect anomalies in login patterns."""
        # Get user's login history
        start_date = datetime.utcnow() - timedelta(days=30)
        
        login_logs = self.db.query(AccessLog).filter(
            and_(
                AccessLog.user_email == user_email,
                AccessLog.action == "login",
                AccessLog.timestamp >= start_date
            )
        ).all()
        
        anomalies = []
        
        if not login_logs:
            # First login from this user
            anomalies.append({
                "type": "first_login",
                "description": "First login detected for user",
                "severity": "low"
            })
            return anomalies
        
        # Analyze login patterns
        login_hours = [log.timestamp.hour for log in login_logs]
        login_ips = [log.ip_address for log in login_logs if log.ip_address]
        
        current_hour = login_data.get("timestamp", datetime.utcnow()).hour
        current_ip = login_data.get("ip_address")
        
        # Check for unusual login time
        if current_hour not in range(min(login_hours), max(login_hours) + 1):
            anomalies.append({
                "type": "unusual_login_time",
                "description": f"Login at unusual hour: {current_hour}",
                "severity": "medium"
            })
        
        # Check for new IP address
        if current_ip and current_ip not in login_ips:
            anomalies.append({
                "type": "new_login_ip",
                "description": f"Login from new IP address: {current_ip}",
                "severity": "high"
            })
        
        return anomalies
    
    async def detect_data_exfiltration(self, user_email: str, activity_data: List[Dict]) -> List[Dict]:
        """Detect potential data exfiltration patterns."""
        anomalies = []
        
        # Look for patterns indicating data exfiltration
        download_count = 0
        total_size = 0
        unique_resources = set()
        
        for activity in activity_data:
            action = activity.get("action", "").lower()
            
            if "download" in action or "export" in action:
                download_count += 1
                resource = activity.get("resource", "")
                if resource:
                    unique_resources.add(resource)
                
                # Extract file size if available
                file_size = activity.get("metadata", {}).get("file_size", 0)
                total_size += file_size
        
        # Check for suspicious patterns
        if download_count > 10:  # High number of downloads
            anomalies.append({
                "type": "high_download_count",
                "description": f"High number of downloads: {download_count}",
                "severity": "medium"
            })
        
        if total_size > 100 * 1024 * 1024:  # > 100MB
            anomalies.append({
                "type": "large_data_transfer",
                "description": f"Large data transfer detected: {total_size / (1024*1024):.2f} MB",
                "severity": "high"
            })
        
        if len(unique_resources) > 50:  # Accessing many different resources
            anomalies.append({
                "type": "broad_access_pattern",
                "description": f"Access to many different resources: {len(unique_resources)}",
                "severity": "medium"
            })
        
        return anomalies


# Celery tasks
@current_app.task
async def run_anomaly_detection():
    """Celery task to run anomaly detection."""
    db = next(get_db())
    try:
        service = AnomalyDetectionService(db)
        await service.run_anomaly_detection()
    finally:
        db.close()


@current_app.task
async def detect_user_anomalies(user_email: str):
    """Celery task to detect anomalies for a specific user."""
    db = next(get_db())
    try:
        service = AnomalyDetectionService(db)
        await service.detect_user_anomalies(user_email)
    finally:
        db.close()
