"""
Base connector class for SaaS integrations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
import structlog

logger = structlog.get_logger()


class BaseConnector(ABC):
    """Base class for all SaaS connectors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize connector with configuration."""
        self.config = config
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.tenant_id = config.get("tenant_id")
        self.is_authenticated = False
        
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the SaaS provider."""
        pass
    
    @abstractmethod
    async def get_access_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Retrieve access logs from the SaaS provider."""
        pass
    
    @abstractmethod
    async def get_users(self) -> List[Dict]:
        """Get list of users from the SaaS provider."""
        pass
    
    @abstractmethod
    async def get_user_activities(self, user_id: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get activities for a specific user."""
        pass
    
    @abstractmethod
    async def audit_file_access(self, file_id: str) -> Dict:
        """Audit file access and permissions."""
        pass
    
    async def test_connection(self) -> bool:
        """Test connection to the SaaS provider."""
        try:
            return await self.authenticate()
        except Exception as e:
            logger.error("Connection test failed", error=str(e))
            return False
    
    def normalize_log_entry(self, raw_log: Dict) -> Dict:
        """Normalize log entry to standard format."""
        return {
            "user_id": raw_log.get("user_id"),
            "user_email": raw_log.get("user_email"),
            "action": raw_log.get("action"),
            "resource": raw_log.get("resource"),
            "ip_address": raw_log.get("ip_address"),
            "user_agent": raw_log.get("user_agent"),
            "timestamp": raw_log.get("timestamp"),
            "status_code": raw_log.get("status_code"),
            "response_time_ms": raw_log.get("response_time_ms"),
            "metadata": raw_log.get("metadata", {})
        }
    
    def extract_risk_indicators(self, log_entry: Dict) -> List[str]:
        """Extract risk indicators from a log entry."""
        indicators = []
        
        # Check for suspicious IP addresses
        ip = log_entry.get("ip_address")
        if ip and self._is_suspicious_ip(ip):
            indicators.append("suspicious_ip")
        
        # Check for unusual time
        timestamp = log_entry.get("timestamp")
        if timestamp and self._is_unusual_time(timestamp):
            indicators.append("unusual_time")
        
        # Check for high-risk actions
        action = log_entry.get("action", "").lower()
        high_risk_actions = ["delete", "download", "export", "share", "admin"]
        if any(risk_action in action for risk_action in high_risk_actions):
            indicators.append("high_risk_action")
        
        return indicators
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious."""
        # Simplified logic - in production, use IP intelligence feeds
        suspicious_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        return any(ip.startswith(range.split('/')[0].rsplit('.', 1)[0]) for range in suspicious_ranges)
    
    def _is_unusual_time(self, timestamp: datetime) -> bool:
        """Check if timestamp is during unusual hours."""
        hour = timestamp.hour
        return hour < 6 or hour > 22  # Outside 6 AM - 10 PM
