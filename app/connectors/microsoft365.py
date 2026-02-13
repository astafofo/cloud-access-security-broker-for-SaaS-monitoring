"""
Microsoft 365 connector for CASB integration.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import structlog
import msal
import requests

from .base import BaseConnector

logger = structlog.get_logger()


class Microsoft365Connector(BaseConnector):
    """Microsoft 365 connector using Microsoft Graph API."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scope = ["https://graph.microsoft.com/.default"]
        self.access_token = None
        self.graph_base_url = "https://graph.microsoft.com/v1.0"
        
    async def authenticate(self) -> bool:
        """Authenticate with Microsoft 365."""
        try:
            app = msal.ConfidentialClientApplication(
                client_id=self.client_id,
                authority=self.authority,
                client_credential=self.client_secret
            )
            
            result = app.acquire_token_for_client(scopes=self.scope)
            
            if "access_token" in result:
                self.access_token = result["access_token"]
                self.is_authenticated = True
                logger.info("Microsoft 365 authentication successful")
                return True
            else:
                logger.error("Microsoft 365 authentication failed", error=result.get("error"))
                return False
                
        except Exception as e:
            logger.error("Microsoft 365 authentication error", error=str(e))
            return False
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for API requests."""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
    
    async def get_access_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Retrieve audit logs from Microsoft 365."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Format times for Microsoft Graph API
            start_filter = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_filter = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Get audit logs
            url = f"{self.graph_base_url}/auditLogs/directoryAudits"
            params = {
                "$filter": f"activityDateTime ge {start_filter} and activityDateTime le {end_filter}",
                "$orderby": "activityDateTime desc",
                "$top": 1000
            }
            
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            
            data = response.json()
            logs = []
            
            for log in data.get("value", []):
                normalized_log = self._normalize_microsoft_log(log)
                logs.append(normalized_log)
            
            logger.info(f"Retrieved {len(logs)} Microsoft 365 audit logs")
            return logs
            
        except Exception as e:
            logger.error("Failed to retrieve Microsoft 365 access logs", error=str(e))
            return []
    
    async def get_users(self) -> List[Dict]:
        """Get list of users from Microsoft 365."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            url = f"{self.graph_base_url}/users"
            params = {
                "$select": "id,displayName,userPrincipalName,mail,accountEnabled,lastSignInDateTime",
                "$top": 999
            }
            
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            
            data = response.json()
            users = []
            
            for user in data.get("value", []):
                users.append({
                    "id": user.get("id"),
                    "username": user.get("userPrincipalName"),
                    "email": user.get("mail") or user.get("userPrincipalName"),
                    "full_name": user.get("displayName"),
                    "is_active": user.get("accountEnabled", False),
                    "last_login": user.get("lastSignInDateTime")
                })
            
            return users
            
        except Exception as e:
            logger.error("Failed to retrieve Microsoft 365 users", error=str(e))
            return []
    
    async def get_user_activities(self, user_id: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get activities for a specific user."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Get user-specific activities
            url = f"{self.graph_base_url}/auditLogs/directoryAudits"
            start_filter = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_filter = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            params = {
                "$filter": f"activityDateTime ge {start_filter} and activityDateTime le {end_filter} and initiatedBy/user/userPrincipalName eq '{user_id}'",
                "$orderby": "activityDateTime desc",
                "$top": 500
            }
            
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            
            data = response.json()
            activities = []
            
            for activity in data.get("value", []):
                normalized_activity = self._normalize_microsoft_log(activity)
                activities.append(normalized_activity)
            
            return activities
            
        except Exception as e:
            logger.error(f"Failed to retrieve activities for user {user_id}", error=str(e))
            return []
    
    async def audit_file_access(self, file_id: str) -> Dict:
        """Audit file access and permissions."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Get file information
            url = f"{self.graph_base_url}/drives/{file_id.split(':')[0]}/items/{file_id.split(':')[1]}"
            
            response = requests.get(url, headers=self._get_headers())
            response.raise_for_status()
            
            file_data = response.json()
            
            # Get file permissions
            permissions_url = f"{url}/permissions"
            permissions_response = requests.get(permissions_url, headers=self._get_headers())
            permissions_response.raise_for_status()
            
            permissions_data = permissions_response.json()
            
            return {
                "file_id": file_id,
                "file_name": file_data.get("name"),
                "file_size": file_data.get("size"),
                "created_by": file_data.get("createdBy", {}).get("user", {}).get("displayName"),
                "created_date": file_data.get("createdDateTime"),
                "modified_by": file_data.get("lastModifiedBy", {}).get("user", {}).get("displayName"),
                "modified_date": file_data.get("lastModifiedDateTime"),
                "permissions": permissions_data.get("value", []),
                "sharing_link": file_data.get("webUrl")
            }
            
        except Exception as e:
            logger.error(f"Failed to audit file {file_id}", error=str(e))
            return {}
    
    def _normalize_microsoft_log(self, log: Dict) -> Dict:
        """Normalize Microsoft 365 log entry to standard format."""
        activity = log.get("activityDisplayName", "")
        initiated_by = log.get("initiatedBy", {})
        user_info = initiated_by.get("user", {})
        
        return {
            "user_id": user_info.get("id"),
            "user_email": user_info.get("userPrincipalName"),
            "action": activity,
            "resource": log.get("targetResources", [{}])[0].get("displayName"),
            "ip_address": log.get("clientAppUsed"),
            "user_agent": log.get("additionalDetails", [{}])[0].get("key") if log.get("additionalDetails") else None,
            "timestamp": datetime.fromisoformat(log.get("activityDateTime").replace("Z", "+00:00")),
            "status_code": 200 if log.get("result") == "success" else 400,
            "response_time_ms": None,
            "metadata": {
                "category": log.get("category"),
                "correlation_id": log.get("correlationId"),
                "result": log.get("result"),
                "result_reason": log.get("resultReason"),
                "operation_type": log.get("operationType")
            }
        }
    
    async def get_sign_in_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get sign-in logs for authentication monitoring."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            url = f"{self.graph_base_url}/auditLogs/signInActivity"
            start_filter = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_filter = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            params = {
                "$filter": f"createdDateTime ge {start_filter} and createdDateTime le {end_filter}",
                "$orderby": "createdDateTime desc",
                "$top": 1000
            }
            
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            
            data = response.json()
            sign_ins = []
            
            for sign_in in data.get("value", []):
                sign_ins.append({
                    "user_id": sign_in.get("userId"),
                    "user_email": sign_in.get("userPrincipalName"),
                    "action": "sign_in",
                    "ip_address": sign_in.get("ipAddress"),
                    "timestamp": datetime.fromisoformat(sign_in.get("createdDateTime").replace("Z", "+00:00")),
                    "status_code": 200 if sign_in.get("status", {}).get("errorCode") == 0 else 400,
                    "metadata": {
                        "app_id": sign_in.get("appDisplayName"),
                        "client_app": sign_in.get("clientAppUsed"),
                        "risk_detail": sign_in.get("riskDetail"),
                        "risk_level_aggregated": sign_in.get("riskLevelAggregated"),
                        "risk_level_during_signin": sign_in.get("riskLevelDuringSignIn"),
                        "location": sign_in.get("location", {})
                    }
                })
            
            return sign_ins
            
        except Exception as e:
            logger.error("Failed to retrieve Microsoft 365 sign-in logs", error=str(e))
            return []
