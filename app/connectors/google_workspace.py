"""
Google Workspace connector for CASB integration.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import structlog
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .base import BaseConnector

logger = structlog.get_logger()


class GoogleWorkspaceConnector(BaseConnector):
    """Google Workspace connector using Admin SDK and Drive API."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.project_id = config.get("project_id")
        self.admin_email = config.get("admin_email")
        self.credentials = None
        self.admin_service = None
        self.drive_service = None
        self.reports_service = None
        
    async def authenticate(self) -> bool:
        """Authenticate with Google Workspace."""
        try:
            # Create credentials with domain-wide delegation
            credentials_info = {
                "type": "service_account",
                "project_id": self.project_id,
                "private_key_id": self.config.get("private_key_id"),
                "private_key": self.config.get("private_key"),
                "client_email": self.config.get("client_email"),
                "client_id": self.client_id,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
            
            self.credentials = service_account.Credentials.from_service_account_info(
                credentials_info,
                scopes=[
                    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
                    'https://www.googleapis.com/auth/admin.directory.user.readonly',
                    'https://www.googleapis.com/auth/drive.readonly'
                ]
            )
            
            # Impersonate admin user
            if self.admin_email:
                self.credentials = self.credentials.with_subject(self.admin_email)
            
            # Build service clients
            self.admin_service = build('admin', 'directory_v1', credentials=self.credentials)
            self.drive_service = build('drive', 'v3', credentials=self.credentials)
            self.reports_service = build('admin', 'reports_v1', credentials=self.credentials)
            
            self.is_authenticated = True
            logger.info("Google Workspace authentication successful")
            return True
            
        except Exception as e:
            logger.error("Google Workspace authentication error", error=str(e))
            return False
    
    async def get_access_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Retrieve audit logs from Google Workspace."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            logs = []
            
            # Get Admin console activity
            admin_logs = await self._get_admin_logs(start_time, end_time)
            logs.extend(admin_logs)
            
            # Get Drive activity
            drive_logs = await self._get_drive_logs(start_time, end_time)
            logs.extend(drive_logs)
            
            # Get Login activity
            login_logs = await self._get_login_logs(start_time, end_time)
            logs.extend(login_logs)
            
            logger.info(f"Retrieved {len(logs)} Google Workspace audit logs")
            return logs
            
        except Exception as e:
            logger.error("Failed to retrieve Google Workspace access logs", error=str(e))
            return []
    
    async def _get_admin_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get Admin console activity logs."""
        try:
            results = self.reports_service.activities().list(
                userKey='all',
                applicationName='admin',
                startTime=start_time.isoformat() + 'Z',
                endTime=end_time.isoformat() + 'Z',
                maxResults=1000
            ).execute()
            
            logs = []
            for activity in results.get('items', []):
                normalized_log = self._normalize_google_log(activity, 'admin')
                logs.append(normalized_log)
            
            return logs
            
        except HttpError as e:
            logger.error("Failed to get Admin logs", error=str(e))
            return []
    
    async def _get_drive_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get Drive activity logs."""
        try:
            results = self.reports_service.activities().list(
                userKey='all',
                applicationName='drive',
                startTime=start_time.isoformat() + 'Z',
                endTime=end_time.isoformat() + 'Z',
                maxResults=1000
            ).execute()
            
            logs = []
            for activity in results.get('items', []):
                normalized_log = self._normalize_google_log(activity, 'drive')
                logs.append(normalized_log)
            
            return logs
            
        except HttpError as e:
            logger.error("Failed to get Drive logs", error=str(e))
            return []
    
    async def _get_login_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get login activity logs."""
        try:
            results = self.reports_service.activities().list(
                userKey='all',
                applicationName='login',
                startTime=start_time.isoformat() + 'Z',
                endTime=end_time.isoformat() + 'Z',
                maxResults=1000
            ).execute()
            
            logs = []
            for activity in results.get('items', []):
                normalized_log = self._normalize_google_log(activity, 'login')
                logs.append(normalized_log)
            
            return logs
            
        except HttpError as e:
            logger.error("Failed to get Login logs", error=str(e))
            return []
    
    async def get_users(self) -> List[Dict]:
        """Get list of users from Google Workspace."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            results = self.admin_service.users().list(
                customer='my_customer',
                maxResults=500,
                query='isSuspended=false'
            ).execute()
            
            users = []
            for user in results.get('users', []):
                users.append({
                    "id": user.get('id'),
                    "username": user.get('primaryEmail'),
                    "email": user.get('primaryEmail'),
                    "full_name": user.get('name', {}).get('fullName'),
                    "is_active": not user.get('suspended', False),
                    "last_login": user.get('lastLoginTime'),
                    "org_unit": user.get('orgUnitPath'),
                    "admin": user.get('isAdmin', False)
                })
            
            return users
            
        except HttpError as e:
            logger.error("Failed to retrieve Google Workspace users", error=str(e))
            return []
    
    async def get_user_activities(self, user_id: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get activities for a specific user."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            activities = []
            applications = ['admin', 'drive', 'login']
            
            for app in applications:
                results = self.reports_service.activities().list(
                    userKey=user_id,
                    applicationName=app,
                    startTime=start_time.isoformat() + 'Z',
                    endTime=end_time.isoformat() + 'Z',
                    maxResults=500
                ).execute()
                
                for activity in results.get('items', []):
                    normalized_activity = self._normalize_google_log(activity, app)
                    activities.append(normalized_activity)
            
            return activities
            
        except HttpError as e:
            logger.error(f"Failed to retrieve activities for user {user_id}", error=str(e))
            return []
    
    async def audit_file_access(self, file_id: str) -> Dict:
        """Audit file access and permissions."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Get file information
            file_obj = self.drive_service.files().get(
                fileId=file_id,
                fields='id,name,size,createdTime,modifiedTime,owners,permissions,webViewLink'
            ).execute()
            
            # Get permission details
            permissions = self.drive_service.permissions().list(
                fileId=file_id,
                fields='permissions(id,type,emailAddress,role,displayName)'
            ).execute()
            
            return {
                "file_id": file_id,
                "file_name": file_obj.get('name'),
                "file_size": int(file_obj.get('size', 0)),
                "created_by": file_obj.get('owners', [{}])[0].get('displayName'),
                "created_date": datetime.fromisoformat(file_obj.get('createdTime').replace('Z', '+00:00')),
                "modified_date": datetime.fromisoformat(file_obj.get('modifiedTime').replace('Z', '+00:00')),
                "permissions": permissions.get('permissions', []),
                "sharing_link": file_obj.get('webViewLink')
            }
            
        except HttpError as e:
            logger.error(f"Failed to audit file {file_id}", error=str(e))
            return {}
    
    def _normalize_google_log(self, activity: Dict, app_name: str) -> Dict:
        """Normalize Google Workspace log entry to standard format."""
        events = activity.get('events', [])
        if not events:
            return {}
        
        event = events[0]  # Take first event
        actor = activity.get('actor', {})
        
        return {
            "user_id": actor.get('profileId'),
            "user_email": actor.get('email'),
            "action": event.get('name'),
            "resource": event.get('parameters', [{}])[0].get('value') if event.get('parameters') else None,
            "ip_address": activity.get('ipAddress'),
            "user_agent": None,  # Google doesn't provide user agent in admin logs
            "timestamp": datetime.fromisoformat(activity.get('id', {}).get('time').replace('Z', '+00:00')),
            "status_code": 200 if activity.get('status') == 'success' else 400,
            "response_time_ms": None,
            "metadata": {
                "application": app_name,
                "event_name": event.get('name'),
                "event_type": event.get('type'),
                "actor_type": actor.get('callerType'),
                "status": activity.get('status')
            }
        }
