"""
Salesforce connector for CASB integration.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import structlog
from simple_salesforce import Salesforce
import requests

from .base import BaseConnector

logger = structlog.get_logger()


class SalesforceConnector(BaseConnector):
    """Salesforce connector using Salesforce REST API."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.username = config.get("username")
        self.password = config.get("password")
        self.security_token = config.get("security_token")
        self.domain = config.get("domain", "login")  # login or test
        self.sf_client = None
        
    async def authenticate(self) -> bool:
        """Authenticate with Salesforce."""
        try:
            self.sf_client = Salesforce(
                username=self.username,
                password=self.password,
                security_token=self.security_token,
                domain=self.domain
            )
            
            # Test connection
            self.sf_client.query("SELECT Count() FROM User LIMIT 1")
            
            self.is_authenticated = True
            logger.info("Salesforce authentication successful")
            return True
            
        except Exception as e:
            logger.error("Salesforce authentication error", error=str(e))
            return False
    
    async def get_access_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Retrieve audit logs from Salesforce."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            logs = []
            
            # Get EventLogFile records
            query = f"""
            SELECT Id, LogDate, EventType, LogFile, 
                   CreatedDate, CreatedBy.Id, CreatedBy.Email, CreatedBy.Name
            FROM EventLogFile 
            WHERE LogDate >= {start_time.strftime('%Y-%m-%dT%H:%M:%S')} 
            AND LogDate <= {end_time.strftime('%Y-%m-%dT%H:%M:%S')}
            ORDER BY LogDate DESC
            """
            
            result = self.sf_client.query_all(query)
            
            for record in result.get('records', []):
                log_data = await self._process_event_log_file(record)
                logs.extend(log_data)
            
            logger.info(f"Retrieved {len(logs)} Salesforce audit logs")
            return logs
            
        except Exception as e:
            logger.error("Failed to retrieve Salesforce access logs", error=str(e))
            return []
    
    async def _process_event_log_file(self, log_file_record: Dict) -> List[Dict]:
        """Process an EventLogFile to extract individual log entries."""
        try:
            # Get the actual log file content
            log_file_id = log_file_record.get('LogFile')
            
            # Download log file
            log_content = self._download_log_file(log_file_id)
            if not log_content:
                return []
            
            # Parse log content (simplified - real implementation would parse CSV format)
            logs = []
            lines = log_content.split('\n')[1:]  # Skip header
            
            for line in lines[:100]:  # Limit to prevent memory issues
                if line.strip():
                    log_entry = self._parse_salesforce_log_line(line, log_file_record)
                    if log_entry:
                        logs.append(log_entry)
            
            return logs
            
        except Exception as e:
            logger.error("Failed to process EventLogFile", error=str(e))
            return []
    
    def _download_log_file(self, log_file_id: str) -> Optional[str]:
        """Download log file content."""
        try:
            # Use Salesforce REST API to download file
            url = f"{self.sf_client.base_url}services/data/v56.0/sobjects/EventLogFile/{log_file_id}/LogFile"
            
            headers = {
                'Authorization': f'Bearer {self.sf_client.session_id}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return response.text
            
        except Exception as e:
            logger.error(f"Failed to download log file {log_file_id}", error=str(e))
            return None
    
    def _parse_salesforce_log_line(self, line: str, log_file_record: Dict) -> Optional[Dict]:
        """Parse a single line from Salesforce log file."""
        try:
            # Simplified parsing - real implementation would handle CSV format properly
            parts = line.split(',')
            if len(parts) < 5:
                return None
            
            return {
                "user_id": parts[0] if parts[0] else log_file_record.get('CreatedBy', {}).get('Id'),
                "user_email": parts[1] if parts[1] else log_file_record.get('CreatedBy', {}).get('Email'),
                "action": parts[2] if parts[2] else 'unknown',
                "resource": parts[3] if len(parts) > 3 else None,
                "ip_address": parts[4] if len(parts) > 4 else None,
                "user_agent": parts[5] if len(parts) > 5 else None,
                "timestamp": datetime.fromisoformat(parts[6].replace('Z', '+00:00')) if len(parts) > 6 else log_file_record.get('LogDate'),
                "status_code": 200 if parts[7] == 'SUCCESS' else 400 if len(parts) > 7 else 200,
                "response_time_ms": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else None,
                "metadata": {
                    "event_type": log_file_record.get('EventType'),
                    "log_file_id": log_file_record.get('Id'),
                    "raw_data": line
                }
            }
            
        except Exception as e:
            logger.error("Failed to parse Salesforce log line", error=str(e))
            return None
    
    async def get_users(self) -> List[Dict]:
        """Get list of users from Salesforce."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            query = """
            SELECT Id, Username, Email, Name, IsActive, LastLoginDate, 
                   Profile.Name, UserRole.Name, UserType
            FROM User 
            WHERE IsActive = true
            """
            
            result = self.sf_client.query_all(query)
            users = []
            
            for record in result.get('records', []):
                users.append({
                    "id": record.get('Id'),
                    "username": record.get('Username'),
                    "email": record.get('Email'),
                    "full_name": record.get('Name'),
                    "is_active": record.get('IsActive', False),
                    "last_login": record.get('LastLoginDate'),
                    "profile": record.get('Profile', {}).get('Name'),
                    "role": record.get('UserRole', {}).get('Name'),
                    "user_type": record.get('UserType')
                })
            
            return users
            
        except Exception as e:
            logger.error("Failed to retrieve Salesforce users", error=str(e))
            return []
    
    async def get_user_activities(self, user_id: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get activities for a specific user."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Query SetupAuditTrail for user activities
            query = f"""
            SELECT Id, Action, CreatedDate, CreatedBy.Id, CreatedBy.Email, 
                   CreatedBy.Name, Display, Section
            FROM SetupAuditTrail 
            WHERE CreatedBy.Id = '{user_id}'
            AND CreatedDate >= {start_time.strftime('%Y-%m-%dT%H:%M:%S')} 
            AND CreatedDate <= {end_time.strftime('%Y-%m-%dT%H:%M:%S')}
            ORDER BY CreatedDate DESC
            """
            
            result = self.sf_client.query_all(query)
            activities = []
            
            for record in result.get('records', []):
                activities.append({
                    "user_id": record.get('CreatedBy', {}).get('Id'),
                    "user_email": record.get('CreatedBy', {}).get('Email'),
                    "action": record.get('Action'),
                    "resource": record.get('Display'),
                    "ip_address": None,
                    "user_agent": None,
                    "timestamp": datetime.fromisoformat(record.get('CreatedDate').replace('+0000', '+00:00')),
                    "status_code": 200,
                    "response_time_ms": None,
                    "metadata": {
                        "section": record.get('Section'),
                        "audit_id": record.get('Id')
                    }
                })
            
            return activities
            
        except Exception as e:
            logger.error(f"Failed to retrieve activities for user {user_id}", error=str(e))
            return []
    
    async def audit_file_access(self, file_id: str) -> Dict:
        """Audit file access and permissions (ContentDocument)."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            # Get ContentDocument information
            query = f"""
            SELECT Id, Title, FileType, ContentSize, CreatedDate, CreatedBy.Name,
                   LastModifiedDate, LastModifiedBy.Name, Description
            FROM ContentDocument 
            WHERE Id = '{file_id}'
            """
            
            result = self.sf_client.query(query)
            records = result.get('records', [])
            
            if not records:
                return {}
            
            doc = records[0]
            
            # Get sharing information
            share_query = f"""
            SELECT Id, LinkedEntityId, ShareType, AccessLevel, RowCause
            FROM ContentDocumentLink 
            WHERE ContentDocumentId = '{file_id}'
            """
            
            share_result = self.sf_client.query(share_query)
            shares = share_result.get('records', [])
            
            return {
                "file_id": file_id,
                "file_name": doc.get('Title'),
                "file_size": doc.get('ContentSize', 0),
                "file_type": doc.get('FileType'),
                "created_by": doc.get('CreatedBy', {}).get('Name'),
                "created_date": datetime.fromisoformat(doc.get('CreatedDate').replace('+0000', '+00:00')),
                "modified_by": doc.get('LastModifiedBy', {}).get('Name'),
                "modified_date": datetime.fromisoformat(doc.get('LastModifiedDate').replace('+0000', '+00:00')),
                "permissions": [
                    {
                        "entity_id": share.get('LinkedEntityId'),
                        "share_type": share.get('ShareType'),
                        "access_level": share.get('AccessLevel'),
                        "row_cause": share.get('RowCause')
                    }
                    for share in shares
                ],
                "description": doc.get('Description')
            }
            
        except Exception as e:
            logger.error(f"Failed to audit file {file_id}", error=str(e))
            return {}
    
    async def get_login_history(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get login history for authentication monitoring."""
        if not self.is_authenticated:
            await self.authenticate()
        
        try:
            query = f"""
            SELECT Id, LoginTime, UserId, Username, LoginType, 
                   SourceIp, LoginUrl, Status, Browser
            FROM LoginHistory 
            WHERE LoginTime >= {start_time.strftime('%Y-%m-%dT%H:%M:%S')} 
            AND LoginTime <= {end_time.strftime('%Y-%m-%dT%H:%M:%S')}
            ORDER BY LoginTime DESC
            """
            
            result = self.sf_client.query_all(query)
            logins = []
            
            for record in result.get('records', []):
                logins.append({
                    "user_id": record.get('UserId'),
                    "user_email": record.get('Username'),
                    "action": "login",
                    "ip_address": record.get('SourceIp'),
                    "timestamp": datetime.fromisoformat(record.get('LoginTime').replace('+0000', '+00:00')),
                    "status_code": 200 if record.get('Status') == 'Success' else 400,
                    "metadata": {
                        "login_type": record.get('LoginType'),
                        "login_url": record.get('LoginUrl'),
                        "browser": record.get('Browser'),
                        "status": record.get('Status')
                    }
                })
            
            return logins
            
        except Exception as e:
            logger.error("Failed to retrieve Salesforce login history", error=str(e))
            return []
