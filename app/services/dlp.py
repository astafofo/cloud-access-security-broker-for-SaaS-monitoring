"""
Data Loss Prevention (DLP) service for sensitive data detection.
"""

import re
from typing import Dict, List, Optional, Set
from datetime import datetime
import structlog
from sqlalchemy.orm import Session

from app.core.models import AccessLog, PolicyViolation, AlertSeverity
from app.services.alerts import AlertService

logger = structlog.get_logger()


class DLPService:
    """Service for Data Loss Prevention and sensitive data detection."""
    
    def __init__(self, db: Session):
        self.db = db
        self.alert_service = AlertService(db)
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize regex patterns for sensitive data detection."""
        return {
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "phone": re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            "api_key": re.compile(r'\b[A-Za-z0-9]{20,}\b'),
            "password": re.compile(r'(?i)password\s*[:=]\s*\S+'),
            "secret": re.compile(r'(?i)secret\s*[:=]\s*\S+'),
            "token": re.compile(r'(?i)token\s*[:=]\s*\S+'),
            "ip_address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "bank_account": re.compile(r'\b\d{9,18}\b'),
            "passport": re.compile(r'\b[A-Z]{2}\d{7}\b'),
            "driver_license": re.compile(r'\b[A-Z]{1,2}\d{7,8}\b')
        }
    
    async def scan_content(self, content: str, context: Dict = None) -> Dict:
        """Scan content for sensitive data patterns."""
        if not content:
            return {"found": False, "patterns": [], "risk_score": 0}
        
        found_patterns = []
        total_matches = 0
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            if matches:
                found_patterns.append({
                    "type": pattern_name,
                    "count": len(matches),
                    "samples": matches[:3]  # First 3 matches
                })
                total_matches += len(matches)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(found_patterns, total_matches, context)
        
        return {
            "found": len(found_patterns) > 0,
            "patterns": found_patterns,
            "risk_score": risk_score,
            "total_matches": total_matches
        }
    
    def _calculate_risk_score(self, patterns: List[Dict], total_matches: int, context: Dict = None) -> int:
        """Calculate risk score based on detected patterns."""
        if not patterns:
            return 0
        
        # Base scores for different pattern types
        pattern_scores = {
            "ssn": 90,
            "credit_card": 85,
            "bank_account": 80,
            "passport": 85,
            "driver_license": 75,
            "api_key": 95,
            "password": 90,
            "secret": 85,
            "token": 80,
            "email": 30,
            "phone": 40,
            "ip_address": 50
        }
        
        max_score = 0
        for pattern in patterns:
            pattern_type = pattern["type"]
            count = pattern["count"]
            base_score = pattern_scores.get(pattern_type, 50)
            
            # Increase score based on count
            if count > 1:
                base_score = min(100, base_score + (count - 1) * 10)
            
            max_score = max(max_score, base_score)
        
        # Contextual adjustments
        if context:
            # Increase score for external sharing
            if context.get("is_external_sharing", False):
                max_score = min(100, max_score + 20)
            
            # Increase score for downloads
            if context.get("is_download", False):
                max_score = min(100, max_score + 15)
            
            # Decrease score for internal access
            if context.get("is_internal_access", False):
                max_score = max(0, max_score - 10)
        
        return max_score
    
    async def scan_file_content(self, file_path: str, context: Dict = None) -> Dict:
        """Scan file content for sensitive data."""
        try:
            # Read file content (simplified - in production, use appropriate file handlers)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return await self.scan_content(content, context)
            
        except Exception as e:
            logger.error(f"Failed to scan file {file_path}", error=str(e))
            return {"found": False, "patterns": [], "risk_score": 0, "error": str(e)}
    
    async def scan_access_log(self, access_log: AccessLog) -> Dict:
        """Scan access log for potential DLP violations."""
        violations = []
        total_risk_score = 0
        
        # Scan resource name
        if access_log.resource:
            resource_scan = await self.scan_content(access_log.resource)
            if resource_scan["found"]:
                violations.append({
                    "source": "resource_name",
                    "patterns": resource_scan["patterns"],
                    "risk_score": resource_scan["risk_score"]
                })
                total_risk_score += resource_scan["risk_score"]
        
        # Scan metadata
        if access_log.metadata:
            metadata_text = str(access_log.metadata)
            metadata_scan = await self.scan_content(metadata_text)
            if metadata_scan["found"]:
                violations.append({
                    "source": "metadata",
                    "patterns": metadata_scan["patterns"],
                    "risk_score": metadata_scan["risk_score"]
                })
                total_risk_score += metadata_scan["risk_score"]
        
        # Check for high-risk actions
        high_risk_actions = ["download", "export", "share", "email", "print"]
        if access_log.action and any(risk in access_log.action.lower() for risk in high_risk_actions):
            total_risk_score += 20
        
        return {
            "violations": violations,
            "total_risk_score": total_risk_score,
            "requires_action": total_risk_score >= 70
        }
    
    async def enforce_dlp_policies(self, access_log: AccessLog) -> Optional[Dict]:
        """Enforce DLP policies on access logs."""
        scan_result = await self.scan_access_log(access_log)
        
        if not scan_result["requires_action"]:
            return None
        
        # Create DLP violation
        violation = {
            "type": "dlp_violation",
            "risk_score": scan_result["total_risk_score"],
            "violations": scan_result["violations"],
            "action_taken": self._determine_action(scan_result["total_risk_score"])
        }
        
        # Create alert for high-risk violations
        if scan_result["total_risk_score"] >= 85:
            await self.alert_service.create_dlp_alert(access_log, violation)
        
        return violation
    
    def _determine_action(self, risk_score: int) -> str:
        """Determine action based on risk score."""
        if risk_score >= 90:
            return "block"
        elif risk_score >= 75:
            return "quarantine"
        elif risk_score >= 60:
            return "alert"
        else:
            return "log"
    
    async def scan_email_content(self, email_data: Dict) -> Dict:
        """Scan email content for sensitive data."""
        content_parts = []
        
        # Combine subject and body
        if email_data.get("subject"):
            content_parts.append(email_data["subject"])
        
        if email_data.get("body"):
            content_parts.append(email_data["body"])
        
        # Scan attachments if available
        attachments = email_data.get("attachments", [])
        for attachment in attachments:
            if attachment.get("content"):
                content_parts.append(attachment["content"])
        
        combined_content = " ".join(content_parts)
        
        # Add context for email scanning
        context = {
            "is_external_sharing": len(email_data.get("external_recipients", [])) > 0,
            "is_download": False,
            "is_internal_access": False
        }
        
        return await self.scan_content(combined_content, context)
    
    async def check_data_classification(self, resource_name: str, content: str = None) -> Dict:
        """Check data classification based on content and naming patterns."""
        classification = "public"
        confidence = 0
        
        # Check resource name for classification indicators
        name_lower = resource_name.lower() if resource_name else ""
        
        if any(indicator in name_lower for indicator in ["confidential", "secret", "restricted"]):
            classification = "confidential"
            confidence = 80
        elif any(indicator in name_lower for indicator in ["internal", "private", "internal-use"]):
            classification = "internal"
            confidence = 60
        elif any(indicator in name_lower for indicator in ["public", "external", "customer"]):
            classification = "public"
            confidence = 70
        
        # Scan content if available
        if content:
            content_scan = await self.scan_content(content)
            if content_scan["risk_score"] >= 80:
                classification = "confidential"
                confidence = max(confidence, content_scan["risk_score"])
            elif content_scan["risk_score"] >= 40:
                classification = "internal"
                confidence = max(confidence, content_scan["risk_score"])
        
        return {
            "classification": classification,
            "confidence": confidence,
            "requires_protection": classification in ["confidential", "internal"]
        }
    
    def add_custom_pattern(self, name: str, pattern: str, description: str = ""):
        """Add a custom pattern for sensitive data detection."""
        try:
            compiled_pattern = re.compile(pattern)
            self.patterns[name] = compiled_pattern
            logger.info(f"Added custom pattern: {name}")
            return True
        except re.error as e:
            logger.error(f"Failed to add custom pattern {name}", error=str(e))
            return False
    
    def remove_pattern(self, name: str):
        """Remove a pattern."""
        if name in self.patterns:
            del self.patterns[name]
            logger.info(f"Removed pattern: {name}")
            return True
        return False
    
    def get_pattern_stats(self) -> Dict:
        """Get statistics about configured patterns."""
        return {
            "total_patterns": len(self.patterns),
            "pattern_names": list(self.patterns.keys()),
            "high_risk_patterns": ["ssn", "credit_card", "api_key", "password"],
            "medium_risk_patterns": ["email", "phone", "ip_address", "secret"]
        }
