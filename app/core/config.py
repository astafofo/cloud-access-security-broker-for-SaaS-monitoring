"""
Application configuration settings using Pydantic Settings.
"""

from typing import List, Optional
from pydantic import BaseSettings, validator
import os


class Settings(BaseSettings):
    """Application settings."""
    
    # Application
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Database
    DATABASE_URL: str = "postgresql://casb_user:password@localhost:5432/casb_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # JWT
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # Microsoft 365
    MICROSOFT_CLIENT_ID: Optional[str] = None
    MICROSOFT_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_TENANT_ID: Optional[str] = None
    
    # Google Workspace
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_PROJECT_ID: Optional[str] = None
    
    # Salesforce
    SALESFORCE_CLIENT_ID: Optional[str] = None
    SALESFORCE_CLIENT_SECRET: Optional[str] = None
    SALESFORCE_USERNAME: Optional[str] = None
    SALESFORCE_PASSWORD: Optional[str] = None
    SALESFORCE_SECURITY_TOKEN: Optional[str] = None
    
    # Slack
    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_CHANNEL: str = "#security-alerts"
    
    # Monitoring
    PROMETHEUS_PORT: int = 8001
    METRICS_ENABLED: bool = True
    
    # DLP
    MAX_FILE_SIZE_MB: int = 100
    SCAN_ENCRYPTED_FILES: bool = False
    SENSITIVE_DATA_PATTERNS: List[str] = ["ssn", "credit_card", "email", "phone"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
