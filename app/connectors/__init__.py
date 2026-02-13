"""
SaaS connectors package for integrating with various cloud applications.
"""

from .base import BaseConnector
from .microsoft365 import Microsoft365Connector
from .google_workspace import GoogleWorkspaceConnector
from .salesforce import SalesforceConnector

__all__ = [
    "BaseConnector",
    "Microsoft365Connector", 
    "GoogleWorkspaceConnector",
    "SalesforceConnector"
]
