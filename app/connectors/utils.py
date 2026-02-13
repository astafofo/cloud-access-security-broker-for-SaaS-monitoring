"""
Utility functions for SaaS connectors.
"""

from typing import Dict, Any
from app.core.models import SaaSProvider
from app.connectors.microsoft365 import Microsoft365Connector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from app.connectors.salesforce import SalesforceConnector


def get_connector(provider: SaaSProvider, config: Dict[str, Any]):
    """Get appropriate connector for a SaaS provider."""
    connector_map = {
        SaaSProvider.MICROSOFT_365: Microsoft365Connector,
        SaaSProvider.GOOGLE_WORKSPACE: GoogleWorkspaceConnector,
        SaaSProvider.SALESFORCE: SalesforceConnector
    }
    
    connector_class = connector_map.get(provider)
    if not connector_class:
        return None
    
    return connector_class(config)
