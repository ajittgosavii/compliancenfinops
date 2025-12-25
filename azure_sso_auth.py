"""
Azure SSO Authentication Module for Cloud Compliance Canvas
============================================================
Implements Azure AD (Entra ID) SSO with role-based access control.

Supports:
- Azure AD SSO authentication via MSAL
- Role-based access control (RBAC)
- Session management
- Multi-tenant support

Roles:
- GlobalAdministrator: Full access to all features
- SecurityAdministrator: Security features, compliance, remediation
- ComplianceManager: Read compliance data, run reports
- FinOpsAnalyst: Cost analysis, optimization recommendations
- SecurityReader: Read-only access to security findings
- Viewer: Dashboard view only
"""

import streamlit as st
import msal
import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from functools import wraps
import hashlib
import secrets

# ============================================================================
# CONFIGURATION
# ============================================================================

def get_azure_config() -> Dict[str, Any]:
    """Get Azure AD configuration from Streamlit secrets"""
    try:
        azure_secrets = st.secrets.get('azure', {})
        return {
            'client_id': azure_secrets.get('client_id', ''),
            'client_secret': azure_secrets.get('client_secret', ''),
            'tenant_id': azure_secrets.get('tenant_id', ''),
            'redirect_uri': azure_secrets.get('redirect_uri', 'https://your-app.streamlit.app/'),
            'authority': f"https://login.microsoftonline.com/{azure_secrets.get('tenant_id', 'common')}",
            'scope': ['User.Read', 'GroupMember.Read.All'],
            'enabled': azure_secrets.get('enabled', False)
        }
    except Exception as e:
        print(f"Error loading Azure config: {e}")
        return {'enabled': False}


# ============================================================================
# ROLE DEFINITIONS
# ============================================================================

ROLES = {
    'GlobalAdministrator': {
        'display_name': 'Global Administrator',
        'description': 'Full access to all features and settings',
        'level': 100,
        'permissions': [
            'view_dashboard',
            'view_compliance',
            'view_security_findings',
            'view_finops',
            'view_accounts',
            'run_remediation',
            'approve_remediation',
            'manage_policies',
            'manage_users',
            'manage_settings',
            'export_reports',
            'view_audit_logs',
            'manage_integrations',
            'delete_resources'
        ],
        'color': '#dc3545'  # Red
    },
    'SecurityAdministrator': {
        'display_name': 'Security Administrator',
        'description': 'Manage security features, compliance, and remediation',
        'level': 80,
        'permissions': [
            'view_dashboard',
            'view_compliance',
            'view_security_findings',
            'view_finops',
            'view_accounts',
            'run_remediation',
            'approve_remediation',
            'manage_policies',
            'export_reports',
            'view_audit_logs'
        ],
        'color': '#fd7e14'  # Orange
    },
    'ComplianceManager': {
        'display_name': 'Compliance Manager',
        'description': 'View compliance data and run compliance reports',
        'level': 60,
        'permissions': [
            'view_dashboard',
            'view_compliance',
            'view_security_findings',
            'view_accounts',
            'export_reports',
            'run_remediation'
        ],
        'color': '#ffc107'  # Yellow
    },
    'FinOpsAnalyst': {
        'display_name': 'FinOps Analyst',
        'description': 'Cost analysis, optimization, and financial reporting',
        'level': 50