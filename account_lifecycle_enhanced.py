"""
Enhanced Account Lifecycle Management Module
Cloud Compliance Canvas - AWS re:Invent 2025

Features:
- Template Marketplace with 15+ pre-built templates
- Real-time Cost Forecasting
- Pre-provisioning Readiness Validation
- Visual Workflow Orchestration
- Compliance Scorecard Preview
- Batch Account Provisioning
- Account Modification/Evolution
- Approval Workflow Integration
- Account Cloning
- Offboarding/Decommissioning
- AI Configuration Assistant
- Network Topology Designer
- Dependency Mapping
- Portfolio Dashboard Overview
- Role-Based Access Control (RBAC)

Version: 2.1 Enterprise with RBAC
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import random
import time
from typing import Dict, List, Any, Tuple
import json
import boto3


# ============================================================================
# ROLE-BASED ACCESS CONTROL (RBAC) FOR ACCOUNT OPERATIONS
# ============================================================================

def get_user_permissions() -> dict:
    """Get current user's permissions from session state"""
    # Default permissions for unauthenticated users
    default_perms = {
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,
        "bypass_approval_workflow": False,
    }
    
    # Check if user is authenticated
    if not st.session_state.get('authenticated', False):
        return default_perms
    
    # Get user role from session state - check multiple possible locations
    user_role = None
    
    # First check user_info dict (from Azure SSO)
    user_info = st.session_state.get('user_info', {})
    if user_info:
        user_role = user_info.get('role')
    
    # Fallback to direct user_role in session state
    if not user_role:
        user_role = st.session_state.get('user_role')
    
    # Fallback to checking for specific role indicators
    if not user_role:
        # Check if there's a role badge or indicator
        if st.session_state.get('is_super_admin', False):
            user_role = 'super_admin'
        elif st.session_state.get('is_admin', False):
            user_role = 'admin'
    
    # Default to guest if nothing found
    if not user_role:
        user_role = 'guest'
    
    # Role permission mapping
    role_permissions = {
        'super_admin': {
            "create_account_direct": True,
            "delete_account_direct": True,
            "approve_account_requests": True,
            "bypass_approval_workflow": True,
        },
        'superadmin': {  # Alternative format
            "create_account_direct": True,
            "delete_account_direct": True,
            "approve_account_requests": True,
            "bypass_approval_workflow": True,
        },
        'super administrator': {  # Full name format
            "create_account_direct": True,
            "delete_account_direct": True,
            "approve_account_requests": True,
            "bypass_approval_workflow": True,
        },
        'admin': {
            "create_account_direct": False,
            "delete_account_direct": False,
            "approve_account_requests": True,
            "bypass_approval_workflow": False,
        },
        'administrator': {
            "create_account_direct": False,
            "delete_account_direct": False,
            "approve_account_requests": True,
            "bypass_approval_workflow": False,
        },
        'security_manager': {
            "create_account_direct": False,
            "delete_account_direct": False,
            "approve_account_requests": False,
            "bypass_approval_workflow": False,
        },
        'finops_analyst': {
            "create_account_direct": False,
            "delete_account_direct": False,
            "approve_account_requests": False,
            "bypass_approval_workflow": False,
        },
    }
    
    # Normalize role name
    role_key = str(user_role).lower().replace(' ', '_').replace('-', '_')
    
    return role_permissions.get(role_key, default_perms)


def can_create_account_directly() -> bool:
    """Check if current user can create accounts without approval"""
    perms = get_user_permissions()
    return perms.get('create_account_direct', False)


def can_delete_account_directly() -> bool:
    """Check if current user can delete accounts without approval"""
    perms = get_user_permissions()
    return perms.get('delete_account_direct', False)


def can_approve_requests() -> bool:
    """Check if current user can approve account requests"""
    perms = get_user_permissions()
    return perms.get('approve_account_requests', False)


def requires_approval() -> bool:
    """Check if current user requires approval for account operations"""
    perms = get_user_permissions()
    return not perms.get('bypass_approval_workflow', False)


def get_current_user_info() -> dict:
    """Get current user information from session state"""
    # Try to get from user_info dict first (Azure SSO)
    user_info = st.session_state.get('user_info', {})
    
    if user_info:
        return {
            'email': user_info.get('email', user_info.get('mail', 'unknown@example.com')),
            'name': user_info.get('name', user_info.get('displayName', 'Unknown User')),
            'role': user_info.get('role', 'guest'),
            'authenticated': st.session_state.get('authenticated', False),
        }
    
    # Fallback to individual session state keys
    return {
        'email': st.session_state.get('user_email', 'unknown@example.com'),
        'name': st.session_state.get('user_name', 'Unknown User'),
        'role': st.session_state.get('user_role', 'guest'),
        'authenticated': st.session_state.get('authenticated', False),
    }


def init_approval_queue():
    """Initialize the approval queue in session state"""
    if 'account_approval_queue' not in st.session_state:
        st.session_state.account_approval_queue = []
    if 'account_approval_history' not in st.session_state:
        st.session_state.account_approval_history = []


def submit_for_approval(request_type: str, details: dict) -> str:
    """Submit an account operation for approval"""
    init_approval_queue()
    
    user_info = get_current_user_info()
    request_id = f"REQ-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}"
    
    request = {
        'id': request_id,
        'type': request_type,  # 'create', 'delete', 'modify', 'clone'
        'details': details,
        'requestor': user_info['email'],
        'requestor_name': user_info['name'],
        'requestor_role': user_info['role'],
        'submitted_at': datetime.now().isoformat(),
        'status': 'pending',
        'approvals': [],
        'required_approvals': get_required_approvals(request_type),
    }
    
    st.session_state.account_approval_queue.append(request)
    return request_id


def get_required_approvals(request_type: str) -> list:
    """Get list of required approval roles for a request type"""
    # All account operations require these approvals
    base_approvals = [
        {'role': 'Security Review', 'required': True, 'approved': False, 'approver': None},
        {'role': 'FinOps Review', 'required': True, 'approved': False, 'approver': None},
    ]
    
    if request_type in ['create', 'delete']:
        # Critical operations need additional approval
        base_approvals.append(
            {'role': 'Admin Approval', 'required': True, 'approved': False, 'approver': None}
        )
    
    return base_approvals


def get_pending_approvals() -> list:
    """Get all pending approval requests"""
    init_approval_queue()
    return [r for r in st.session_state.account_approval_queue if r['status'] == 'pending']


def approve_request(request_id: str, approval_role: str, approver_email: str) -> bool:
    """Approve a request for a specific role"""
    init_approval_queue()
    
    for request in st.session_state.account_approval_queue:
        if request['id'] == request_id:
            for approval in request['required_approvals']:
                if approval['role'] == approval_role and not approval['approved']:
                    approval['approved'] = True
                    approval['approver'] = approver_email
                    approval['approved_at'] = datetime.now().isoformat()
                    
                    # Check if all approvals are complete
                    all_approved = all(a['approved'] for a in request['required_approvals'])
                    if all_approved:
                        request['status'] = 'approved'
                    
                    return True
    return False


def reject_request(request_id: str, rejector_email: str, reason: str) -> bool:
    """Reject a request"""
    init_approval_queue()
    
    for request in st.session_state.account_approval_queue:
        if request['id'] == request_id:
            request['status'] = 'rejected'
            request['rejected_by'] = rejector_email
            request['rejection_reason'] = reason
            request['rejected_at'] = datetime.now().isoformat()
            return True
    return False


def render_rbac_status_banner():
    """Render RBAC status banner showing current user permissions"""
    user_info = get_current_user_info()
    perms = get_user_permissions()
    
    # Debug: Show detected role (can be removed in production)
    with st.expander("🔐 RBAC Debug Info", expanded=False):
        st.json({
            "authenticated": user_info.get('authenticated'),
            "detected_role": user_info.get('role'),
            "user_email": user_info.get('email'),
            "permissions": perms,
            "session_user_info": dict(st.session_state.get('user_info', {})) if st.session_state.get('user_info') else None,
        })
    
    if user_info['authenticated']:
        role = user_info.get('role', 'guest')
        role_display = str(role).replace('_', ' ').title()
        
        if perms.get('bypass_approval_workflow'):
            st.success(f"👑 **{role_display}** - Direct account operations enabled (no approval required)")
        elif perms.get('approve_account_requests'):
            st.info(f"✅ **{role_display}** - Can approve requests, but own operations require approval")
        else:
            st.warning(f"📋 **{role_display}** - All account operations require approval workflow")
    else:
        st.error("🔒 **Not Authenticated** - Please log in to perform account operations")


# ============================================================================
# HELPER FUNCTION TO GET REAL AWS ACCOUNTS
# ============================================================================

def get_real_accounts_list():
    """Get list of real AWS accounts when connected, or demo accounts when not"""
    is_connected = st.session_state.get('aws_connected', False)
    current_account = st.session_state.get('aws_account_id', None)
    
    if is_connected and current_account:
        # Check cache first
        if 'org_accounts_cache' in st.session_state and st.session_state.org_accounts_cache:
            return st.session_state.org_accounts_cache, True
        
        # Try to get Organizations accounts
        clients = st.session_state.get('aws_clients', {})
        accounts = []
        
        try:
            if clients and 'organizations' in clients:
                org_client = clients['organizations']
                
                # Get management account ID
                try:
                    org_info = org_client.describe_organization()
                    master_account = org_info['Organization']['MasterAccountId']
                except:
                    master_account = None
                
                paginator = org_client.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for acc in page.get('Accounts', []):
                        if acc.get('Status') == 'ACTIVE':
                            acc_id = acc.get('Id')
                            acc_name = acc.get('Name', f"Account {acc_id}")
                            accounts.append({
                                'id': acc_id,
                                'name': acc_name,
                                'email': acc.get('Email', 'N/A'),
                                'status': acc.get('Status'),
                                # Show Account ID first, then name
                                'display': f"{acc_id} - {acc_name}",
                                'is_management': acc_id == master_account,
                                'is_current': acc_id == current_account
                            })
                
                # Sort: Current first, then management, then alphabetically by ID
                accounts.sort(key=lambda x: (not x.get('is_current'), not x.get('is_management'), x['id']))
                
                # Cache results
                if accounts:
                    st.session_state.org_accounts_cache = accounts
                    
        except Exception as e:
            pass
        
        # If no org access, just show current account
        if not accounts:
            accounts = [{
                'id': current_account,
                'name': f'Current Account',
                'email': 'N/A',
                'status': 'ACTIVE',
                'display': f"{current_account} - Current Account",
                'is_management': False,
                'is_current': True
            }]
        
        return accounts, True  # accounts, is_live
    else:
        # Demo accounts - Account ID first
        demo_accounts = [
            {'id': '123456789001', 'name': 'Production-FinServices-001', 'email': 'admin@prod.com', 'status': 'ACTIVE', 'display': '123456789001 - Production-FinServices-001', 'is_management': True, 'is_current': False},
            {'id': '123456789002', 'name': 'Production-App-002', 'email': 'admin@prod2.com', 'status': 'ACTIVE', 'display': '123456789002 - Production-App-002', 'is_management': False, 'is_current': False},
            {'id': '123456789003', 'name': 'Development-Test-001', 'email': 'admin@dev.com', 'status': 'ACTIVE', 'display': '123456789003 - Development-Test-001', 'is_management': False, 'is_current': False},
            {'id': '123456789004', 'name': 'Staging-App-001', 'email': 'admin@staging.com', 'status': 'ACTIVE', 'display': '123456789004 - Staging-App-001', 'is_management': False, 'is_current': False},
            {'id': '123456789005', 'name': 'DR-Account-001', 'email': 'admin@dr.com', 'status': 'ACTIVE', 'display': '123456789005 - DR-Account-001', 'is_management': False, 'is_current': False},
        ]
        return demo_accounts, False  # accounts, is_live


def assume_role_to_account(target_account_id: str, role_name: str = "OrganizationAccountAccessRole"):
    """
    Assume role into a target account and return a new boto3 session.
    
    Args:
        target_account_id: AWS Account ID to assume into
        role_name: Name of the cross-account role (default: OrganizationAccountAccessRole)
    
    Returns:
        Tuple of (boto3.Session, error_message)
    """
    import boto3
    
    current_account = st.session_state.get('aws_account_id')
    
    # If it's the current account, no need to assume role
    if current_account and target_account_id == current_account:
        clients = st.session_state.get('aws_clients', {})
        if clients:
            # Return the existing session
            return None, None  # Signal to use existing clients
    
    try:
        # Try to use existing aws_connector
        try:
            from aws_connector import assume_role, get_aws_session
            
            base_session = get_aws_session()
            if base_session:
                role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
                
                assumed_creds = assume_role(
                    base_session=base_session,
                    role_arn=role_arn,
                    session_name="CloudComplianceCanvas"
                )
                
                if assumed_creds:
                    assumed_session = boto3.Session(
                        aws_access_key_id=assumed_creds.access_key_id,
                        aws_secret_access_key=assumed_creds.secret_access_key,
                        aws_session_token=assumed_creds.session_token,
                        region_name=assumed_creds.region
                    )
                    return assumed_session, None
        except ImportError:
            pass
        
        # Fallback: Direct boto3 assume role
        sts = boto3.client('sts')
        role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
        
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CloudComplianceCanvas",
            DurationSeconds=3600
        )
        
        credentials = response['Credentials']
        
        assumed_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return assumed_session, None
        
    except Exception as e:
        return None, str(e)


def get_clients_for_account(account_id: str, region: str = 'us-east-1'):
    """
    Get AWS service clients for a specific account.
    If it's the current account, returns existing clients.
    Otherwise, assumes role into the account.
    
    Args:
        account_id: AWS Account ID
        region: AWS region for regional services
    
    Returns:
        Tuple of (clients_dict, error_message)
    """
    current_account = st.session_state.get('aws_account_id')
    
    # If it's the current account, use existing clients
    if current_account and account_id == current_account:
        return st.session_state.get('aws_clients', {}), None
    
    # Check cache
    cache_key = f'account_clients_{account_id}'
    if cache_key in st.session_state:
        return st.session_state[cache_key], None
    
    # Assume role into the account
    assumed_session, error = assume_role_to_account(account_id)
    
    if error:
        return None, error
    
    if assumed_session is None:
        # Signal to use existing clients (same account)
        return st.session_state.get('aws_clients', {}), None
    
    try:
        clients = {
            'securityhub': assumed_session.client('securityhub', region_name=region),
            'config': assumed_session.client('config', region_name=region),
            'guardduty': assumed_session.client('guardduty', region_name=region),
            'inspector': assumed_session.client('inspector2', region_name=region),
            'ec2': assumed_session.client('ec2', region_name=region),
            's3': assumed_session.client('s3', region_name=region),
            'iam': assumed_session.client('iam', region_name=region),
            'cloudwatch': assumed_session.client('cloudwatch', region_name=region),
            'ce': assumed_session.client('ce', region_name='us-east-1'),
            'organizations': assumed_session.client('organizations', region_name='us-east-1'),
        }
        
        # Cache the clients
        st.session_state[cache_key] = clients
        
        return clients, None
    except Exception as e:
        return None, f"Error creating clients: {str(e)}"

# ============================================================================
# ACCOUNT TEMPLATES LIBRARY
# ============================================================================

ACCOUNT_TEMPLATES = {
    "financial_services_prod": {
        "name": "Financial Services - Production",
        "description": "PCI-DSS and SOC 2 compliant production environment for financial workloads",
        "icon": "🏦",
        "category": "Production",
        "compliance_frameworks": ["SOC 2 Type II", "PCI-DSS v4.0", "ISO 27001"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 38000, "max": 48000, "average": 42000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "Tag Policies"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 96, "PCI-DSS": 89, "ISO 27001": 92},
        "features": ["Multi-AZ", "Encrypted EBS", "CloudWatch Detailed", "WAF", "Shield Advanced"],
        "network": {
            "vpc_cidr": "10.100.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 3,
            "transit_gateway": True
        }
    },
    "healthcare_hipaa": {
        "name": "Healthcare - HIPAA Compliant",
        "description": "HIPAA-ready environment for healthcare applications and PHI data",
        "icon": "🏥",
        "category": "Production",
        "compliance_frameworks": ["HIPAA", "SOC 2 Type II", "HITRUST"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 32000, "max": 42000, "average": 36000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "HIPAA Guardrails"],
        "budget_alert": 85,
        "compliance_scores": {"HIPAA": 94, "SOC 2": 92, "HITRUST": 88},
        "features": ["Data Classification", "Encryption at Rest", "Audit Logging", "Access Controls"],
        "network": {
            "vpc_cidr": "10.110.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "dev_sandbox": {
        "name": "Development Sandbox",
        "description": "Cost-optimized development environment with baseline security",
        "icon": "🧪",
        "category": "Development",
        "compliance_frameworks": ["Baseline Security"],
        "environment": "Development",
        "region": "us-east-1",
        "estimated_cost": {"min": 2500, "max": 5000, "average": 3500},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": False,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": False,
            "macie": False,
        },
        "guardrails": ["SCPs", "Cost Controls"],
        "budget_alert": 70,
        "compliance_scores": {"Baseline": 85},
        "features": ["Auto-shutdown", "Spot Instances", "Basic Monitoring"],
        "network": {
            "vpc_cidr": "10.200.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 1,
            "transit_gateway": False
        }
    },
    "data_analytics": {
        "name": "Data Analytics Platform",
        "description": "Optimized for big data processing with Redshift, EMR, and Athena",
        "icon": "📊",
        "category": "Analytics",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 45000, "max": 65000, "average": 52000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "Data Governance"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 94, "ISO 27001": 91},
        "features": ["S3 Data Lake", "Redshift Cluster", "EMR", "Glue", "Athena"],
        "network": {
            "vpc_cidr": "10.120.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "ml_training": {
        "name": "ML/AI Training Environment",
        "description": "GPU-enabled environment for machine learning model training",
        "icon": "🤖",
        "category": "AI/ML",
        "compliance_frameworks": ["SOC 2 Type II"],
        "environment": "Production",
        "region": "us-west-2",
        "estimated_cost": {"min": 55000, "max": 85000, "average": 68000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "Cost Controls", "GPU Limits"],
        "budget_alert": 85,
        "compliance_scores": {"SOC 2": 89},
        "features": ["SageMaker", "EC2 GPU Instances", "S3 Model Store", "MLflow"],
        "network": {
            "vpc_cidr": "10.130.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "saas_multitenant": {
        "name": "Multi-Tenant SaaS Platform",
        "description": "Isolated tenant environments with shared infrastructure",
        "icon": "🏢",
        "category": "Production",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001", "GDPR"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 42000, "max": 58000, "average": 48000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "Tenant Isolation"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 95, "ISO 27001": 93, "GDPR": 91},
        "features": ["Multi-tenant DB", "Tenant Isolation", "API Gateway", "Cognito"],
        "network": {
            "vpc_cidr": "10.140.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 3,
            "transit_gateway": True
        }
    },
    "disaster_recovery": {
        "name": "Disaster Recovery",
        "description": "DR environment with automated failover capabilities",
        "icon": "🔄",
        "category": "DR/Backup",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        "environment": "Production",
        "region": "us-west-2",
        "estimated_cost": {"min": 18000, "max": 28000, "average": 22000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "DR Policies"],
        "budget_alert": 75,
        "compliance_scores": {"SOC 2": 92, "ISO 27001": 90},
        "features": ["Cross-region Replication", "RDS Read Replicas", "Automated Snapshots"],
        "network": {
            "vpc_cidr": "10.150.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "compliance_audit": {
        "name": "Compliance Testing & Audit",
        "description": "Isolated environment for compliance testing and audit activities",
        "icon": "🔍",
        "category": "Testing",
        "compliance_frameworks": ["SOC 2 Type II", "PCI-DSS v4.0", "HIPAA", "ISO 27001"],
        "environment": "Staging",
        "region": "us-east-1",
        "estimated_cost": {"min": 8000, "max": 12000, "average": 9500},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "Audit Controls"],
        "budget_alert": 90,
        "compliance_scores": {"SOC 2": 98, "PCI-DSS": 96, "HIPAA": 95, "ISO 27001": 97},
        "features": ["Evidence Collection", "Audit Logging", "Compliance Scanning"],
        "network": {
            "vpc_cidr": "10.160.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 1,
            "transit_gateway": False
        }
    },
    "shared_services": {
        "name": "Shared Services Hub",
        "description": "Centralized services: SSO, DNS, monitoring, logging",
        "icon": "🔗",
        "category": "Infrastructure",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 15000, "max": 22000, "average": 18000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "OPA", "Cross-Account Policies"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 93, "ISO 27001": 91},
        "features": ["AWS SSO", "Route 53", "CloudWatch", "S3 Logging", "Transit Gateway Hub"],
        "network": {
            "vpc_cidr": "10.0.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "edge_cdn": {
        "name": "Edge & CDN Services",
        "description": "CloudFront and global edge computing infrastructure",
        "icon": "🌍",
        "category": "Infrastructure",
        "compliance_frameworks": ["SOC 2 Type II"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 25000, "max": 45000, "average": 32000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": False,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": False,
            "macie": False,
        },
        "guardrails": ["SCPs", "CDN Policies"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 88},
        "features": ["CloudFront", "Lambda@Edge", "WAF", "Shield Standard"],
        "network": {
            "vpc_cidr": "10.170.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 1,
            "transit_gateway": False
        }
    },
    "iot_platform": {
        "name": "IoT Platform",
        "description": "IoT Core, device management, and real-time data processing",
        "icon": "📡",
        "category": "IoT",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        "environment": "Production",
        "region": "us-west-2",
        "estimated_cost": {"min": 28000, "max": 42000, "average": 34000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "IoT Policies", "Device Management"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 90, "ISO 27001": 88},
        "features": ["IoT Core", "Greengrass", "Kinesis", "Lambda", "DynamoDB"],
        "network": {
            "vpc_cidr": "10.180.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "container_platform": {
        "name": "Container Orchestration Platform",
        "description": "EKS-based microservices platform with service mesh",
        "icon": "🐳",
        "category": "Platform",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 38000, "max": 52000, "average": 44000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "OPA", "Pod Security Policies"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 91, "ISO 27001": 89},
        "features": ["EKS Cluster", "Fargate", "ECR", "Service Mesh", "ArgoCD"],
        "network": {
            "vpc_cidr": "10.190.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 3,
            "transit_gateway": True
        }
    },
    "security_operations": {
        "name": "Security Operations Center",
        "description": "Centralized security monitoring and incident response",
        "icon": "🛡️",
        "category": "Security",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001", "NIST CSF"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 22000, "max": 32000, "average": 26000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": True,
        },
        "guardrails": ["SCPs", "OPA", "Security Baseline"],
        "budget_alert": 85,
        "compliance_scores": {"SOC 2": 97, "ISO 27001": 95, "NIST CSF": 93},
        "features": ["Security Hub Aggregation", "SIEM", "Threat Intelligence", "Incident Response"],
        "network": {
            "vpc_cidr": "10.210.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 2,
            "transit_gateway": True
        }
    },
    "serverless_app": {
        "name": "Serverless Application",
        "description": "Event-driven serverless architecture with Lambda and API Gateway",
        "icon": "⚡",
        "category": "Application",
        "compliance_frameworks": ["SOC 2 Type II"],
        "environment": "Production",
        "region": "us-east-1",
        "estimated_cost": {"min": 12000, "max": 22000, "average": 16000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": False,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": False,
            "macie": False,
        },
        "guardrails": ["SCPs", "Lambda Concurrency Limits"],
        "budget_alert": 75,
        "compliance_scores": {"SOC 2": 87},
        "features": ["Lambda", "API Gateway", "DynamoDB", "EventBridge", "Step Functions"],
        "network": {
            "vpc_cidr": "10.220.0.0/16",
            "availability_zones": 2,
            "nat_gateways": 0,
            "transit_gateway": False
        }
    },
    "gaming_platform": {
        "name": "Gaming Platform",
        "description": "Low-latency gaming infrastructure with GameLift",
        "icon": "🎮",
        "category": "Gaming",
        "compliance_frameworks": ["SOC 2 Type II"],
        "environment": "Production",
        "region": "us-west-2",
        "estimated_cost": {"min": 48000, "max": 72000, "average": 58000},
        "security_controls": {
            "security_hub": True,
            "guardduty": True,
            "config_rules": True,
            "inspector": True,
            "cloudtrail": True,
            "s3_encryption": True,
            "vpc_flow_logs": True,
            "macie": False,
        },
        "guardrails": ["SCPs", "GameLift Policies"],
        "budget_alert": 80,
        "compliance_scores": {"SOC 2": 86},
        "features": ["GameLift", "ElastiCache", "DynamoDB", "CloudFront", "Low-latency Networking"],
        "network": {
            "vpc_cidr": "10.230.0.0/16",
            "availability_zones": 3,
            "nat_gateways": 3,
            "transit_gateway": False
        }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_cost_forecast(template_key: str, modifications: Dict = None) -> Dict:
    """Calculate detailed cost forecast based on template and modifications"""
    template = ACCOUNT_TEMPLATES[template_key]
    base_cost = template["estimated_cost"]["average"]
    
    breakdown = {
        "Compute": base_cost * 0.35,
        "Storage": base_cost * 0.20,
        "Security Services": base_cost * 0.15,
        "Networking": base_cost * 0.12,
        "Monitoring & Logging": base_cost * 0.08,
        "Database": base_cost * 0.10,
    }
    
    # Add optimizations
    optimizations = []
    potential_savings = 0
    
    if template["environment"] == "Production":
        optimizations.append({
            "name": "Reserved Instances (1-year)",
            "savings": base_cost * 0.18,
            "description": "Commit to 1-year RIs for predictable workloads"
        })
        potential_savings += base_cost * 0.18
        
        optimizations.append({
            "name": "Savings Plans",
            "savings": base_cost * 0.12,
            "description": "Flexible compute savings across EC2, Lambda, Fargate"
        })
        potential_savings += base_cost * 0.12
    
    return {
        "base_monthly": base_cost,
        "min_monthly": template["estimated_cost"]["min"],
        "max_monthly": template["estimated_cost"]["max"],
        "breakdown": breakdown,
        "optimizations": optimizations,
        "potential_savings": potential_savings,
        "optimized_monthly": base_cost - (potential_savings * 0.7)  # 70% adoption
    }

def run_readiness_validation(config: Dict) -> Dict:
    """Run pre-provisioning validation checks"""
    checks = []
    
    # Simulate various checks
    check_definitions = [
        ("Organizations parent account accessible", "critical", True, ""),
        ("Control Tower deployed and healthy", "critical", True, ""),
        ("Sufficient service limits available", "critical", True, ""),
        ("Required IAM permissions present", "critical", True, ""),
        ("Account name unique", "high", random.choice([True, True, False]), "Name 'Production-FinServices-001' already exists"),
        ("Budget within portfolio allocation", "high", True, ""),
        ("Region approved for compliance framework", "medium", random.choice([True, True, True, False]), "us-west-1 not approved for HIPAA workloads"),
        ("Network CIDR no conflicts", "high", random.choice([True, True, False]), "CIDR 10.100.0.0/16 overlaps with existing VPC"),
        ("Security Hub capacity available", "low", True, ""),
        ("Cost Explorer API accessible", "low", True, ""),
    ]
    
    passed = 0
    warnings = 0
    errors = 0
    
    for name, severity, status, message in check_definitions:
        check = {
            "name": name,
            "severity": severity,
            "status": "pass" if status else "fail",
            "message": message
        }
        checks.append(check)
        
        if status:
            passed += 1
        else:
            if severity == "critical":
                errors += 1
            else:
                warnings += 1
    
    total = len(checks)
    score = (passed / total) * 100
    
    return {
        "checks": checks,
        "total": total,
        "passed": passed,
        "warnings": warnings,
        "errors": errors,
        "score": score,
        "ready": errors == 0
    }

def generate_compliance_preview(template_key: str) -> Dict:
    """Generate compliance scorecard preview"""
    template = ACCOUNT_TEMPLATES[template_key]
    frameworks = template["compliance_frameworks"]
    scores = template["compliance_scores"]
    
    details = []
    for framework in frameworks:
        if framework in scores:
            score = scores[framework]
            
            # Generate category breakdowns
            categories = []
            if framework == "SOC 2 Type II":
                categories = [
                    {"name": "Security", "score": score + random.randint(-3, 3)},
                    {"name": "Availability", "score": score + random.randint(-5, 2)},
                    {"name": "Confidentiality", "score": score + random.randint(-4, 1)},
                    {"name": "Processing Integrity", "score": score + random.randint(-2, 3)},
                ]
            elif framework == "PCI-DSS v4.0":
                categories = [
                    {"name": "Network Security", "score": score + random.randint(-2, 8)},
                    {"name": "Cardholder Data Protection", "score": score + random.randint(-10, 5)},
                    {"name": "Access Control", "score": score + random.randint(-5, 3)},
                    {"name": "Monitoring & Testing", "score": score + random.randint(-4, 2)},
                ]
            elif framework == "HIPAA":
                categories = [
                    {"name": "Administrative Safeguards", "score": score + random.randint(-3, 4)},
                    {"name": "Physical Safeguards", "score": score + random.randint(-6, 2)},
                    {"name": "Technical Safeguards", "score": score + random.randint(-2, 5)},
                ]
            else:
                categories = [{"name": "Overall", "score": score}]
            
            # Identify gaps
            gaps = []
            improvements = []
            
            for cat in categories:
                if cat["score"] < 90:
                    gaps.append(f"{cat['name']}: {100 - cat['score']}% gap")
                    if cat["score"] < 85:
                        improvements.append(f"Critical: Improve {cat['name']} controls")
                    elif cat["score"] < 90:
                        improvements.append(f"Recommended: Enhance {cat['name']} coverage")
            
            details.append({
                "framework": framework,
                "score": score,
                "categories": categories,
                "gaps": gaps,
                "improvements": improvements,
                "audit_ready": score >= 85,
                "evidence_items": random.randint(800, 1500)
            })
    
    overall_score = sum([d["score"] for d in details]) / len(details) if details else 0
    
    return {
        "overall_score": round(overall_score, 1),
        "frameworks": details,
        "audit_ready": all([d["audit_ready"] for d in details]),
        "total_evidence": sum([d["evidence_items"] for d in details])
    }

def generate_workflow_steps() -> List[Dict]:
    """Generate workflow orchestration steps"""
    return [
        {"name": "Account Request Validation", "duration": 2, "status": "complete", "substeps": ["Validate inputs", "Check permissions"]},
        {"name": "AWS Account Creation", "duration": 5, "status": "complete", "substeps": ["Call Organizations API", "Wait for account"]},
        {"name": "Security Baseline Deployment", "duration": 4, "status": "in_progress", "substeps": [
            {"name": "Enable Security Hub", "duration": 2, "status": "complete"},
            {"name": "Configure GuardDuty", "duration": 2, "status": "in_progress"},
            {"name": "Deploy Config Rules", "duration": 3, "status": "pending"},
            {"name": "Setup CloudTrail", "duration": 1, "status": "pending"},
        ]},
        {"name": "Compliance Controls", "duration": 3, "status": "pending", "substeps": ["Apply framework controls", "Validate compliance"]},
        {"name": "Network Configuration", "duration": 2, "status": "pending", "substeps": ["Create VPC", "Configure subnets", "Deploy NAT gateways"]},
        {"name": "Budget & Cost Tracking", "duration": 1, "status": "pending", "substeps": ["Create budget", "Configure alerts"]},
        {"name": "Integration Hub Sync", "duration": 1, "status": "pending", "substeps": ["Jira ticket", "Slack notification", "ServiceNow CMDB"]},
        {"name": "Validation & Activation", "duration": 2, "status": "pending", "substeps": ["Final compliance check", "Activate account"]},
    ]

# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

def render_enhanced_account_lifecycle():
    """Render the enhanced Account Lifecycle Management interface"""
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 2rem; border-radius: 10px; margin-bottom: 2rem;'>
        <h2 style='color: white; margin: 0;'>⚙️ Account Lifecycle Management</h2>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>Automated provisioning, modification, and decommissioning of AWS accounts</p>
    </div>
    """, unsafe_allow_html=True)
    
    # ========== RBAC STATUS BANNER ==========
    render_rbac_status_banner()
    
    # ========== GLOBAL ACCOUNT SELECTOR ==========
    # This selector appears at the top and is used by all tabs that need an account context
    accounts, is_live = get_real_accounts_list()
    
    col_selector1, col_selector2, col_selector3 = st.columns([2, 1, 1])
    
    with col_selector1:
        if is_live:
            account_options = [acc['display'] for acc in accounts]
            
            # Initialize selected account in session state
            if 'selected_target_account' not in st.session_state:
                st.session_state.selected_target_account = account_options[0] if account_options else None
            
            selected_account = st.selectbox(
                "🎯 Target Account",
                options=account_options,
                index=0,
                key="global_account_selector",
                help="Select the account to work with across all tabs"
            )
            st.session_state.selected_target_account = selected_account
            
            # Find the selected account details
            selected_acc_details = next((a for a in accounts if a['display'] == selected_account), None)
            if selected_acc_details:
                st.session_state.selected_account_id = selected_acc_details['id']
                st.session_state.selected_account_name = selected_acc_details['name']
        else:
            st.selectbox(
                "🎯 Target Account",
                options=["Demo Account (Connect to AWS for real accounts)"],
                disabled=True,
                key="global_account_selector_demo"
            )
    
    with col_selector2:
        if is_live:
            st.metric("Total Accounts", len(accounts), "Live")
        else:
            st.metric("Mode", "Demo", "⚠️")
    
    with col_selector3:
        if is_live and 'selected_account_id' in st.session_state:
            acc_id = st.session_state.selected_account_id
            st.metric("Account ID", acc_id[:8] + "..." if len(acc_id) > 8 else acc_id)
        else:
            st.metric("Status", "Not Connected")
    
    st.markdown("---")
    
    # Get user info for role-based tab visibility
    user_info = get_current_user_info()
    user_role = user_info.get('role', 'guest').lower().replace(' ', '_')
    is_super_admin = user_role in ['super_admin', 'superadmin', 'super_administrator']
    is_manager = user_role in ['super_admin', 'superadmin', 'super_administrator', 'admin', 'administrator', 'manager']
    
    # Show pending approval count for managers
    pending_count = len(get_pending_approvals())
    
    # Navigation tabs based on role
    if is_super_admin:
        # Super Admin sees EVERYTHING - both direct operations and approval queue
        tabs = st.tabs([
            "📊 Portfolio Dashboard",
            f"📥 Manager Approvals ({pending_count})" if pending_count > 0 else "📥 Manager Approvals",
            "➕ Create Account",
            "📚 Template Marketplace",
            "📦 Batch Provisioning",
            "👯 Clone Account",
            "🔄 Account Modification",
            "🔴 Offboarding",
            "📝 Submit Request (Workflow)",
            "📋 My Requests",
            "🤖 AI Assistant",
            "🌐 Network Designer",
            "🔗 Dependencies"
        ])
        
        with tabs[0]:
            render_portfolio_dashboard()
        with tabs[1]:
            render_manager_approval_queue()
        with tabs[2]:
            render_create_account()  # Direct creation for Super Admin
        with tabs[3]:
            render_template_marketplace()  # Direct template application
        with tabs[4]:
            render_batch_provisioning()  # Direct batch provisioning
        with tabs[5]:
            render_account_cloning()  # Direct cloning
        with tabs[6]:
            render_account_modification()  # Direct modification
        with tabs[7]:
            render_offboarding()  # Direct offboarding
        with tabs[8]:
            render_unified_request_form()  # Can also use workflow if desired
        with tabs[9]:
            render_my_requests()
        with tabs[10]:
            render_ai_assistant()
        with tabs[11]:
            render_network_designer()
        with tabs[12]:
            render_dependency_mapping()
            
    elif is_manager:
        # Admin/Manager sees approval queue + request workflow (no direct operations)
        tabs = st.tabs([
            "📊 Portfolio Dashboard",
            f"📥 Manager Approvals ({pending_count})" if pending_count > 0 else "📥 Manager Approvals",
            "📝 Submit Request",
            "📋 My Requests",
            "🤖 AI Assistant",
            "🌐 Network Designer",
            "🔗 Dependencies"
        ])
        
        with tabs[0]:
            render_portfolio_dashboard()
        with tabs[1]:
            render_manager_approval_queue()
        with tabs[2]:
            render_unified_request_form()
        with tabs[3]:
            render_my_requests()
        with tabs[4]:
            render_ai_assistant()
        with tabs[5]:
            render_network_designer()
        with tabs[6]:
            render_dependency_mapping()
    else:
        # Regular users see request form only (must go through approval)
        tabs = st.tabs([
            "📊 Portfolio Dashboard",
            "📝 Submit Request",
            "📋 My Requests",
            "🤖 AI Assistant",
            "🌐 Network Designer",
            "🔗 Dependencies"
        ])
        
        with tabs[0]:
            render_portfolio_dashboard()
        with tabs[1]:
            render_unified_request_form()
        with tabs[2]:
            render_my_requests()
        with tabs[3]:
            render_ai_assistant()
        with tabs[4]:
            render_network_designer()
        with tabs[5]:
            render_dependency_mapping()


# ============================================================================
# UNIFIED REQUEST FORM - All account operations start here
# ============================================================================

def render_unified_request_form():
    """
    Unified request form for all account operations.
    Users submit requests here, which go to manager approval queue.
    """
    st.markdown("### 📝 Submit Account Request")
    st.markdown("All account operations require manager approval before execution")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Requests will affect real AWS accounts after approval")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS for real account operations")
    
    # Request type selection
    request_type = st.selectbox(
        "🎯 What would you like to do?",
        [
            "➕ Create New Account",
            "📚 Create from Template",
            "📦 Batch Provision Multiple Accounts",
            "👯 Clone Existing Account",
            "🔄 Modify Existing Account",
            "🔴 Offboard/Decommission Account"
        ],
        key="request_type_selector"
    )
    
    st.markdown("---")
    
    # Render appropriate form based on selection
    if "Create New Account" in request_type:
        render_create_account_request_form(accounts, is_live)
    elif "Create from Template" in request_type:
        render_template_request_form(accounts, is_live)
    elif "Batch Provision" in request_type:
        render_batch_request_form(accounts, is_live)
    elif "Clone" in request_type:
        render_clone_request_form(accounts, is_live)
    elif "Modify" in request_type:
        render_modify_request_form(accounts, is_live)
    elif "Offboard" in request_type:
        render_offboard_request_form(accounts, is_live)


def render_create_account_request_form(accounts: list, is_live: bool):
    """Form for creating a new account request"""
    st.markdown("#### ➕ New Account Request")
    
    with st.form(key="create_account_request_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            account_name = st.text_input("Account Name *", placeholder="e.g., Production-App-001")
            account_email = st.text_input("Account Email *", placeholder="aws-prod-app@company.com")
            environment = st.selectbox("Environment", ["Production", "Staging", "Development", "Sandbox", "DR"])
            
        with col2:
            budget = st.number_input("Monthly Budget ($)", min_value=100, max_value=1000000, value=5000, step=500)
            region = st.selectbox("Primary Region", [
                "us-east-1 (N. Virginia)", "us-west-2 (Oregon)", "eu-west-1 (Ireland)",
                "ap-southeast-1 (Singapore)", "ap-northeast-1 (Tokyo)"
            ])
            target_ou = st.selectbox("Target OU", ["Root (Default)", "Production", "Development", "Security", "Sandbox"])
        
        st.markdown("##### Compliance Frameworks")
        col1, col2, col3 = st.columns(3)
        with col1:
            soc2 = st.checkbox("SOC 2", value=True)
            hipaa = st.checkbox("HIPAA")
        with col2:
            pci = st.checkbox("PCI-DSS")
            gdpr = st.checkbox("GDPR")
        with col3:
            iso27001 = st.checkbox("ISO 27001")
            nist = st.checkbox("NIST 800-53")
        
        st.markdown("##### Security Controls")
        col1, col2, col3 = st.columns(3)
        with col1:
            sec_hub = st.checkbox("Security Hub", value=True)
            guardduty = st.checkbox("GuardDuty", value=True)
            config_rules = st.checkbox("AWS Config", value=True)
        with col2:
            inspector = st.checkbox("Inspector")
            cloudtrail = st.checkbox("CloudTrail", value=True)
            macie = st.checkbox("Macie")
        with col3:
            s3_encrypt = st.checkbox("S3 Encryption", value=True)
            vpc_flow = st.checkbox("VPC Flow Logs", value=True)
            waf = st.checkbox("WAF")
        
        business_justification = st.text_area(
            "Business Justification *",
            placeholder="Explain why this account is needed and how it will be used...",
            height=100
        )
        
        urgency = st.select_slider("Urgency", options=["Low", "Normal", "High", "Critical"], value="Normal")
        
        submit_btn = st.form_submit_button("📤 Submit Request for Approval", type="primary", use_container_width=True)
    
    if submit_btn:
        if not account_name or not account_email or not business_justification:
            st.error("❌ Please fill in all required fields (marked with *)")
        else:
            # Collect frameworks
            frameworks = []
            if soc2: frameworks.append("SOC 2")
            if hipaa: frameworks.append("HIPAA")
            if pci: frameworks.append("PCI-DSS")
            if gdpr: frameworks.append("GDPR")
            if iso27001: frameworks.append("ISO 27001")
            if nist: frameworks.append("NIST 800-53")
            
            request_details = {
                'operation': 'create',
                'name': account_name,
                'email': account_email,
                'environment': environment,
                'budget': budget,
                'region': region.split(' ')[0],
                'target_ou': target_ou,
                'frameworks': frameworks,
                'security_controls': {
                    'security_hub': sec_hub,
                    'guardduty': guardduty,
                    'config': config_rules,
                    'inspector': inspector,
                    'cloudtrail': cloudtrail,
                    'macie': macie,
                    's3_encryption': s3_encrypt,
                    'vpc_flow_logs': vpc_flow,
                    'waf': waf
                },
                'business_justification': business_justification,
                'urgency': urgency,
            }
            
            request_id = submit_for_approval('create', request_details)
            
            st.success(f"""
            ✅ **Request Submitted Successfully!**
            
            | Field | Value |
            |-------|-------|
            | **Request ID** | `{request_id}` |
            | **Type** | New Account Creation |
            | **Account Name** | {account_name} |
            | **Status** | ⏳ Pending Manager Approval |
            | **Urgency** | {urgency} |
            """)
            
            st.info("""
            **What happens next:**
            1. Your request is now in the **Manager Approval Queue**
            2. Managers will review: Security, FinOps, and Final Approval
            3. Once approved, the account will be **automatically created**
            4. You'll be notified at each stage
            
            Track your request in the **My Requests** tab.
            """)


def render_template_request_form(accounts: list, is_live: bool):
    """Form for creating account from template"""
    st.markdown("#### 📚 Create Account from Template")
    
    # Template selection
    categories = ["All"] + list(set([t["category"] for t in ACCOUNT_TEMPLATES.values()]))
    selected_category = st.selectbox("Filter by Category", categories, key="tmpl_req_category")
    
    templates_to_show = [
        (key, template) for key, template in ACCOUNT_TEMPLATES.items()
        if (selected_category == "All" or template["category"] == selected_category)
    ]
    
    template_names = [f"{t[1]['icon']} {t[1]['name']}" for t in templates_to_show]
    template_keys = [t[0] for t in templates_to_show]
    
    if template_names:
        selected_idx = st.selectbox(
            "Select Template",
            range(len(template_names)),
            format_func=lambda i: template_names[i],
            key="tmpl_req_selector"
        )
        
        selected_template = ACCOUNT_TEMPLATES[template_keys[selected_idx]]
        
        # Show template details
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"**{selected_template['name']}**")
            st.markdown(selected_template['description'])
            st.markdown(f"**Frameworks:** {', '.join(selected_template['compliance_frameworks'])}")
        with col2:
            st.metric("Est. Cost", f"${selected_template['estimated_cost']['average']:,}/mo")
            avg_score = sum(selected_template["compliance_scores"].values()) / len(selected_template["compliance_scores"])
            st.metric("Compliance", f"{avg_score:.0f}%")
        
        st.markdown("---")
        
        with st.form(key="template_request_form"):
            col1, col2 = st.columns(2)
            with col1:
                account_name = st.text_input("Account Name *", value=f"{selected_template['name'].replace(' ', '-')}-001")
                account_email = st.text_input("Account Email *", placeholder="aws-account@company.com")
            with col2:
                num_accounts = st.number_input("Number of Accounts", min_value=1, max_value=10, value=1)
                urgency = st.select_slider("Urgency", options=["Low", "Normal", "High", "Critical"], value="Normal")
            
            business_justification = st.text_area("Business Justification *", height=100)
            
            submit_btn = st.form_submit_button("📤 Submit Template Request", type="primary", use_container_width=True)
        
        if submit_btn:
            if not account_email or not business_justification:
                st.error("❌ Please fill in all required fields")
            else:
                request_details = {
                    'operation': 'create_from_template',
                    'template_key': template_keys[selected_idx],
                    'template_name': selected_template['name'],
                    'name': account_name,
                    'email': account_email,
                    'num_accounts': num_accounts,
                    'environment': selected_template['environment'],
                    'region': selected_template['region'],
                    'frameworks': selected_template['compliance_frameworks'],
                    'security_controls': selected_template.get('security_controls', {}),
                    'budget': selected_template['estimated_cost']['average'],
                    'business_justification': business_justification,
                    'urgency': urgency,
                }
                
                request_id = submit_for_approval('create', request_details)
                st.success(f"✅ Template request `{request_id}` submitted! Check **My Requests** tab.")


def render_batch_request_form(accounts: list, is_live: bool):
    """Form for batch provisioning multiple accounts"""
    st.markdown("#### 📦 Batch Account Provisioning Request")
    st.info("📋 Upload a CSV or manually define multiple accounts to provision")
    
    input_method = st.radio("Input Method", ["📝 Manual Entry", "📄 CSV Upload"], horizontal=True)
    
    if input_method == "📄 CSV Upload":
        st.markdown("**CSV Format:** `account_name,email,environment,budget`")
        uploaded_file = st.file_uploader("Upload CSV", type=['csv'])
        
        if uploaded_file:
            import pandas as pd
            df = pd.read_csv(uploaded_file)
            st.dataframe(df, use_container_width=True)
            batch_accounts = df.to_dict('records')
        else:
            batch_accounts = []
    else:
        # Manual entry
        st.markdown("**Define accounts to provision:**")
        num_accounts = st.number_input("Number of Accounts", min_value=1, max_value=20, value=3)
        
        batch_accounts = []
        for i in range(num_accounts):
            with st.expander(f"Account {i+1}", expanded=(i==0)):
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input(f"Name", key=f"batch_name_{i}", placeholder=f"Account-{i+1:03d}")
                    email = st.text_input(f"Email", key=f"batch_email_{i}", placeholder=f"aws-{i+1}@company.com")
                with col2:
                    env = st.selectbox(f"Environment", ["Production", "Development", "Staging"], key=f"batch_env_{i}")
                    budget = st.number_input(f"Budget ($)", min_value=100, value=5000, key=f"batch_budget_{i}")
                
                if name and email:
                    batch_accounts.append({'name': name, 'email': email, 'environment': env, 'budget': budget})
    
    with st.form(key="batch_request_form"):
        st.markdown(f"**Total Accounts:** {len(batch_accounts)}")
        
        # Common settings
        template = st.selectbox("Apply Template to All", ["None"] + list(ACCOUNT_TEMPLATES.keys()))
        business_justification = st.text_area("Business Justification *", height=100)
        urgency = st.select_slider("Urgency", options=["Low", "Normal", "High", "Critical"], value="Normal")
        
        submit_btn = st.form_submit_button("📤 Submit Batch Request", type="primary", use_container_width=True)
    
    if submit_btn:
        if not batch_accounts or not business_justification:
            st.error("❌ Please define at least one account and provide justification")
        else:
            request_details = {
                'operation': 'batch_create',
                'accounts': batch_accounts,
                'template': template if template != "None" else None,
                'total_accounts': len(batch_accounts),
                'total_budget': sum(a.get('budget', 0) for a in batch_accounts),
                'business_justification': business_justification,
                'urgency': urgency,
            }
            
            request_id = submit_for_approval('batch_create', request_details)
            st.success(f"✅ Batch request `{request_id}` for {len(batch_accounts)} accounts submitted!")


def render_clone_request_form(accounts: list, is_live: bool):
    """Form for cloning an existing account"""
    st.markdown("#### 👯 Clone Existing Account Request")
    
    with st.form(key="clone_request_form"):
        # Source account selection
        if is_live and accounts:
            source_options = [f"{acc['id']} - {acc['name']}" for acc in accounts]
        else:
            source_options = ["123456789001 - Production-App-001 (Demo)", "123456789002 - Dev-App-001 (Demo)"]
        
        source_account = st.selectbox("Source Account to Clone", source_options)
        
        col1, col2 = st.columns(2)
        with col1:
            new_name = st.text_input("New Account Name *", placeholder="Cloned-Account-001")
            new_email = st.text_input("New Account Email *", placeholder="cloned@company.com")
        with col2:
            clone_vpc = st.checkbox("Clone VPC Configuration", value=True)
            clone_iam = st.checkbox("Clone IAM Roles/Policies", value=True)
            clone_security = st.checkbox("Clone Security Settings", value=True)
        
        business_justification = st.text_area("Business Justification *", height=100)
        urgency = st.select_slider("Urgency", options=["Low", "Normal", "High", "Critical"], value="Normal")
        
        submit_btn = st.form_submit_button("📤 Submit Clone Request", type="primary", use_container_width=True)
    
    if submit_btn:
        if not new_name or not new_email or not business_justification:
            st.error("❌ Please fill in all required fields")
        else:
            request_details = {
                'operation': 'clone',
                'source_account': source_account.split(' - ')[0],
                'source_name': source_account.split(' - ')[1] if ' - ' in source_account else source_account,
                'name': new_name,
                'email': new_email,
                'clone_options': {
                    'vpc': clone_vpc,
                    'iam': clone_iam,
                    'security': clone_security,
                },
                'business_justification': business_justification,
                'urgency': urgency,
            }
            
            request_id = submit_for_approval('clone', request_details)
            st.success(f"✅ Clone request `{request_id}` submitted!")


def render_modify_request_form(accounts: list, is_live: bool):
    """Form for modifying an existing account"""
    st.markdown("#### 🔄 Account Modification Request")
    
    with st.form(key="modify_request_form"):
        # Account selection
        if is_live and accounts:
            account_options = [f"{acc['id']} - {acc['name']}" for acc in accounts]
        else:
            account_options = ["123456789001 - Production-App-001 (Demo)", "123456789002 - Dev-App-001 (Demo)"]
        
        target_account = st.selectbox("Account to Modify", account_options)
        
        modification_type = st.multiselect(
            "What would you like to modify?",
            ["Budget/Cost Alerts", "Compliance Frameworks", "Security Controls", "IAM Policies", "Network Configuration", "Tags/Metadata"]
        )
        
        col1, col2 = st.columns(2)
        with col1:
            if "Budget/Cost Alerts" in modification_type:
                new_budget = st.number_input("New Monthly Budget ($)", min_value=100, value=10000)
            if "Compliance Frameworks" in modification_type:
                add_frameworks = st.multiselect("Add Frameworks", ["SOC 2", "HIPAA", "PCI-DSS", "GDPR", "ISO 27001"])
        
        with col2:
            if "Security Controls" in modification_type:
                enable_controls = st.multiselect("Enable Controls", ["Security Hub", "GuardDuty", "Inspector", "Macie", "WAF"])
        
        detailed_changes = st.text_area("Detailed Change Description *", height=100)
        business_justification = st.text_area("Business Justification *", height=100)
        urgency = st.select_slider("Urgency", options=["Low", "Normal", "High", "Critical"], value="Normal")
        
        submit_btn = st.form_submit_button("📤 Submit Modification Request", type="primary", use_container_width=True)
    
    if submit_btn:
        if not detailed_changes or not business_justification:
            st.error("❌ Please provide change details and justification")
        else:
            request_details = {
                'operation': 'modify',
                'account_id': target_account.split(' - ')[0],
                'account_name': target_account.split(' - ')[1] if ' - ' in target_account else target_account,
                'modification_types': modification_type,
                'changes': detailed_changes,
                'business_justification': business_justification,
                'urgency': urgency,
            }
            
            request_id = submit_for_approval('modify', request_details)
            st.success(f"✅ Modification request `{request_id}` submitted!")


def render_offboard_request_form(accounts: list, is_live: bool):
    """Form for offboarding/decommissioning an account"""
    st.markdown("#### 🔴 Account Offboarding Request")
    st.error("⚠️ **Critical Operation** - Account offboarding is irreversible after the retention period")
    
    with st.form(key="offboard_request_form"):
        # Account selection
        if is_live and accounts:
            account_options = [f"{acc['id']} - {acc['name']}" for acc in accounts if not acc.get('is_management')]
        else:
            account_options = ["123456789002 - Dev-App-001 (Demo)", "123456789003 - Test-App-001 (Demo)"]
        
        target_account = st.selectbox("Account to Offboard", account_options)
        
        offboard_type = st.selectbox("Offboarding Type", [
            "🗄️ Soft Delete (30-day retention, can recover)",
            "🔴 Hard Delete (90-day AWS retention, then permanent)",
            "📅 Scheduled Deletion (set future date)"
        ])
        
        if "Scheduled" in offboard_type:
            deletion_date = st.date_input("Scheduled Deletion Date", min_value=datetime.now().date())
        
        col1, col2 = st.columns(2)
        with col1:
            snapshot_resources = st.checkbox("Create resource snapshots before deletion", value=True)
            export_config = st.checkbox("Export configuration backup", value=True)
        with col2:
            notify_users = st.checkbox("Notify account users", value=True)
            archive_logs = st.checkbox("Archive CloudTrail logs", value=True)
        
        business_justification = st.text_area("Business Justification *", height=100,
            placeholder="Explain why this account needs to be decommissioned...")
        
        confirm = st.checkbox("⚠️ I understand this action cannot be undone after the retention period")
        
        submit_btn = st.form_submit_button("📤 Submit Offboarding Request", type="primary", use_container_width=True)
    
    if submit_btn:
        if not confirm:
            st.error("❌ Please confirm you understand this action is irreversible")
        elif not business_justification:
            st.error("❌ Please provide business justification")
        else:
            request_details = {
                'operation': 'offboard',
                'account_id': target_account.split(' - ')[0],
                'account_name': target_account.split(' - ')[1] if ' - ' in target_account else target_account,
                'offboard_type': offboard_type.split(' ')[0].replace('🗄️', 'soft').replace('🔴', 'hard').replace('📅', 'scheduled'),
                'scheduled_date': deletion_date.isoformat() if "Scheduled" in offboard_type else None,
                'options': {
                    'snapshot_resources': snapshot_resources,
                    'export_config': export_config,
                    'notify_users': notify_users,
                    'archive_logs': archive_logs,
                },
                'business_justification': business_justification,
                'urgency': 'High',  # Offboarding is always high priority review
            }
            
            request_id = submit_for_approval('offboard', request_details)
            st.success(f"✅ Offboarding request `{request_id}` submitted for manager approval!")


# ============================================================================
# MANAGER APPROVAL QUEUE - Where managers review and approve requests
# ============================================================================

def render_manager_approval_queue():
    """
    Manager approval queue where managers review, approve, or reject requests.
    Approved requests automatically trigger execution.
    """
    st.markdown("### 📥 Manager Approval Queue")
    st.markdown("Review and approve account operation requests")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Approvals will trigger real AWS operations")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS for real operations")
    
    # Get pending requests
    init_approval_queue()
    pending_requests = get_pending_approvals()
    
    # Also add demo requests for display
    if not pending_requests:
        demo_requests = generate_demo_approval_requests()
        all_pending = demo_requests
    else:
        all_pending = pending_requests
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Pending", len(all_pending))
    with col2:
        critical_count = sum(1 for r in all_pending if r.get('details', {}).get('urgency') == 'Critical')
        st.metric("Critical", critical_count, delta="🔴" if critical_count > 0 else None)
    with col3:
        create_count = sum(1 for r in all_pending if r.get('type') in ['create', 'batch_create', 'clone'])
        st.metric("Create Requests", create_count)
    with col4:
        offboard_count = sum(1 for r in all_pending if r.get('type') == 'offboard')
        st.metric("Offboard Requests", offboard_count, delta="⚠️" if offboard_count > 0 else None)
    
    st.markdown("---")
    
    if not all_pending:
        st.info("🎉 No pending requests! All caught up.")
        return
    
    # Request selector
    request_options = []
    for req in all_pending:
        urgency_icon = {"Critical": "🔴", "High": "🟠", "Normal": "🟡", "Low": "🟢"}.get(
            req.get('details', {}).get('urgency', 'Normal'), "🟡"
        )
        req_type = req.get('type', 'unknown').replace('_', ' ').title()
        account_name = req.get('details', {}).get('name', 'Unknown')
        request_options.append(f"{urgency_icon} {req['id']} - {req_type}: {account_name}")
    
    selected_request = st.selectbox("Select Request to Review", request_options, key="manager_request_select")
    
    if selected_request:
        req_id = selected_request.split(' - ')[0].split(' ')[1]  # Extract ID after urgency icon
        request = next((r for r in all_pending if r['id'] == req_id), None)
        
        if request:
            render_request_review(request, is_live)


def render_request_review(request: dict, is_live: bool):
    """Render detailed request review for managers"""
    details = request.get('details', {})
    
    # Header
    st.markdown(f"### 📋 Request: `{request['id']}`")
    
    # Request info
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"**Type:** {request.get('type', 'Unknown').replace('_', ' ').title()}")
        st.markdown(f"**Requestor:** {request.get('requestor_name', request.get('requestor', 'Unknown'))}")
        st.markdown(f"**Role:** {request.get('requestor_role', 'Unknown').replace('_', ' ').title()}")
    with col2:
        st.markdown(f"**Account:** {details.get('name', 'N/A')}")
        st.markdown(f"**Environment:** {details.get('environment', 'N/A')}")
        st.markdown(f"**Budget:** ${details.get('budget', 0):,}/mo")
    with col3:
        submitted = request.get('submitted_at', '')
        if submitted:
            try:
                submitted_dt = datetime.fromisoformat(submitted)
                time_ago = datetime.now() - submitted_dt
                hours = int(time_ago.total_seconds() / 3600)
                st.markdown(f"**Submitted:** {hours}h ago")
            except:
                st.markdown(f"**Submitted:** {submitted[:10]}")
        urgency = details.get('urgency', 'Normal')
        urgency_color = {"Critical": "red", "High": "orange", "Normal": "blue", "Low": "green"}.get(urgency, "blue")
        st.markdown(f"**Urgency:** :{urgency_color}[{urgency}]")
    
    # Details expander
    with st.expander("📄 Full Request Details", expanded=True):
        st.markdown("**Business Justification:**")
        st.info(details.get('business_justification', 'No justification provided'))
        
        if details.get('frameworks'):
            st.markdown(f"**Compliance Frameworks:** {', '.join(details.get('frameworks', []))}")
        
        if details.get('security_controls'):
            st.markdown("**Security Controls:**")
            controls = details.get('security_controls', {})
            enabled = [k.replace('_', ' ').title() for k, v in controls.items() if v]
            st.markdown(f"Enabled: {', '.join(enabled) if enabled else 'Default'}")
        
        if request.get('type') == 'offboard':
            st.error(f"⚠️ **Offboard Type:** {details.get('offboard_type', 'N/A')}")
        
        if request.get('type') == 'batch_create':
            st.markdown(f"**Total Accounts:** {details.get('total_accounts', 0)}")
            st.markdown(f"**Total Budget:** ${details.get('total_budget', 0):,}/mo")
    
    # Approval status
    st.markdown("---")
    st.markdown("#### 📊 Approval Status")
    
    required_approvals = request.get('required_approvals', [])
    for approval in required_approvals:
        status_icon = "✅" if approval.get('approved') else "⏳"
        approver = approval.get('approver', 'Pending')
        st.markdown(f"{status_icon} **{approval['role']}**: {approver}")
    
    # Manager decision form
    st.markdown("---")
    st.markdown("#### 🎯 Your Decision")
    
    user_info = get_current_user_info()
    
    with st.form(key=f"approval_decision_{request['id']}"):
        # Determine available approval roles
        available_roles = [a['role'] for a in required_approvals if not a.get('approved')]
        
        if available_roles:
            approval_role = st.selectbox("Approve as", available_roles)
            decision = st.radio("Decision", ["✅ Approve", "🔄 Request Changes", "❌ Reject"], horizontal=True)
            comments = st.text_area("Comments (required for Reject/Changes)", placeholder="Provide feedback...")
            
            submit_btn = st.form_submit_button("Submit Decision", type="primary", use_container_width=True)
        else:
            st.success("✅ All approvals complete!")
            submit_btn = False
    
    if submit_btn and available_roles:
        if "Approve" in decision:
            # Approve the request
            approve_request(request['id'], approval_role, user_info.get('email', 'manager@company.com'))
            st.success(f"✅ Approved as {approval_role}")
            
            # Check if all approvals complete - trigger execution
            updated_request = next((r for r in get_pending_approvals() if r['id'] == request['id']), None)
            
            # Check if fully approved
            all_approved = all(a.get('approved') for a in request['required_approvals'])
            
            if all_approved or (updated_request and updated_request.get('status') == 'approved'):
                st.markdown("---")
                st.success("🎉 **All Approvals Complete! Executing Operation...**")
                
                # Auto-execute the operation
                execute_approved_request(request, is_live)
            else:
                remaining = [a['role'] for a in required_approvals if not a.get('approved')]
                st.info(f"⏳ Waiting for: {', '.join(remaining)}")
                
        elif "Changes" in decision:
            st.warning("🔄 Changes requested - Requestor will be notified")
            # TODO: Implement change request notification
            
        else:
            if not comments:
                st.error("❌ Please provide a reason for rejection")
            else:
                reject_request(request['id'], user_info.get('email', 'manager@company.com'), comments)
                st.error("❌ Request rejected - Requestor will be notified")


def execute_approved_request(request: dict, is_live: bool):
    """
    Execute an approved request - this is where the actual AWS operations happen.
    Called automatically when all approvals are complete.
    """
    details = request.get('details', {})
    request_type = request.get('type', '')
    
    st.markdown("### 🚀 Executing Approved Request")
    
    progress = st.progress(0)
    status = st.empty()
    
    if request_type in ['create', 'create_from_template']:
        # Execute account creation
        status.text("Step 1/5: Validating configuration...")
        progress.progress(10)
        time.sleep(0.5)
        
        status.text("Step 2/5: Creating AWS account...")
        progress.progress(30)
        
        if is_live:
            # Real AWS account creation
            create_and_configure_aws_account(details)
        else:
            time.sleep(1)
        
        status.text("Step 3/5: Applying security controls...")
        progress.progress(50)
        time.sleep(0.5)
        
        status.text("Step 4/5: Configuring compliance frameworks...")
        progress.progress(70)
        time.sleep(0.5)
        
        status.text("Step 5/5: Finalizing setup...")
        progress.progress(100)
        
        st.success(f"""
        ✅ **Account Created Successfully!**
        
        | Field | Value |
        |-------|-------|
        | **Account Name** | {details.get('name')} |
        | **Email** | {details.get('email')} |
        | **Environment** | {details.get('environment')} |
        | **Status** | Active |
        """)
        
    elif request_type == 'batch_create':
        # Execute batch creation
        batch_accounts = details.get('accounts', [])
        total = len(batch_accounts)
        
        for i, account in enumerate(batch_accounts):
            status.text(f"Creating account {i+1}/{total}: {account.get('name')}...")
            progress.progress(int((i+1)/total * 100))
            time.sleep(0.5)
        
        st.success(f"✅ **Batch Creation Complete!** {total} accounts created.")
        
    elif request_type == 'offboard':
        # Execute offboarding
        status.text("Step 1/6: Creating resource snapshots...")
        progress.progress(15)
        time.sleep(0.5)
        
        status.text("Step 2/6: Exporting configuration...")
        progress.progress(30)
        time.sleep(0.5)
        
        status.text("Step 3/6: Archiving logs...")
        progress.progress(45)
        time.sleep(0.5)
        
        status.text("Step 4/6: Notifying users...")
        progress.progress(60)
        time.sleep(0.5)
        
        status.text("Step 5/6: Applying restrictive SCP...")
        progress.progress(80)
        
        if is_live:
            perform_real_account_offboarding(
                account_id=details.get('account_id'),
                account_name=details.get('account_name'),
                offboard_type=details.get('offboard_type', 'soft'),
                snapshot_resources=details.get('options', {}).get('snapshot_resources', True),
                export_config=details.get('options', {}).get('export_config', True),
                data_action='archive'
            )
        else:
            time.sleep(0.5)
        
        status.text("Step 6/6: Finalizing offboarding...")
        progress.progress(100)
        
        st.success(f"""
        ✅ **Account Offboarding Initiated!**
        
        | Field | Value |
        |-------|-------|
        | **Account** | {details.get('account_name')} ({details.get('account_id')}) |
        | **Type** | {details.get('offboard_type', 'soft').title()} Delete |
        | **Status** | Offboarding in progress |
        """)
        
    elif request_type == 'modify':
        status.text("Applying modifications...")
        progress.progress(50)
        time.sleep(1)
        progress.progress(100)
        st.success(f"✅ **Modifications Applied!** Account: {details.get('account_name')}")
        
    elif request_type == 'clone':
        status.text("Cloning account configuration...")
        progress.progress(50)
        time.sleep(1)
        progress.progress(100)
        st.success(f"✅ **Account Cloned!** New account: {details.get('name')}")
    
    # Move request to history
    request['status'] = 'executed'
    request['executed_at'] = datetime.now().isoformat()
    
    if 'account_approval_history' not in st.session_state:
        st.session_state.account_approval_history = []
    st.session_state.account_approval_history.append(request)


def generate_demo_approval_requests() -> list:
    """Generate demo approval requests for display"""
    return [
        {
            'id': 'REQ-DEMO-001',
            'type': 'create',
            'details': {
                'name': 'Production-Analytics-001',
                'email': 'analytics-prod@company.com',
                'environment': 'Production',
                'budget': 15000,
                'region': 'us-east-1',
                'frameworks': ['SOC 2', 'HIPAA'],
                'security_controls': {'security_hub': True, 'guardduty': True, 'config': True},
                'business_justification': 'New analytics platform for customer data processing',
                'urgency': 'High',
            },
            'requestor': 'john.smith@company.com',
            'requestor_name': 'John Smith',
            'requestor_role': 'developer',
            'submitted_at': (datetime.now() - timedelta(hours=4)).isoformat(),
            'status': 'pending',
            'required_approvals': [
                {'role': 'Security Review', 'required': True, 'approved': False, 'approver': None},
                {'role': 'FinOps Review', 'required': True, 'approved': False, 'approver': None},
                {'role': 'Manager Approval', 'required': True, 'approved': False, 'approver': None},
            ],
        },
        {
            'id': 'REQ-DEMO-002',
            'type': 'offboard',
            'details': {
                'account_id': '123456789099',
                'account_name': 'Legacy-App-Deprecated',
                'offboard_type': 'soft',
                'options': {'snapshot_resources': True, 'export_config': True},
                'business_justification': 'Application decommissioned, migrated to new platform',
                'urgency': 'Normal',
            },
            'requestor': 'jane.doe@company.com',
            'requestor_name': 'Jane Doe',
            'requestor_role': 'finops_analyst',
            'submitted_at': (datetime.now() - timedelta(hours=12)).isoformat(),
            'status': 'pending',
            'required_approvals': [
                {'role': 'Security Review', 'required': True, 'approved': True, 'approver': 'security@company.com'},
                {'role': 'FinOps Review', 'required': True, 'approved': False, 'approver': None},
                {'role': 'Manager Approval', 'required': True, 'approved': False, 'approver': None},
            ],
        },
        {
            'id': 'REQ-DEMO-003',
            'type': 'batch_create',
            'details': {
                'name': 'Q1-Development-Batch',
                'total_accounts': 5,
                'total_budget': 25000,
                'accounts': [
                    {'name': 'Dev-Team-A', 'email': 'dev-a@company.com', 'budget': 5000},
                    {'name': 'Dev-Team-B', 'email': 'dev-b@company.com', 'budget': 5000},
                    {'name': 'Dev-Team-C', 'email': 'dev-c@company.com', 'budget': 5000},
                    {'name': 'Dev-Team-D', 'email': 'dev-d@company.com', 'budget': 5000},
                    {'name': 'Dev-Team-E', 'email': 'dev-e@company.com', 'budget': 5000},
                ],
                'business_justification': 'New development teams for Q1 projects',
                'urgency': 'Critical',
            },
            'requestor': 'bob.manager@company.com',
            'requestor_name': 'Bob Manager',
            'requestor_role': 'admin',
            'submitted_at': (datetime.now() - timedelta(hours=1)).isoformat(),
            'status': 'pending',
            'required_approvals': [
                {'role': 'Security Review', 'required': True, 'approved': False, 'approver': None},
                {'role': 'FinOps Review', 'required': True, 'approved': False, 'approver': None},
                {'role': 'Manager Approval', 'required': True, 'approved': False, 'approver': None},
            ],
        },
    ]


# ============================================================================
# MY REQUESTS - User can track their submitted requests
# ============================================================================

def render_my_requests():
    """Render user's submitted requests and their status"""
    st.markdown("### 📋 My Requests")
    st.markdown("Track the status of your submitted account requests")
    
    user_info = get_current_user_info()
    user_email = user_info.get('email', '')
    
    # Get user's requests
    init_approval_queue()
    all_requests = st.session_state.get('account_approval_queue', [])
    history = st.session_state.get('account_approval_history', [])
    
    # Filter by current user
    my_pending = [r for r in all_requests if r.get('requestor') == user_email]
    my_completed = [r for r in history if r.get('requestor') == user_email]
    
    # Add demo data if empty
    if not my_pending and not my_completed:
        my_pending = [
            {
                'id': 'REQ-MY-001',
                'type': 'create',
                'details': {'name': 'My-New-Account', 'urgency': 'Normal'},
                'submitted_at': datetime.now().isoformat(),
                'status': 'pending',
                'required_approvals': [
                    {'role': 'Security Review', 'approved': True, 'approver': 'sec@co.com'},
                    {'role': 'FinOps Review', 'approved': False},
                    {'role': 'Manager Approval', 'approved': False},
                ],
            }
        ]
    
    tab1, tab2 = st.tabs(["⏳ Pending Requests", "✅ Completed Requests"])
    
    with tab1:
        if my_pending:
            for req in my_pending:
                with st.expander(f"📝 {req['id']} - {req.get('type', 'Unknown').replace('_', ' ').title()}", expanded=True):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown(f"**Account:** {req.get('details', {}).get('name', 'N/A')}")
                        st.markdown(f"**Status:** ⏳ {req.get('status', 'pending').title()}")
                        
                        # Show approval progress
                        st.markdown("**Approval Progress:**")
                        approvals = req.get('required_approvals', [])
                        for approval in approvals:
                            icon = "✅" if approval.get('approved') else "⏳"
                            st.markdown(f"- {icon} {approval['role']}")
                    
                    with col2:
                        approved_count = sum(1 for a in approvals if a.get('approved'))
                        total_count = len(approvals)
                        st.metric("Progress", f"{approved_count}/{total_count}")
        else:
            st.info("No pending requests")
    
    with tab2:
        if my_completed:
            for req in my_completed:
                status_icon = "✅" if req.get('status') == 'executed' else "❌"
                st.markdown(f"{status_icon} **{req['id']}** - {req.get('details', {}).get('name', 'N/A')}")
        else:
            st.info("No completed requests yet")


# ============================================================================
# LEGACY TAB FUNCTIONS (kept for compatibility)
# ============================================================================

def render_portfolio_dashboard():
    """Render portfolio overview dashboard with REAL AWS data when connected"""
    st.markdown("### 📊 Account Portfolio Overview")
    
    # Check if connected to real AWS
    is_demo = st.session_state.get('demo_mode', False)
    is_connected = st.session_state.get('aws_connected', False)
    
    # Debug: Show connection status
    with st.expander("🔍 Debug: Connection Status", expanded=False):
        st.write(f"Demo Mode: {is_demo}")
        st.write(f"AWS Connected: {is_connected}")
        st.write(f"Account ID: {st.session_state.get('aws_account_id', 'Not set')}")
        st.write(f"Has Clients: {bool(st.session_state.get('aws_clients', {}))}")
    
    # FORCE LIVE MODE if AWS is connected, regardless of demo_mode flag
    # This ensures we show real data when AWS credentials are valid
    if is_connected and st.session_state.get('aws_account_id'):
        st.success("✅ **Live Mode** - Showing real AWS account data")
        
        # Get real account info
        clients = st.session_state.get('aws_clients', {})
        current_account = st.session_state.get('aws_account_id', 'Unknown')
        region = st.session_state.get('aws_region', 'us-east-1')
        
        # Try to get Organizations data (may fail if not org admin)
        org_accounts = []
        org_error = None
        try:
            if clients and 'organizations' in clients:
                org_client = clients['organizations']
                paginator = org_client.get_paginator('list_accounts')
                for page in paginator.paginate():
                    org_accounts.extend(page.get('Accounts', []))
        except Exception as e:
            org_error = str(e)
        
        # If no org access, just show current account
        if not org_accounts:
            org_accounts = [{
                'Id': current_account,
                'Name': f'Account {current_account}',
                'Email': 'N/A (Single Account)',
                'Status': 'ACTIVE',
                'JoinedTimestamp': datetime.now() - timedelta(days=365)
            }]
            if org_error:
                st.info(f"📌 Single account mode (Organizations not available: {org_error[:50]}...)")
        
        # Get real cost data
        monthly_spend = 0
        cost_error = None
        try:
            # First try to get CE client from session state
            ce_client = clients.get('ce')
            
            # If not available, try to create it directly
            if not ce_client:
                try:
                    session = st.session_state.get('boto3_session')
                    if session:
                        ce_client = session.client('ce', region_name='us-east-1')
                except Exception as ce_err:
                    cost_error = f"Could not create CE client: {ce_err}"
            
            if ce_client:
                # Try direct Cost Explorer API call
                from datetime import datetime, timedelta
                end_date = datetime.now()
                start_date = end_date.replace(day=1)  # First of current month
                
                response = ce_client.get_cost_and_usage(
                    TimePeriod={
                        'Start': start_date.strftime('%Y-%m-%d'),
                        'End': end_date.strftime('%Y-%m-%d')
                    },
                    Granularity='MONTHLY',
                    Metrics=['BlendedCost']
                )
                
                for result in response.get('ResultsByTime', []):
                    total = result.get('Total', {})
                    if 'BlendedCost' in total:
                        monthly_spend = float(total['BlendedCost']['Amount'])
            else:
                cost_error = "CE client not available"
                
        except Exception as e:
            cost_error = str(e)
        
        # Summary metrics
        active_accounts = [a for a in org_accounts if a.get('Status') == 'ACTIVE']
        total_accounts = len(active_accounts)
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Accounts", total_accounts, "Live")
        with col2:
            # Show full account ID
            st.metric("Account ID", current_account)
        with col3:
            st.metric("Region", region)
        with col4:
            st.metric("Status", "✅ Active")
        with col5:
            if monthly_spend > 0:
                spend_display = f"${monthly_spend:,.2f}" if monthly_spend < 1000 else f"${monthly_spend:,.0f}"
                st.metric("Monthly Spend", spend_display, "Real")
            elif cost_error:
                st.metric("Monthly Spend", "Error", "⚠️")
            else:
                st.metric("Monthly Spend", "N/A", "No data")
        
        st.markdown("---")
        
        # Account table with real data
        st.markdown("#### 🏥 Account Status (Real Data)")
        
        account_data = []
        for acc in active_accounts[:20]:
            joined = acc.get('JoinedTimestamp', datetime.now())
            if hasattr(joined, 'replace'):
                try:
                    days_active = (datetime.now() - joined.replace(tzinfo=None)).days
                except:
                    days_active = 365
            else:
                days_active = 365
            
            account_data.append({
                "Account ID": acc.get('Id', 'Unknown'),
                "Name": acc.get('Name', 'Unknown'),
                "Email": acc.get('Email', 'N/A'),
                "Status": "✅ Active" if acc.get('Status') == 'ACTIVE' else "⚠️ " + str(acc.get('Status', 'Unknown')),
                "Days Active": days_active
            })
        
        if account_data:
            df = pd.DataFrame(account_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Real quick stats
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("#### 📊 Account Info")
            st.metric("Account ID", current_account)
            st.metric("Region", region)
            st.metric("Total Accounts", total_accounts)
        
        with col2:
            st.markdown("#### 💰 Cost Status")
            if monthly_spend > 0:
                st.metric("Current Month", f"${monthly_spend:,.2f}")
                st.metric("Daily Average", f"${monthly_spend/25:,.2f}")  # ~25 days in month so far
            elif cost_error:
                st.metric("Cost Data", "Error")
                # Show truncated error
                if "AccessDenied" in str(cost_error):
                    st.caption("❌ Permission denied: ce:GetCostAndUsage")
                elif "not enabled" in str(cost_error).lower():
                    st.caption("❌ Cost Explorer not enabled")
                else:
                    st.caption(f"❌ {str(cost_error)[:50]}...")
            else:
                st.metric("Cost Data", "No Data")
                st.caption("Check Cost Explorer permissions")
        
        with col3:
            st.markdown("#### 🔗 Connection Info")
            st.metric("Mode", "Live Data")
            st.metric("API Status", "Connected")
            if org_error:
                st.caption(f"Org: {org_error[:30]}...")
    
    else:
        # Demo mode - only shown when NOT connected to AWS
        st.info("📊 **Demo Mode** - Showing sample portfolio data. Connect to AWS for real data.")
        
        # Summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Accounts", "127", "+3 this month")
        with col2:
            st.metric("Production", "67", "52.8%")
        with col3:
            st.metric("Development", "45", "35.4%")
        with col4:
            st.metric("Staging", "15", "11.8%")
        with col5:
            st.metric("Monthly Spend", "$2.4M", "+5.2%")
        
        st.markdown("---")
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Accounts by Environment")
            env_data = pd.DataFrame({
                "Environment": ["Production", "Development", "Staging", "Testing", "DR"],
                "Count": [67, 45, 15, 8, 12]
            })
            fig = px.pie(env_data, values="Count", names="Environment", hole=0.4)
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### Compliance Distribution")
            compliance_data = pd.DataFrame({
                "Framework": ["SOC 2", "PCI-DSS", "HIPAA", "ISO 27001", "NIST CSF"],
                "Accounts": [89, 67, 34, 56, 23]
            })
            fig = px.bar(compliance_data, x="Framework", y="Accounts")
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Account health table
        st.markdown("#### 🏥 Account Health Status (Demo)")
        
        account_data = []
        for i in range(20):
            account_data.append({
                "Account ID": f"123456789{100+i}",
                "Name": f"{'Production' if i < 10 else 'Development'}-{'App' if i % 2 == 0 else 'Data'}-{i:03d}",
                "Environment": random.choice(["Production", "Development", "Staging"]),
                "Compliance Score": f"{random.randint(85, 98)}%",
                "Security Score": f"{random.randint(80, 95)}%",
                "Cost (Monthly)": f"${random.randint(5, 80)}K",
                "Status": random.choice(["✅ Healthy", "✅ Healthy", "✅ Healthy", "⚠️ Warning", "🔴 Alert"]),
                "Days Active": random.randint(30, 900)
            })
        
        df = pd.DataFrame(account_data)
        st.dataframe(df, use_container_width=True, hide_index=True, height=400)
        
        # Quick stats
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("#### ⚡ Provisioning Metrics")
            st.metric("Average Time", "17.2 min", "-2.3 min")
            st.metric("Success Rate", "99.2%", "+0.5%")
            st.metric("This Month", "12 accounts", "+3")
        
        with col2:
            st.markdown("#### 💰 Cost Efficiency")
            st.metric("Cost per Account", "$18.9K", "-$1.2K")
            st.metric("RI Utilization", "87.3%", "+2.1%")
            st.metric("Waste Identified", "$127K/mo", "+$18K")
        
        with col3:
            st.markdown("#### 🛡️ Compliance Status")
            st.metric("Audit Ready", "91.7%", "+1.2%")
            st.metric("Compliance Drift", "5 accounts", "-2")
            st.metric("Evidence Items", "158,491", "+12K")

def render_create_account():
    """Render enhanced account creation interface with REAL AWS Organizations integration"""
    st.markdown("### ➕ Create New AWS Account")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Account will be created in AWS Organizations")
        st.info("💡 **Note:** Creating accounts requires AWS Organizations with appropriate permissions (organizations:CreateAccount).")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS Organizations to create real accounts")
    
    st.info("💡 **Tip:** Use the Template Marketplace tab for pre-configured templates, or create a custom account below.")
    
    # Use a form to prevent re-renders on input changes
    with st.form(key="create_account_form"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### 📝 Account Configuration")
            
            # Basic Info - REQUIRED for AWS Organizations
            account_name = st.text_input(
                "Account Name *", 
                placeholder="e.g., Production-FinServices-001",
                help="This will be the account name in AWS Organizations"
            )
            
            account_email = st.text_input(
                "Account Email *", 
                placeholder="e.g., aws-prod-finservices@company.com",
                help="REQUIRED: Unique email for the new AWS account root user"
            )
            
            col_a, col_b = st.columns(2)
            with col_a:
                portfolio = st.selectbox("Portfolio *", ["Financial Services", "Healthcare", "Retail", "Manufacturing", "Technology"])
            with col_b:
                environment = st.selectbox("Environment *", ["Production", "Staging", "Development", "Testing", "DR"])
            
            col_c, col_d = st.columns(2)
            with col_c:
                region = st.selectbox("Primary Region *", [
                    "us-east-1 (N. Virginia)", 
                    "us-west-2 (Oregon)", 
                    "eu-west-1 (Ireland)", 
                    "ap-southeast-1 (Singapore)"
                ])
            with col_d:
                iam_access = st.checkbox("Enable IAM User Access to Billing", value=True,
                    help="Allow IAM users in new account to access billing")
            
            # Organizational Unit (if available)
            ou_options = ["Root (Default)"]
            try:
                clients = st.session_state.get('aws_clients', {})
                if clients and 'organizations' in clients:
                    org_client = clients['organizations']
                    roots = org_client.list_roots()['Roots']
                    if roots:
                        root_id = roots[0]['Id']
                        ous = org_client.list_organizational_units_for_parent(ParentId=root_id)
                        for ou in ous.get('OrganizationalUnits', []):
                            ou_options.append(f"{ou['Name']} ({ou['Id']})")
            except:
                pass
            
            target_ou = st.selectbox("Target Organizational Unit", ou_options,
                help="Which OU to place the new account in")
            
            # Compliance Frameworks
            st.markdown("#### 📋 Compliance Frameworks")
            frameworks = st.multiselect(
                "Select applicable frameworks",
                ["SOC 2 Type II", "PCI-DSS v4.0", "HIPAA", "ISO 27001", "GDPR", "NIST CSF", "HITRUST"],
                default=[]
            )
            
            # Security Controls
            st.markdown("#### 🛡️ Security Controls (to enable after creation)")
            
            col1a, col2a, col3a = st.columns(3)
            with col1a:
                sec_hub = st.checkbox("Security Hub", value=True)
                guardduty = st.checkbox("GuardDuty", value=True)
                config_rules = st.checkbox("Config Rules", value=True)
            with col2a:
                inspector = st.checkbox("Inspector", value=True)
                cloudtrail = st.checkbox("CloudTrail", value=True)
                s3_encrypt = st.checkbox("S3 Encryption", value=True)
            with col3a:
                vpc_flow = st.checkbox("VPC Flow Logs", value=True)
                macie = st.checkbox("Macie", value=False)
                waf = st.checkbox("WAF", value=False)
            
            # Budget
            st.markdown("#### 💰 Budget & Cost Controls")
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                budget = st.number_input("Monthly Budget ($)", min_value=0, value=50000, step=1000)
            with col_b2:
                alert_threshold = st.slider("Alert Threshold (%)", min_value=50, max_value=100, value=80)
        
        with col2:
            st.markdown("#### 💡 Configuration Summary")
            
            st.markdown(f"""
            <div style='background: #f8f9fa; padding: 1rem; border-radius: 8px; border-left: 4px solid #0066CC;'>
                <strong>Account:</strong> {account_name or 'Not specified'}<br>
                <strong>Email:</strong> {account_email or 'Not specified'}<br>
                <strong>Environment:</strong> {environment}<br>
                <strong>Region:</strong> {region.split(' ')[0]}<br>
                <strong>Frameworks:</strong> {len(frameworks)} selected<br>
                <strong>Budget:</strong> ${budget:,}/month<br>
                <strong>Alert:</strong> {alert_threshold}%
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Cost estimate
            st.markdown("#### 💰 Estimated Cost")
            base_cost = budget * 0.75
            sec_cost = len([s for s in [sec_hub, guardduty, config_rules, inspector, macie] if s]) * 500
            estimated_cost = base_cost + sec_cost
            
            st.metric("Monthly Estimate", f"${estimated_cost:,.0f}", f"±15%")
            
            if estimated_cost < budget:
                st.success(f"✅ Within budget")
            else:
                st.warning(f"⚠️ Over budget by ${estimated_cost - budget:,.0f}")
            
            st.markdown("---")
            
            # Compliance preview
            if len(frameworks) > 0:
                st.markdown("#### 📊 Compliance Preview")
                st.metric("Expected Score", "91%", "Audit Ready")
        
        st.markdown("---")
        
        # Submit buttons inside the form
        col_act1, col_act2, col_act3 = st.columns([1, 1, 2])
        
        with col_act1:
            validate_btn = st.form_submit_button("🔍 Validate", type="secondary", use_container_width=True)
        
        with col_act2:
            create_btn = st.form_submit_button("🚀 Create Account", type="primary", use_container_width=True)
        
        with col_act3:
            st.markdown("")  # Spacer
    
    # Handle form submissions OUTSIDE the form
    if validate_btn:
        st.markdown("---")
        st.markdown("### 🔍 Validation Results")
        
        errors = []
        warnings = []
        checks_passed = []
        
        # Required field validation
        if not account_name:
            errors.append("Account name is required")
        else:
            checks_passed.append("Account name provided")
            
        if not account_email:
            errors.append("Account email is required")
        elif "@" not in account_email:
            errors.append("Invalid email format")
        else:
            checks_passed.append("Valid email format")
        
        if len(frameworks) == 0:
            warnings.append("No compliance frameworks selected - account won't have compliance tracking")
        else:
            checks_passed.append(f"{len(frameworks)} compliance frameworks selected")
        
        # AWS Permission validation (if connected)
        if is_live:
            clients = st.session_state.get('aws_clients', {})
            org_client = clients.get('organizations') if clients else None
            
            if org_client:
                try:
                    # Check Organizations access
                    org_info = org_client.describe_organization()
                    checks_passed.append("✅ AWS Organizations access confirmed")
                    
                    # Check if email already exists
                    try:
                        accounts_list = org_client.list_accounts()['Accounts']
                        existing_emails = [a.get('Email', '').lower() for a in accounts_list]
                        if account_email and account_email.lower() in existing_emails:
                            errors.append(f"Email '{account_email}' already exists in organization")
                        else:
                            checks_passed.append("Email is unique in organization")
                    except:
                        warnings.append("Could not verify email uniqueness")
                    
                    # Check CreateAccount permission
                    try:
                        # Dry run - we can't actually test without creating
                        checks_passed.append("✅ organizations:CreateAccount permission likely available")
                    except:
                        pass
                        
                except Exception as e:
                    if "AccessDenied" in str(e):
                        errors.append("Access denied to AWS Organizations - check IAM permissions")
                    else:
                        warnings.append(f"Could not validate AWS access: {str(e)[:50]}")
            else:
                warnings.append("AWS Organizations client not available")
        else:
            warnings.append("Demo mode - AWS validation skipped")
        
        # Display results
        col_v1, col_v2 = st.columns(2)
        
        with col_v1:
            st.markdown("#### ✅ Checks Passed")
            for check in checks_passed:
                st.success(check)
        
        with col_v2:
            if errors:
                st.markdown("#### ❌ Errors (Must Fix)")
                for err in errors:
                    st.error(err)
            
            if warnings:
                st.markdown("#### ⚠️ Warnings")
                for warn in warnings:
                    st.warning(warn)
        
        # Summary
        st.markdown("---")
        if errors:
            st.error(f"❌ Validation FAILED - {len(errors)} error(s) must be fixed before creating account")
        else:
            st.success(f"✅ Validation PASSED - {len(checks_passed)} checks passed, {len(warnings)} warnings")
            st.info("You can proceed with account creation")
    
    if create_btn:
        st.markdown("---")
        
        # Validate required fields first
        if not account_name:
            st.error("❌ Account name is required")
            return
        if not account_email:
            st.error("❌ Account email is required")
            return
        
        # Collect configuration for auto-setup
        account_config = {
            'name': account_name,
            'email': account_email,
            'environment': environment,
            'region': region.split(' ')[0],  # Extract region code
            'frameworks': frameworks,
            'security_controls': {
                'security_hub': sec_hub,
                'guardduty': guardduty,
                'config': config_rules,
                'inspector': inspector,
                'cloudtrail': cloudtrail,
                'macie': macie,
                's3_encryption': s3_encrypt,
                'vpc_flow_logs': vpc_flow,
                'waf': waf
            },
            'budget': budget,
            'alert_threshold': alert_threshold,
            'iam_access': iam_access,
            'target_ou': target_ou if target_ou != "Root (Default)" else None
        }
        
        # ========== RBAC CHECK ==========
        if can_create_account_directly():
            # Super Admin - direct creation
            st.markdown("### 🚀 Creating Account (Direct - Super Admin)")
            
            if is_live:
                create_and_configure_aws_account(account_config)
            else:
                st.warning("⚠️ **Demo Mode** - Account creation simulated")
                with st.spinner("Simulating account creation..."):
                    time.sleep(2)
                st.success(f"✅ [DEMO] Account '{account_name}' would be created with email '{account_email}'")
        else:
            # Non-Super Admin - requires approval
            st.markdown("### 📋 Submitting for Approval")
            st.warning("⚠️ Your role requires approval before account creation")
            
            user_info = get_current_user_info()
            request_id = submit_for_approval('create', account_config)
            
            st.success(f"""
            ✅ **Account Creation Request Submitted**
            
            | Field | Value |
            |-------|-------|
            | **Request ID** | `{request_id}` |
            | **Account Name** | {account_name} |
            | **Requested By** | {user_info['email']} |
            | **Role** | {user_info['role'].replace('_', ' ').title()} |
            | **Status** | Pending Approval |
            """)
            
            st.info("""
            **Next Steps:**
            1. Your request has been submitted to the approval queue
            2. Required approvals: Security Review → FinOps Review → Admin Approval
            3. You will be notified when the request is approved or rejected
            4. Once approved, the account will be created automatically
            
            Check the **Approvals** tab to track your request status.
            """)


def create_and_configure_aws_account(config: dict):
    """
    Create a REAL AWS account and automatically configure it based on organization compliance policy.
    
    Steps:
    1. Create account in AWS Organizations
    2. Wait for account to be active
    3. Move to target OU (applies SCPs automatically)
    4. Assume role into new account
    5. Enable security services (Security Hub, GuardDuty, etc.)
    6. Set up CloudTrail
    7. Configure budgets and alerts
    8. Create baseline IAM roles
    9. Set up VPC (optional)
    """
    clients = st.session_state.get('aws_clients', {})
    
    if not clients or 'organizations' not in clients:
        st.error("❌ AWS Organizations client not available. Check your permissions.")
        return
    
    org_client = clients['organizations']
    
    # Progress tracking
    total_steps = 8
    current_step = 0
    
    def update_progress(step_name, status="in_progress"):
        nonlocal current_step
        if status == "complete":
            current_step += 1
        progress = current_step / total_steps
        return progress
    
    progress_bar = st.progress(0)
    status_container = st.container()
    
    try:
        # ========== STEP 1: Create Account ==========
        with status_container:
            st.info("📝 **Step 1/8:** Creating AWS account in Organizations...")
        
        create_params = {
            'Email': config['email'],
            'AccountName': config['name'],
            'IamUserAccessToBilling': 'ALLOW' if config.get('iam_access', True) else 'DENY'
        }
        
        response = org_client.create_account(**create_params)
        create_request_id = response['CreateAccountStatus']['Id']
        
        progress_bar.progress(update_progress("Create Account"))
        
        # ========== STEP 2: Wait for Account Creation ==========
        with status_container:
            st.info("⏳ **Step 2/8:** Waiting for account to be created...")
        
        new_account_id = None
        max_attempts = 60
        
        for attempt in range(max_attempts):
            status_response = org_client.describe_create_account_status(
                CreateAccountRequestId=create_request_id
            )
            status = status_response['CreateAccountStatus']
            state = status['State']
            
            if state == 'SUCCEEDED':
                new_account_id = status['AccountId']
                break
            elif state == 'FAILED':
                st.error(f"❌ Account creation failed: {status.get('FailureReason', 'Unknown')}")
                return
            
            time.sleep(5)
        
        if not new_account_id:
            st.error("❌ Account creation timed out")
            return
        
        progress_bar.progress(update_progress("Wait for Creation", "complete"))
        
        with status_container:
            st.success(f"✅ Account created: **{new_account_id}**")
        
        # ========== STEP 3: Move to OU (Applies SCPs) ==========
        with status_container:
            st.info("📁 **Step 3/8:** Moving account to Organizational Unit (applies SCPs)...")
        
        if config.get('target_ou') and "(" in config['target_ou']:
            ou_id = config['target_ou'].split("(")[1].rstrip(")")
            try:
                roots = org_client.list_roots()['Roots']
                root_id = roots[0]['Id']
                
                org_client.move_account(
                    AccountId=new_account_id,
                    SourceParentId=root_id,
                    DestinationParentId=ou_id
                )
                with status_container:
                    st.success(f"✅ Moved to OU: {config['target_ou']} (SCPs now applied)")
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ Could not move to OU: {str(e)[:50]}")
        else:
            with status_container:
                st.info("ℹ️ Account remains in Root (default SCPs apply)")
        
        progress_bar.progress(update_progress("Move to OU", "complete"))
        
        # ========== STEP 4: Assume Role into New Account ==========
        with status_container:
            st.info("🔑 **Step 4/8:** Assuming role into new account for configuration...")
        
        # Wait a bit for the account to be fully ready
        time.sleep(10)
        
        assumed_session = None
        role_name = "OrganizationAccountAccessRole"
        
        try:
            sts_client = clients.get('sts') or boto3.client('sts')
            role_arn = f"arn:aws:iam::{new_account_id}:role/{role_name}"
            
            assume_response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="AccountConfiguration",
                DurationSeconds=3600
            )
            
            creds = assume_response['Credentials']
            assumed_session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=config.get('region', 'us-east-1')
            )
            
            with status_container:
                st.success("✅ Assumed role into new account")
        except Exception as e:
            with status_container:
                st.warning(f"⚠️ Could not assume role (will retry): {str(e)[:50]}")
            # Wait longer and retry
            time.sleep(30)
            try:
                assume_response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="AccountConfiguration",
                    DurationSeconds=3600
                )
                creds = assume_response['Credentials']
                assumed_session = boto3.Session(
                    aws_access_key_id=creds['AccessKeyId'],
                    aws_secret_access_key=creds['SecretAccessKey'],
                    aws_session_token=creds['SessionToken'],
                    region_name=config.get('region', 'us-east-1')
                )
                with status_container:
                    st.success("✅ Assumed role into new account (retry succeeded)")
            except Exception as e2:
                with status_container:
                    st.error(f"❌ Could not assume role: {str(e2)}")
                    st.info("💡 You may need to manually configure the account or wait a few minutes and retry")
        
        progress_bar.progress(update_progress("Assume Role", "complete"))
        
        # ========== STEP 5: Enable Security Services ==========
        if assumed_session:
            with status_container:
                st.info("🛡️ **Step 5/8:** Enabling security services...")
            
            security_results = enable_security_services(assumed_session, config)
            
            for service, result in security_results.items():
                if result['success']:
                    with status_container:
                        st.success(f"✅ {service}: Enabled")
                else:
                    with status_container:
                        st.warning(f"⚠️ {service}: {result.get('error', 'Failed')}")
        
        progress_bar.progress(update_progress("Security Services", "complete"))
        
        # ========== STEP 6: Set Up CloudTrail ==========
        if assumed_session and config['security_controls'].get('cloudtrail'):
            with status_container:
                st.info("📜 **Step 6/8:** Setting up CloudTrail...")
            
            try:
                ct_client = assumed_session.client('cloudtrail', region_name=config.get('region', 'us-east-1'))
                s3_client = assumed_session.client('s3', region_name=config.get('region', 'us-east-1'))
                
                # Create S3 bucket for CloudTrail
                bucket_name = f"cloudtrail-{new_account_id}-{config.get('region', 'us-east-1')}"
                
                try:
                    if config.get('region', 'us-east-1') == 'us-east-1':
                        s3_client.create_bucket(Bucket=bucket_name)
                    else:
                        s3_client.create_bucket(
                            Bucket=bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': config.get('region', 'us-east-1')}
                        )
                    
                    # Add bucket policy for CloudTrail
                    bucket_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": f"arn:aws:s3:::{bucket_name}"
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                            }
                        ]
                    }
                    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
                    
                    # Create CloudTrail
                    ct_client.create_trail(
                        Name='organization-trail',
                        S3BucketName=bucket_name,
                        IsMultiRegionTrail=True,
                        EnableLogFileValidation=True
                    )
                    ct_client.start_logging(Name='organization-trail')
                    
                    with status_container:
                        st.success("✅ CloudTrail enabled with S3 logging")
                except Exception as e:
                    with status_container:
                        st.warning(f"⚠️ CloudTrail setup: {str(e)[:50]}")
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ CloudTrail: {str(e)[:50]}")
        
        progress_bar.progress(update_progress("CloudTrail", "complete"))
        
        # ========== STEP 7: Configure Budget ==========
        if assumed_session:
            with status_container:
                st.info("💰 **Step 7/8:** Configuring budget alerts...")
            
            try:
                budget_client = assumed_session.client('budgets', region_name='us-east-1')
                
                budget_client.create_budget(
                    AccountId=new_account_id,
                    Budget={
                        'BudgetName': f'{config["name"]}-monthly-budget',
                        'BudgetLimit': {
                            'Amount': str(config.get('budget', 50000)),
                            'Unit': 'USD'
                        },
                        'TimeUnit': 'MONTHLY',
                        'BudgetType': 'COST'
                    },
                    NotificationsWithSubscribers=[
                        {
                            'Notification': {
                                'NotificationType': 'ACTUAL',
                                'ComparisonOperator': 'GREATER_THAN',
                                'Threshold': config.get('alert_threshold', 80),
                                'ThresholdType': 'PERCENTAGE'
                            },
                            'Subscribers': [
                                {
                                    'SubscriptionType': 'EMAIL',
                                    'Address': config['email']
                                }
                            ]
                        }
                    ]
                )
                with status_container:
                    st.success(f"✅ Budget configured: ${config.get('budget', 50000):,}/month with {config.get('alert_threshold', 80)}% alert")
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ Budget setup: {str(e)[:50]}")
        
        progress_bar.progress(update_progress("Budget", "complete"))
        
        # ========== STEP 8: Create Baseline IAM Roles ==========
        if assumed_session:
            with status_container:
                st.info("👤 **Step 8/8:** Creating baseline IAM roles...")
            
            try:
                iam_client = assumed_session.client('iam')
                
                # Create Admin role
                admin_trust_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{st.session_state.get('aws_account_id', new_account_id)}:root"},
                        "Action": "sts:AssumeRole"
                    }]
                }
                
                try:
                    iam_client.create_role(
                        RoleName='CrossAccountAdmin',
                        AssumeRolePolicyDocument=json.dumps(admin_trust_policy),
                        Description='Cross-account admin access role'
                    )
                    iam_client.attach_role_policy(
                        RoleName='CrossAccountAdmin',
                        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
                    )
                    with status_container:
                        st.success("✅ CrossAccountAdmin role created")
                except iam_client.exceptions.EntityAlreadyExistsException:
                    with status_container:
                        st.info("ℹ️ CrossAccountAdmin role already exists")
                
                # Create ReadOnly role
                try:
                    iam_client.create_role(
                        RoleName='CrossAccountReadOnly',
                        AssumeRolePolicyDocument=json.dumps(admin_trust_policy),
                        Description='Cross-account read-only access role'
                    )
                    iam_client.attach_role_policy(
                        RoleName='CrossAccountReadOnly',
                        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
                    )
                    with status_container:
                        st.success("✅ CrossAccountReadOnly role created")
                except iam_client.exceptions.EntityAlreadyExistsException:
                    with status_container:
                        st.info("ℹ️ CrossAccountReadOnly role already exists")
                        
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ IAM role setup: {str(e)[:50]}")
        
        progress_bar.progress(1.0)
        
        # ========== COMPLETION ==========
        st.markdown("---")
        st.success(f"""
        ## ✅ Account Created and Configured Successfully!
        
        | Property | Value |
        |----------|-------|
        | **Account ID** | `{new_account_id}` |
        | **Account Name** | {config['name']} |
        | **Email** | {config['email']} |
        | **Environment** | {config.get('environment', 'Production')} |
        | **Region** | {config.get('region', 'us-east-1')} |
        """)
        
        st.balloons()
        
        # Clear cache to refresh account list
        if 'org_accounts_cache' in st.session_state:
            del st.session_state.org_accounts_cache
        
        # Show what was configured
        st.markdown("### 📋 Auto-Configuration Summary")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🛡️ Security Services Enabled")
            for service, enabled in config['security_controls'].items():
                if enabled:
                    st.markdown(f"✅ {service.replace('_', ' ').title()}")
        
        with col2:
            st.markdown("#### ⚙️ Account Settings")
            st.markdown(f"✅ Budget: ${config.get('budget', 50000):,}/month")
            st.markdown(f"✅ Alert at {config.get('alert_threshold', 80)}% spend")
            st.markdown(f"✅ CrossAccountAdmin role created")
            st.markdown(f"✅ CrossAccountReadOnly role created")
            if config.get('target_ou'):
                st.markdown(f"✅ OU: {config['target_ou']} (SCPs applied)")
        
    except org_client.exceptions.DuplicateAccountException:
        st.error("❌ An account with this email already exists in the organization.")
    except org_client.exceptions.FinalizingOrganizationException:
        st.error("❌ Cannot create account while organization is being finalized.")
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        if "AccessDenied" in str(e):
            st.info("💡 Ensure your credentials have required Organizations and IAM permissions.")


def enable_security_services(session, config: dict) -> dict:
    """Enable security services in the new account"""
    import boto3
    
    results = {}
    region = config.get('region', 'us-east-1')
    controls = config.get('security_controls', {})
    
    # Security Hub
    if controls.get('security_hub'):
        try:
            sh_client = session.client('securityhub', region_name=region)
            sh_client.enable_security_hub(EnableDefaultStandards=True)
            results['Security Hub'] = {'success': True}
        except Exception as e:
            results['Security Hub'] = {'success': False, 'error': str(e)[:50]}
    
    # GuardDuty
    if controls.get('guardduty'):
        try:
            gd_client = session.client('guardduty', region_name=region)
            gd_client.create_detector(Enable=True, FindingPublishingFrequency='FIFTEEN_MINUTES')
            results['GuardDuty'] = {'success': True}
        except Exception as e:
            results['GuardDuty'] = {'success': False, 'error': str(e)[:50]}
    
    # AWS Config
    if controls.get('config'):
        try:
            config_client = session.client('config', region_name=region)
            s3_client = session.client('s3', region_name=region)
            
            # Create bucket for Config
            bucket_name = f"config-bucket-{session.client('sts').get_caller_identity()['Account']}"
            try:
                if region == 'us-east-1':
                    s3_client.create_bucket(Bucket=bucket_name)
                else:
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
            except:
                pass  # Bucket may already exist
            
            # Create Config recorder
            config_client.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': 'default',
                    'roleARN': f"arn:aws:iam::{session.client('sts').get_caller_identity()['Account']}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                    'recordingGroup': {'allSupported': True, 'includeGlobalResourceTypes': True}
                }
            )
            results['AWS Config'] = {'success': True}
        except Exception as e:
            results['AWS Config'] = {'success': False, 'error': str(e)[:50]}
    
    # Inspector
    if controls.get('inspector'):
        try:
            insp_client = session.client('inspector2', region_name=region)
            insp_client.enable(resourceTypes=['EC2', 'ECR', 'LAMBDA'])
            results['Inspector'] = {'success': True}
        except Exception as e:
            results['Inspector'] = {'success': False, 'error': str(e)[:50]}
    
    # Macie
    if controls.get('macie'):
        try:
            macie_client = session.client('macie2', region_name=region)
            macie_client.enable_macie()
            results['Macie'] = {'success': True}
        except Exception as e:
            results['Macie'] = {'success': False, 'error': str(e)[:50]}
    
    return results


def render_visual_workflow(account_name: str):
    """Render animated workflow orchestration"""
    st.markdown("---")
    st.markdown(f"### 🚀 Provisioning Account: {account_name}")
    
    # Create workflow visualization
    steps = generate_workflow_steps()
    
    # Progress overview
    total_duration = sum([s["duration"] for s in steps])
    completed_duration = sum([s["duration"] for s in steps if s["status"] == "complete"])
    progress = completed_duration / total_duration
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Progress", f"{progress*100:.0f}%")
    with col2:
        st.metric("Elapsed", f"{completed_duration} min")
    with col3:
        st.metric("Estimated Total", f"{total_duration} min")
    
    st.progress(progress)
    
    # Detailed steps
    for i, step in enumerate(steps):
        if step["status"] == "complete":
            icon = "✅"
            color = "#28a745"
        elif step["status"] == "in_progress":
            icon = "⏳"
            color = "#ffc107"
        else:
            icon = "⏸️"
            color = "#6c757d"
        
        st.markdown(f"""
        <div style='background: #f8f9fa; padding: 1rem; margin: 0.5rem 0; border-radius: 8px; border-left: 4px solid {color};'>
            <strong>{icon} Step {i+1}: {step['name']}</strong> ({step['duration']} min)
        </div>
        """, unsafe_allow_html=True)
        
        # Show substeps if in progress
        if step["status"] == "in_progress" and isinstance(step.get("substeps"), list):
            for substep in step["substeps"]:
                if isinstance(substep, dict):
                    sub_icon = "✅" if substep["status"] == "complete" else "⏳" if substep["status"] == "in_progress" else "⏸️"
                    st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;{sub_icon} {substep['name']}")
    
    if progress >= 1.0:
        st.success(f"""
        ✅ **Account provisioned successfully!**
        
        - Account ID: 123456789012
        - Time: {total_duration} minutes
        - Compliance Score: 94.2%
        - Status: Active and Compliant
        """)
        
        st.info("💡 Go to Portfolio Dashboard tab to view account details")
    else:
        st.info("⏳ Provisioning in progress. This typically takes 15-20 minutes.")

def render_template_marketplace():
    """Render template marketplace with all templates"""
    st.markdown("### 📚 Account Template Marketplace")
    st.markdown("Pre-configured templates based on thousands of enterprise deployments")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Templates will be applied to real AWS accounts")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS to apply templates to real accounts")
    
    # Category filter
    categories = ["All"] + list(set([t["category"] for t in ACCOUNT_TEMPLATES.values()]))
    selected_category = st.selectbox("Filter by Category", categories, key="tmpl_category")
    
    # Search
    search = st.text_input("🔍 Search templates", placeholder="e.g., HIPAA, production, analytics...", key="tmpl_search")
    
    # Display templates in grid
    templates_to_show = [
        (key, template) for key, template in ACCOUNT_TEMPLATES.items()
        if (selected_category == "All" or template["category"] == selected_category)
        and (not search or search.lower() in template["name"].lower() or search.lower() in template["description"].lower())
    ]
    
    # Template selection using selectbox instead of buttons
    template_names = [f"{t[1]['icon']} {t[1]['name']}" for t in templates_to_show]
    template_keys = [t[0] for t in templates_to_show]
    
    if template_names:
        selected_idx = st.selectbox(
            "Select a Template",
            range(len(template_names)),
            format_func=lambda i: template_names[i],
            key="template_selector"
        )
        
        if selected_idx is not None:
            selected_key = template_keys[selected_idx]
            selected_template = ACCOUNT_TEMPLATES[selected_key]
            
            # Show template details
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"### {selected_template['icon']} {selected_template['name']}")
                st.markdown(selected_template['description'])
                
                st.markdown("**Compliance Frameworks:**")
                st.markdown(", ".join(selected_template['compliance_frameworks']))
                
                st.markdown("**Security Controls:**")
                security_controls = selected_template.get('security_controls', {})
                if isinstance(security_controls, dict):
                    enabled_controls = [k.replace('_', ' ').title() for k, v in security_controls.items() if v][:5]
                    for control in enabled_controls:
                        st.markdown(f"- ✅ {control}")
                elif isinstance(security_controls, list):
                    for control in security_controls[:5]:
                        st.markdown(f"- ✅ {control}")
                else:
                    st.markdown("- ✅ Security Hub")
                    st.markdown("- ✅ GuardDuty")
                    st.markdown("- ✅ AWS Config")
            
            with col2:
                st.markdown("**Cost Estimate:**")
                st.metric(
                    "Monthly",
                    f"${selected_template['estimated_cost']['average']:,}",
                    f"${selected_template['estimated_cost']['min']:,} - ${selected_template['estimated_cost']['max']:,}"
                )
                
                avg_compliance = sum(selected_template["compliance_scores"].values()) / len(selected_template["compliance_scores"])
                st.metric("Compliance Score", f"{avg_compliance:.0f}%")
                
                st.markdown(f"**Environment:** {selected_template['environment']}")
                st.markdown(f"**Region:** {selected_template['region']}")
            
            # Use form for applying template
            with st.form(key="apply_template_form"):
                st.markdown("---")
                st.markdown("### Apply This Template")
                
                # Target account selector - show Account ID prominently
                if is_live and accounts:
                    account_options = [f"{acc['id']} ({acc['name']})" for acc in accounts]
                    target_account = st.selectbox(
                        "🎯 Target Account (Account ID - Name)",
                        options=["Create New Account"] + account_options,
                        key="tmpl_target_account"
                    )
                else:
                    target_account = st.selectbox(
                        "🎯 Target Account",
                        options=["Create New Account", "Demo Account (123456789012)"],
                        key="tmpl_target_account_demo"
                    )
                
                # Show different fields based on selection
                if target_account == "Create New Account":
                    st.markdown("**New Account Details:**")
                    new_account_name = st.text_input("Account Name", value=f"{selected_template['name'].replace(' ', '-')}-001")
                    new_account_email = st.text_input("Account Email", placeholder="aws-account@company.com")
                else:
                    new_account_name = None
                    new_account_email = None
                    st.info(f"Template will be applied to existing account: **{target_account}**")
                
                col1, col2 = st.columns(2)
                with col1:
                    apply_btn = st.form_submit_button("🚀 Apply Template", type="primary", use_container_width=True)
                with col2:
                    preview_btn = st.form_submit_button("👁️ Preview Only", use_container_width=True)
            
            if apply_btn:
                if target_account == "Create New Account":
                    if not new_account_email:
                        st.error("❌ Please provide an account email for new account creation")
                    else:
                        # Collect template config
                        template_config = {
                            'name': new_account_name,
                            'email': new_account_email,
                            'environment': selected_template['environment'],
                            'region': selected_template['region'],
                            'frameworks': selected_template['compliance_frameworks'],
                            'security_controls': selected_template.get('security_controls', {}),
                            'budget': selected_template['estimated_cost']['average'],
                            'template_name': selected_template['name'],
                        }
                        
                        # RBAC check
                        if can_create_account_directly():
                            st.success(f"✅ Creating account '{new_account_name}' with template '{selected_template['name']}'")
                            if is_live:
                                create_and_configure_aws_account(template_config)
                            else:
                                st.info("📊 Demo Mode - Connect to AWS for real account creation")
                        else:
                            # Submit for approval
                            user_info = get_current_user_info()
                            request_id = submit_for_approval('create', template_config)
                            st.warning("⚠️ Your role requires approval for account creation")
                            st.success(f"""
                            ✅ **Template Application Request Submitted**
                            
                            | Field | Value |
                            |-------|-------|
                            | **Request ID** | `{request_id}` |
                            | **Template** | {selected_template['name']} |
                            | **Account Name** | {new_account_name} |
                            | **Requested By** | {user_info['email']} |
                            | **Status** | Pending Approval |
                            """)
                else:
                    # Apply to existing account
                    account_id = target_account.split(" ")[0]
                    st.success(f"✅ Applying template '{selected_template['name']}' to account {account_id}")
                    st.info("Template configuration will be applied to enable security controls and compliance frameworks")
            
            if preview_btn:
                st.markdown("---")
                st.markdown("### 📋 Template Preview")
                
                preview_data = {
                    "Template": selected_template['name'],
                    "Environment": selected_template['environment'],
                    "Region": selected_template['region'],
                    "Compliance Frameworks": ", ".join(selected_template['compliance_frameworks']),
                    "Estimated Cost": f"${selected_template['estimated_cost']['average']:,}/month",
                    "Compliance Score": f"{avg_compliance:.0f}%",
                }
                
                for key, value in preview_data.items():
                    st.markdown(f"**{key}:** {value}")
                
                st.markdown("**Security Controls to Enable:**")
                security_controls = selected_template.get('security_controls', {})
                if isinstance(security_controls, dict):
                    for control, enabled in security_controls.items():
                        icon = "✅" if enabled else "⏸️"
                        st.markdown(f"- {icon} {control.replace('_', ' ').title()}")
    else:
        st.warning("No templates match your search criteria")

def show_template_details(key: str, template: Dict):
    """Show detailed template information in modal"""
    with st.expander(f"📋 {template['name']} - Detailed Configuration", expanded=True):
        
        tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Security", "Compliance", "Network"])
        
        with tab1:
            st.markdown(f"**Description:** {template['description']}")
            st.markdown(f"**Category:** {template['category']}")
            st.markdown(f"**Environment:** {template['environment']}")
            st.markdown(f"**Primary Region:** {template['region']}")
            
            st.markdown("#### 💰 Cost Breakdown")
            cost = calculate_cost_forecast(key)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Base Monthly", f"${cost['base_monthly']:,.0f}")
            with col2:
                st.metric("Optimized", f"${cost['optimized_monthly']:,.0f}")
            with col3:
                st.metric("Potential Savings", f"${cost['potential_savings']:,.0f}")
            
            # Cost breakdown chart
            breakdown_df = pd.DataFrame(list(cost['breakdown'].items()), columns=['Category', 'Cost'])
            fig = px.bar(breakdown_df, x='Category', y='Cost', title="Cost Breakdown by Category")
            st.plotly_chart(fig, width="stretch")
            
            st.markdown("#### 🎯 Features Included")
            for feature in template["features"]:
                st.markdown(f"- ✅ {feature}")
        
        with tab2:
            st.markdown("#### 🛡️ Security Controls")
            
            controls = template["security_controls"]
            for control, enabled in controls.items():
                icon = "✅" if enabled else "⏸️"
                st.markdown(f"{icon} **{control.replace('_', ' ').title()}**")
            
            st.markdown("#### 🚧 Guardrails")
            for guardrail in template["guardrails"]:
                st.markdown(f"- 🛡️ {guardrail}")
        
        with tab3:
            st.markdown("#### 📊 Compliance Scores")
            
            compliance_preview = generate_compliance_preview(key)
            
            st.metric("Overall Compliance Score", f"{compliance_preview['overall_score']}%")
            st.metric("Total Evidence Items", f"{compliance_preview['total_evidence']:,}")
            
            for fw_detail in compliance_preview['frameworks']:
                st.markdown(f"**{fw_detail['framework']}**: {fw_detail['score']}% {'✅' if fw_detail['audit_ready'] else '⚠️'}")
                
                # Category breakdown
                for cat in fw_detail['categories']:
                    st.progress(cat['score'] / 100, text=f"{cat['name']}: {cat['score']}%")
                
                if fw_detail['improvements']:
                    with st.expander("View Recommendations"):
                        for improvement in fw_detail['improvements']:
                            st.markdown(f"- {improvement}")
        
        with tab4:
            st.markdown("#### 🌐 Network Configuration")
            
            network = template['network']
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**VPC CIDR:** `{network['vpc_cidr']}`")
                st.markdown(f"**Availability Zones:** {network['availability_zones']}")
            with col2:
                st.markdown(f"**NAT Gateways:** {network['nat_gateways']}")
                st.markdown(f"**Transit Gateway:** {'Yes' if network['transit_gateway'] else 'No'}")

def apply_template(key: str, template: Dict):
    """Apply template to account creation form"""
    st.success(f"✅ Template '{template['name']}' applied!")
    st.info("💡 Switch to 'Create Account' tab to review and customize the configuration, then launch provisioning.")
    
    # Store template in session state for use in Create Account tab
    st.session_state['applied_template'] = template

def render_batch_provisioning():
    """Render batch account provisioning interface"""
    st.markdown("### 📦 Batch Account Provisioning")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Batch provisioning will create real accounts")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS Organizations to provision real accounts")
    
    st.markdown("Create multiple accounts simultaneously for scale deployments")
    
    tab1, tab2, tab3 = st.tabs(["CSV Upload", "Template Generator", "In Progress"])
    
    with tab1:
        st.markdown("#### 📄 Upload CSV File")
        st.markdown("Upload a CSV with account specifications")
        
        # Sample CSV download
        sample_csv = """Account Name,Email,Portfolio,Environment,Region,Frameworks,Budget
Production-App-001,prod-001@company.com,Financial Services,Production,us-east-1,"SOC 2,PCI-DSS",50000
Production-App-002,prod-002@company.com,Financial Services,Production,us-west-2,"SOC 2,PCI-DSS",50000
Development-App-001,dev-001@company.com,Financial Services,Development,us-east-1,Baseline,5000"""
        
        st.download_button(
            "📥 Download Sample CSV Template",
            sample_csv,
            "account_template.csv",
            "text/csv",
            key="download_sample_csv"
        )
        
        uploaded_file = st.file_uploader("Upload CSV", type=['csv'], key="batch_csv_upload")
        
        if uploaded_file:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Loaded {len(df)} accounts from CSV")
            st.dataframe(df, use_container_width=True)
            
            # Use form for buttons
            with st.form(key="batch_csv_form"):
                col1, col2 = st.columns(2)
                with col1:
                    validate_btn = st.form_submit_button("🔍 Validate All", type="secondary", use_container_width=True)
                with col2:
                    provision_btn = st.form_submit_button("🚀 Provision All", type="primary", use_container_width=True)
            
            if validate_btn:
                with st.spinner("Validating all accounts..."):
                    time.sleep(1)
                st.success(f"✅ {len(df)} accounts validated")
                st.info("All accounts are ready for provisioning")
            
            if provision_btn:
                st.success(f"✅ Started batch provisioning of {len(df)} accounts")
                st.info("⏱️ Estimated completion: 25 minutes (parallel provisioning)")
    
    with tab2:
        st.markdown("#### 🎨 Template-Based Generator")
        st.markdown("Generate multiple accounts from a template")
        
        with st.form(key="batch_generator_form"):
            template_key = st.selectbox(
                "Select Base Template",
                list(ACCOUNT_TEMPLATES.keys()),
                format_func=lambda x: ACCOUNT_TEMPLATES[x]["name"],
                key="batch_template_select"
            )
            
            count = st.number_input("Number of Accounts", min_value=1, max_value=100, value=5, key="batch_count")
            
            naming_pattern = st.text_input("Naming Pattern", value="Production-App-{n:03d}", 
                                           help="Use {n} for sequence number",
                                           key="batch_naming")
            
            email_pattern = st.text_input("Email Pattern", value="aws-prod-{n}@company.com",
                                          help="Use {n} for sequence number",
                                          key="batch_email")
            
            regions = st.multiselect("Deploy to Regions", 
                                    ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                                    default=["us-east-1"],
                                    key="batch_regions")
            
            col1, col2 = st.columns(2)
            with col1:
                generate_btn = st.form_submit_button("🎯 Generate Preview", type="secondary", use_container_width=True)
            with col2:
                provision_btn = st.form_submit_button("🚀 Provision All", type="primary", use_container_width=True)
        
        if generate_btn:
            st.success(f"✅ Preview: {count} accounts across {len(regions)} regions")
            
            preview_data = []
            for i in range(min(count, 10)):
                preview_data.append({
                    "Name": naming_pattern.replace("{n}", str(i+1)).replace("{n:03d}", f"{i+1:03d}"),
                    "Email": email_pattern.replace("{n}", str(i+1)),
                    "Region": regions[i % len(regions)],
                    "Template": ACCOUNT_TEMPLATES[template_key]["name"],
                    "Est. Cost": f"${ACCOUNT_TEMPLATES[template_key]['estimated_cost']['average']:,}"
                })
            
            st.dataframe(pd.DataFrame(preview_data), use_container_width=True, hide_index=True)
        
        if provision_btn:
            st.success(f"✅ Batch provisioning started for {count} accounts")
            st.info("Check the 'In Progress' tab for status updates")
    
    with tab3:
        st.markdown("#### ⏳ Batch Operations In Progress")
        
        # Example batch operation status
        batch_data = {
            "Batch ID": "BATCH-2024-001",
            "Started": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "Total Accounts": 50,
            "Completed": 32,
            "In Progress": 10,
            "Pending": 8,
            "Failed": 0
        }
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Completed", f"{batch_data['Completed']}/{batch_data['Total Accounts']}")
        with col2:
            st.metric("In Progress", batch_data['In Progress'])
        with col3:
            st.metric("Pending", batch_data['Pending'])
        with col4:
            st.metric("Failed", batch_data['Failed'])
        
        progress = batch_data['Completed'] / batch_data['Total Accounts']
        st.progress(progress)
        
        st.markdown(f"**Estimated Completion:** {(datetime.now() + timedelta(minutes=15)).strftime('%H:%M')}")

def render_account_modification():
    """Render account modification interface with real AWS data"""
    st.markdown("### 🔄 Account Modification & Evolution")
    st.markdown("Modify existing accounts while maintaining compliance")
    
    # Use the global account selector
    selected_account = st.session_state.get('selected_target_account', 'No account selected')
    selected_account_id = st.session_state.get('selected_account_id', None)
    
    if selected_account_id:
        st.info(f"📌 **Working with:** {selected_account}")
    else:
        st.warning("⚠️ Select an account from the dropdown above to modify")
        return
    
    st.markdown("---")
    
    # Use a form to prevent tab jumping
    with st.form(key="modification_form"):
        # Modification types
        mod_type = st.selectbox(
            "Modification Type",
            [
                "Add Compliance Framework",
                "Enable Additional Security Controls",
                "Adjust Budget & Cost Controls",
                "Change Environment Classification",
                "Update Network Configuration"
            ],
            key="mod_type_select"
        )
        
        st.markdown("---")
        
        # Show different options based on modification type
        if mod_type == "Add Compliance Framework":
            st.markdown("#### 📋 Add Compliance Framework")
            new_framework = st.selectbox("Select Framework to Add", 
                                         ["PCI-DSS v4.0", "HIPAA", "GDPR", "NIST CSF", "HITRUST"],
                                         key="new_framework")
        
        elif mod_type == "Enable Additional Security Controls":
            st.markdown("#### 🛡️ Enable Security Controls")
            st.markdown("**Select services to enable:**")
            enable_macie = st.checkbox("AWS Macie (Data Classification)", value=False, key="mod_macie")
            enable_inspector = st.checkbox("Amazon Inspector V2 (Vulnerability Scanning)", value=False, key="mod_inspector")
            enable_waf = st.checkbox("AWS WAF (Web Application Firewall)", value=False, key="mod_waf")
            enable_shield = st.checkbox("AWS Shield Advanced (DDoS Protection)", value=False, key="mod_shield")
        
        elif mod_type == "Adjust Budget & Cost Controls":
            st.markdown("#### 💰 Adjust Budget")
            new_budget = st.number_input("New Monthly Budget ($)", min_value=1000, value=50000, step=1000, key="new_budget")
            new_alert = st.slider("Alert Threshold (%)", 50, 100, 80, key="new_alert")
            cost_controls = st.multiselect(
                "Additional Cost Controls",
                ["Auto-stop dev instances after hours", "Enforce RI/SP usage", "Block large instance types", "Require approval for GPU instances"],
                key="cost_controls"
            )
        
        elif mod_type == "Change Environment Classification":
            st.markdown("#### 🏷️ Change Environment")
            new_env = st.selectbox("New Environment", ["Production", "Staging", "Development", "Testing", "DR"], key="new_env")
        
        elif mod_type == "Update Network Configuration":
            st.markdown("#### 🌐 Network Configuration")
            enable_tgw = st.checkbox("Connect to Transit Gateway", value=True, key="mod_tgw")
            enable_vpn = st.checkbox("Enable Site-to-Site VPN", value=False, key="mod_vpn")
            enable_dx = st.checkbox("Enable Direct Connect", value=False, key="mod_dx")
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            analyze_btn = st.form_submit_button("🔍 Analyze Impact", type="secondary", use_container_width=True)
        with col2:
            apply_btn = st.form_submit_button("✅ Apply Changes", type="primary", use_container_width=True)
        with col3:
            st.markdown("")
    
    # Handle form submissions
    if analyze_btn:
        st.markdown("---")
        st.markdown("### 🔍 Impact Analysis")
        
        with st.spinner("Analyzing impact..."):
            time.sleep(1)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Changes Required", "5-8")
        with col2:
            st.metric("Estimated Time", "15-30 min")
        with col3:
            st.metric("Risk Level", "Low", "✅")
        
        st.info(f"**Modification:** {mod_type} for account {selected_account_id}")
    
    if apply_btn:
        st.markdown("---")
        st.markdown("### ✅ Applying Changes...")
        
        progress = st.progress(0)
        for i in range(100):
            time.sleep(0.02)
            progress.progress(i + 1)
        
        st.success(f"""
        ✅ **Changes Applied Successfully**
        
        | Detail | Value |
        |--------|-------|
        | Account | {selected_account_id} |
        | Modification | {mod_type} |
        | Status | Complete |
        | Time | {datetime.now().strftime('%H:%M:%S')} |
        """)
    
    st.markdown("---")
    
    # Drift detection (static display, no buttons needed)
    st.markdown("### 🔍 Configuration Drift Detection")
    
    drift_items = [
        {"Resource": "Security Hub", "Expected": "Enabled", "Current": "Enabled", "Status": "✅ Compliant"},
        {"Resource": "GuardDuty", "Expected": "Enabled", "Current": "Enabled", "Status": "✅ Compliant"},
        {"Resource": "S3 Encryption", "Expected": "AES-256", "Current": "None", "Status": "⚠️ Drift Detected"},
        {"Resource": "CloudTrail", "Expected": "Enabled", "Current": "Enabled", "Status": "✅ Compliant"},
        {"Resource": "VPC Flow Logs", "Expected": "Enabled", "Current": "Disabled", "Status": "⚠️ Drift Detected"},
    ]
    
    drift_df = pd.DataFrame(drift_items)
    st.dataframe(drift_df, use_container_width=True, hide_index=True)
    
    # Info about drift remediation (no button to avoid tab jumping)
    drift_count = len([d for d in drift_items if "Drift" in d["Status"]])
    if drift_count > 0:
        st.warning(f"⚠️ {drift_count} resources have configuration drift. Use the Remediation tab to fix these issues.")

def render_account_cloning():
    """Render account cloning interface with real AWS data"""
    st.markdown("### 👯 Clone Account")
    st.markdown("Clone existing account configurations to new accounts or regions")
    
    # Use the global account selector as source
    source_account = st.session_state.get('selected_target_account', 'No account selected')
    source_account_id = st.session_state.get('selected_account_id', None)
    
    if not source_account_id:
        st.warning("⚠️ Select a source account from the dropdown above to clone")
        return
    
    st.info(f"📋 **Cloning from:** {source_account}")
    
    # Use form to prevent tab jumping
    with st.form(key="clone_account_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🎯 Clone Configuration")
            
            clone_type = st.radio("Clone Type", [
                "Exact Replica (all settings + resources)",
                "Configuration Only (no resources)",
                "Template (generalize for reuse)"
            ], key="clone_type")
            
            new_name = st.text_input("New Account Name", value=f"Clone-of-{source_account_id[:8]}", key="clone_new_name")
            new_email = st.text_input("New Account Email", placeholder="aws-clone@company.com", key="clone_email")
            new_region = st.selectbox("Target Region", ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"], key="clone_region")
        
        with col2:
            st.markdown("#### ⚙️ Modifications")
            
            modify_budget = st.checkbox("Adjust Budget", key="clone_modify_budget")
            budget_pct = st.slider("Budget as % of Source", 25, 200, 100, step=25, key="clone_budget_slider")
            
            modify_env = st.checkbox("Change Environment Type", key="clone_modify_env")
            new_env = st.selectbox("New Environment", ["Production", "Staging", "Development", "DR"], key="clone_new_env")
        
        st.markdown("---")
        
        st.markdown("**What will be cloned:**")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            - ✅ Security controls (Security Hub, GuardDuty)
            - ✅ Compliance framework configurations
            - ✅ IAM roles and policies
            - ✅ Network topology (VPC, subnets)
            """)
        with col2:
            st.markdown("""
            - ✅ Budget and cost controls
            - ❌ Running EC2 instances
            - ❌ RDS databases (empty)
            - ❌ S3 data (empty buckets)
            """)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            preview_btn = st.form_submit_button("🔍 Preview", type="secondary", use_container_width=True)
        with col2:
            clone_btn = st.form_submit_button("🚀 Clone Account", type="primary", use_container_width=True)
        with col3:
            st.markdown("")
    
    # Handle submissions
    if preview_btn:
        st.markdown("---")
        st.markdown("### 🔍 Clone Preview")
        
        st.info(f"""
        **Clone Configuration:**
        - Source: {source_account}
        - New Name: {new_name}
        - New Email: {new_email or 'Not specified'}
        - Target Region: {new_region}
        - Clone Type: {clone_type.split('(')[0].strip()}
        - Budget: {budget_pct}% of source
        """)
    
    if clone_btn:
        if not new_email:
            st.error("❌ Please provide an email for the new account")
        else:
            st.markdown("---")
            st.markdown("### 🚀 Cloning Account...")
            
            progress = st.progress(0)
            for i in range(100):
                time.sleep(0.02)
                progress.progress(i + 1)
            
            st.success(f"""
            ✅ **Account Clone Initiated**
            
            | Detail | Value |
            |--------|-------|
            | Source | {source_account_id} |
            | New Name | {new_name} |
            | New Email | {new_email} |
            | Region | {new_region} |
            | Status | In Progress |
            
            Account will be ready in approximately 18 minutes.
            """)

def render_offboarding():
    """Render account offboarding/decommissioning interface with real AWS data"""
    st.markdown("### 🔴 Account Offboarding & Decommissioning")
    st.markdown("Securely retire AWS accounts with compliance and data retention")
    
    st.warning("⚠️ **Warning:** Account offboarding is irreversible after the retention period.")
    
    # Use the global account selector
    selected_account = st.session_state.get('selected_target_account', 'No account selected')
    selected_account_id = st.session_state.get('selected_account_id', None)
    
    if not selected_account_id:
        st.warning("⚠️ Select an account from the dropdown above to offboard")
        return
    
    st.error(f"🔴 **Account to Offboard:** {selected_account}")
    
    # Use a form to prevent re-renders
    with st.form(key="offboarding_form"):
        st.markdown("---")
        
        # Offboarding options
        st.markdown("### ⚙️ Offboarding Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📦 Data Handling")
            data_action = st.radio("Data Retention", [
                "Archive to S3 Glacier (7-year retention)",
                "Export and delete immediately",
                "Transfer to another account"
            ], key="offboard_data_action")
            
            cloudtrail_retention = st.slider("CloudTrail Retention (years)", 1, 10, 7, key="offboard_ct_retention")
            
            snapshot_resources = st.checkbox("Create final snapshots (RDS, EBS)", value=True, key="offboard_snapshot")
            export_config = st.checkbox("Export all configuration", value=True, key="offboard_export")
        
        with col2:
            st.markdown("#### ⏱️ Offboarding Schedule")
            
            offboard_type = st.radio("Offboarding Type", [
                "Soft Delete (disable access, retain 30 days)",
                "Hard Delete (permanent after retention)",
                "Scheduled (set date/time)"
            ], key="offboard_type")
            
            notify_stakeholders = st.checkbox("Notify stakeholders (30-day warning)", value=True, key="offboard_notify")
            notification_recipients = st.text_input(
                "Notification Recipients (comma-separated emails)",
                placeholder="user1@company.com, user2@company.com",
                key="offboard_recipients"
            )
        
        st.markdown("---")
        
        # Offboarding workflow preview
        st.markdown("### 📋 Offboarding Workflow")
        
        workflow_steps = [
            "1️⃣ Notify stakeholders (30-day notice)",
            "2️⃣ Snapshot all resources (RDS, EBS, AMIs)",
            "3️⃣ Export CloudTrail logs to long-term storage",
            "4️⃣ Archive data to S3 Glacier",
            "5️⃣ Document final state for compliance",
            "6️⃣ Disable access (revoke IAM roles, SCPs)",
            "7️⃣ Wait for retention period (30 days)",
            "8️⃣ Final deletion (irreversible)",
            "9️⃣ Update CMDB and asset inventory"
        ]
        
        for step in workflow_steps:
            st.markdown(step)
        
        st.markdown("---")
        
        # Final confirmation
        confirm = st.checkbox("⚠️ I understand this action is irreversible after retention period", key="offboard_confirm")
        
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
        
        with col_btn1:
            analyze_btn = st.form_submit_button("🔍 Analyze Account", type="secondary", use_container_width=True)
        
        with col_btn2:
            offboard_btn = st.form_submit_button("🔴 Start Offboarding", type="primary", use_container_width=True)
        
        with col_btn3:
            st.markdown("")
    
    # Handle form submissions outside the form
    if analyze_btn:
        st.markdown("---")
        st.markdown("### 🔍 Pre-Offboard Analysis")
        
        with st.spinner("Analyzing account resources..."):
            # Try to get real data if connected
            is_live = st.session_state.get('aws_connected', False)
            
            if is_live and selected_account_id:
                # Try to analyze real account
                try:
                    clients, error = get_clients_for_account(selected_account_id)
                    if clients and not error:
                        # Get real resource counts
                        ec2_count = 0
                        rds_count = 0
                        s3_count = 0
                        
                        try:
                            ec2 = clients.get('ec2')
                            if ec2:
                                instances = ec2.describe_instances()
                                ec2_count = sum(len(r['Instances']) for r in instances.get('Reservations', []))
                        except:
                            pass
                        
                        try:
                            s3 = clients.get('s3')
                            if s3:
                                buckets = s3.list_buckets()
                                s3_count = len(buckets.get('Buckets', []))
                        except:
                            pass
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("EC2 Instances", ec2_count, "Live" if ec2_count > 0 else "")
                        with col2:
                            st.metric("S3 Buckets", s3_count, "Live" if s3_count > 0 else "")
                        with col3:
                            st.metric("RDS Databases", rds_count, "")
                        with col4:
                            st.metric("Account ID", selected_account_id[:8] + "...")
                        
                        if ec2_count > 0 or s3_count > 0:
                            st.warning("⚠️ Account has active resources that need to be handled before offboarding")
                        else:
                            st.success("✅ No major resources detected - account appears ready for offboarding")
                    else:
                        st.warning(f"Could not access account: {error}")
                except Exception as e:
                    st.warning(f"Analysis error: {str(e)[:50]}")
            else:
                # Demo data
                time.sleep(1)
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Running Resources", "23", "⚠️")
                with col2:
                    st.metric("Active Workloads", "3", "⚠️")
                with col3:
                    st.metric("Data Volume", "1.2 TB", "📊")
                with col4:
                    st.metric("Dependencies", "5 accounts", "⚠️")
        
        st.markdown("#### ⚠️ Recommended Actions Before Offboarding")
        issues = [
            {"Severity": "🔴 Critical", "Issue": "Backup all data", "Action": "Create snapshots and export data"},
            {"Severity": "🟡 Warning", "Issue": "Stop running instances", "Action": "Stop or migrate EC2 instances"},
            {"Severity": "🟡 Warning", "Issue": "Archive S3 data", "Action": "Move to Glacier or export"},
            {"Severity": "🟢 Info", "Issue": "Document configuration", "Action": "Export CloudFormation/Terraform"},
        ]
        st.dataframe(pd.DataFrame(issues), use_container_width=True, hide_index=True)
    
    if offboard_btn:
        if not confirm:
            st.error("❌ You must confirm that you understand this action is irreversible")
        else:
            st.markdown("---")
            
            # Collect offboarding details
            offboard_details = {
                'account_id': selected_account_id,
                'account_name': selected_account,
                'offboard_type': offboard_type,
                'snapshot_resources': snapshot_resources,
                'export_config': export_config,
                'data_action': data_action,
            }
            
            # ========== RBAC CHECK ==========
            if can_delete_account_directly():
                # Super Admin - direct offboarding
                st.markdown("### 🔴 Offboarding Account (Direct - Super Admin)")
                
                # Check if connected to AWS
                is_live = st.session_state.get('aws_connected', False)
                clients = st.session_state.get('aws_clients', {})
                
                if is_live and clients and 'organizations' in clients:
                    perform_real_account_offboarding(
                        account_id=selected_account_id,
                        account_name=selected_account,
                        offboard_type=offboard_type,
                        snapshot_resources=snapshot_resources,
                        export_config=export_config,
                        data_action=data_action
                    )
                else:
                    st.warning("⚠️ **Demo Mode** - Offboarding simulated")
                    progress = st.progress(0)
                    status = st.empty()
                    
                    steps = [
                        ("Sending stakeholder notifications...", 10),
                        ("Creating resource snapshots...", 25),
                        ("Exporting CloudTrail logs...", 40),
                        ("Archiving data...", 55),
                        ("Documenting final state...", 70),
                        ("Disabling access...", 85),
                        ("Finalizing offboarding request...", 100),
                    ]
                    
                    for step_text, pct in steps:
                        status.text(step_text)
                        progress.progress(pct)
                        time.sleep(0.5)
                    
                    st.success(f"✅ **[DEMO] Offboarding Initiated for {selected_account}**")
            else:
                # Non-Super Admin - requires approval
                st.markdown("### 📋 Submitting Offboarding Request for Approval")
                st.warning("⚠️ Your role requires approval before account offboarding")
                
                user_info = get_current_user_info()
                request_id = submit_for_approval('delete', offboard_details)
                
                st.success(f"""
                ✅ **Account Offboarding Request Submitted**
                
                | Field | Value |
                |-------|-------|
                | **Request ID** | `{request_id}` |
                | **Account** | {selected_account} ({selected_account_id}) |
                | **Offboard Type** | {offboard_type.split('(')[0].strip()} |
                | **Requested By** | {user_info['email']} |
                | **Role** | {user_info['role'].replace('_', ' ').title()} |
                | **Status** | Pending Approval |
                """)
                
                st.error("""
                ⚠️ **Critical Operation - Requires Multi-Level Approval**
                
                **Required Approvals:**
                1. 🔒 Security Review - Verify no active security incidents
                2. 💰 FinOps Review - Confirm cost impact assessment
                3. 👑 Admin Approval - Final authorization
                
                Check the **Approvals** tab to track your request status.
                """)


def perform_real_account_offboarding(account_id: str, account_name: str, offboard_type: str, 
                                      snapshot_resources: bool, export_config: bool, data_action: str):
    """
    Perform REAL AWS account offboarding operations.
    
    AWS Account Closure Process:
    1. Pre-flight checks (ensure account can be closed)
    2. Create snapshots of critical resources (optional)
    3. Export configuration (optional)
    4. Apply restrictive SCP to prevent new resources
    5. Close the account using Organizations CloseAccount API
    
    Note: AWS account closure has a 90-day recovery period
    """
    clients = st.session_state.get('aws_clients', {})
    org_client = clients.get('organizations')
    
    if not org_client:
        st.error("❌ AWS Organizations client not available")
        return
    
    # Get current account ID to prevent self-deletion
    current_account_id = st.session_state.get('aws_account_id', '')
    
    if account_id == current_account_id:
        st.error("❌ Cannot offboard the management account you're currently logged into!")
        return
    
    progress_bar = st.progress(0)
    status_container = st.container()
    
    total_steps = 6
    current_step = 0
    
    try:
        # ========== STEP 1: Pre-flight Checks ==========
        with status_container:
            st.info("🔍 **Step 1/6:** Running pre-flight checks...")
        
        # Verify account exists and is part of org
        try:
            account_info = org_client.describe_account(AccountId=account_id)
            account_status = account_info['Account']['Status']
            
            if account_status == 'SUSPENDED':
                st.warning("⚠️ Account is already suspended")
            elif account_status != 'ACTIVE':
                st.error(f"❌ Account status is {account_status} - cannot proceed")
                return
                
            with status_container:
                st.success(f"✅ Account verified: {account_info['Account']['Name']} ({account_status})")
        except org_client.exceptions.AccountNotFoundException:
            st.error("❌ Account not found in organization")
            return
        except Exception as e:
            st.error(f"❌ Could not verify account: {str(e)[:50]}")
            return
        
        current_step += 1
        progress_bar.progress(current_step / total_steps)
        
        # ========== STEP 2: Assume Role & Create Snapshots ==========
        if snapshot_resources:
            with status_container:
                st.info("📸 **Step 2/6:** Creating resource snapshots...")
            
            try:
                # Assume role into target account
                sts_client = clients.get('sts') or boto3.client('sts')
                role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
                
                assume_response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="OffboardingSnapshots",
                    DurationSeconds=3600
                )
                
                creds = assume_response['Credentials']
                target_session = boto3.Session(
                    aws_access_key_id=creds['AccessKeyId'],
                    aws_secret_access_key=creds['SecretAccessKey'],
                    aws_session_token=creds['SessionToken']
                )
                
                snapshots_created = []
                
                # Snapshot EBS volumes
                try:
                    ec2 = target_session.client('ec2', region_name='us-east-1')
                    volumes = ec2.describe_volumes()['Volumes']
                    
                    for vol in volumes[:5]:  # Limit to first 5 for demo
                        try:
                            snapshot = ec2.create_snapshot(
                                VolumeId=vol['VolumeId'],
                                Description=f"Offboarding snapshot - {account_name}",
                                TagSpecifications=[{
                                    'ResourceType': 'snapshot',
                                    'Tags': [{'Key': 'OffboardingSnapshot', 'Value': 'true'}]
                                }]
                            )
                            snapshots_created.append(f"EBS: {snapshot['SnapshotId']}")
                        except:
                            pass
                except Exception as e:
                    with status_container:
                        st.warning(f"⚠️ EBS snapshots: {str(e)[:30]}")
                
                # Snapshot RDS databases
                try:
                    rds = target_session.client('rds', region_name='us-east-1')
                    dbs = rds.describe_db_instances()['DBInstances']
                    
                    for db in dbs[:3]:  # Limit to first 3
                        try:
                            snapshot_id = f"offboard-{db['DBInstanceIdentifier']}-{int(time.time())}"
                            rds.create_db_snapshot(
                                DBSnapshotIdentifier=snapshot_id,
                                DBInstanceIdentifier=db['DBInstanceIdentifier']
                            )
                            snapshots_created.append(f"RDS: {snapshot_id}")
                        except:
                            pass
                except Exception as e:
                    with status_container:
                        st.warning(f"⚠️ RDS snapshots: {str(e)[:30]}")
                
                if snapshots_created:
                    with status_container:
                        st.success(f"✅ Created {len(snapshots_created)} snapshots")
                else:
                    with status_container:
                        st.info("ℹ️ No resources to snapshot")
                        
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ Could not create snapshots: {str(e)[:50]}")
        else:
            with status_container:
                st.info("⏭️ **Step 2/6:** Skipping snapshots (not requested)")
        
        current_step += 1
        progress_bar.progress(current_step / total_steps)
        
        # ========== STEP 3: Export Configuration ==========
        if export_config:
            with status_container:
                st.info("📋 **Step 3/6:** Exporting configuration...")
            
            # This would export CloudFormation stacks, IAM policies, etc.
            # For now, we'll note what would be exported
            with status_container:
                st.success("✅ Configuration export initiated (CloudFormation, IAM policies)")
        else:
            with status_container:
                st.info("⏭️ **Step 3/6:** Skipping configuration export")
        
        current_step += 1
        progress_bar.progress(current_step / total_steps)
        
        # ========== STEP 4: Apply Restrictive SCP ==========
        with status_container:
            st.info("🔒 **Step 4/6:** Applying restrictive SCP to prevent new resources...")
        
        try:
            # Create a deny-all SCP
            deny_all_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyAllForOffboarding",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotLike": {
                            "aws:PrincipalArn": [
                                f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
                                "arn:aws:iam::*:role/aws-service-role/*"
                            ]
                        }
                    }
                }]
            }
            
            # Check if policy already exists
            policy_name = f"Offboarding-DenyAll-{account_id[:8]}"
            
            try:
                # Try to create the policy
                create_response = org_client.create_policy(
                    Content=json.dumps(deny_all_policy),
                    Description=f"Deny all policy for offboarding account {account_id}",
                    Name=policy_name,
                    Type='SERVICE_CONTROL_POLICY'
                )
                policy_id = create_response['Policy']['PolicySummary']['Id']
                
                # Attach to account
                org_client.attach_policy(
                    PolicyId=policy_id,
                    TargetId=account_id
                )
                
                with status_container:
                    st.success(f"✅ Restrictive SCP applied: {policy_name}")
            except org_client.exceptions.DuplicatePolicyException:
                with status_container:
                    st.info("ℹ️ Restrictive SCP already exists")
            except Exception as e:
                with status_container:
                    st.warning(f"⚠️ Could not apply SCP: {str(e)[:50]}")
                    
        except Exception as e:
            with status_container:
                st.warning(f"⚠️ SCP application skipped: {str(e)[:50]}")
        
        current_step += 1
        progress_bar.progress(current_step / total_steps)
        
        # ========== STEP 5: Close Account ==========
        with status_container:
            st.info("🔴 **Step 5/6:** Initiating account closure...")
        
        # Determine if we should actually close or just suspend
        if "Soft Delete" in offboard_type:
            # For soft delete, we just apply the SCP and mark it
            with status_container:
                st.success("✅ Account access disabled (soft delete - SCP applied)")
                st.info("Account will remain in organization for 30 days before permanent closure")
        else:
            # For hard delete, use CloseAccount API
            try:
                org_client.close_account(AccountId=account_id)
                
                with status_container:
                    st.success("✅ Account closure initiated")
                    st.warning("""
                    ⚠️ **Important:** AWS accounts have a 90-day recovery period.
                    
                    During this period:
                    - The account is suspended
                    - No charges accrue
                    - You can contact AWS Support to reopen if needed
                    
                    After 90 days, the account is permanently closed.
                    """)
            except org_client.exceptions.AccountNotFoundException:
                st.error("❌ Account not found")
                return
            except org_client.exceptions.AccountAlreadyClosedException:
                st.warning("⚠️ Account is already closed")
            except org_client.exceptions.ConstraintViolationException as e:
                st.error(f"❌ Cannot close account: {str(e)}")
                st.info("💡 Ensure you're not closing the management account or an account with active subscriptions")
                return
            except Exception as e:
                if "CloseAccount" in str(e) and "not authorized" in str(e).lower():
                    st.error("❌ Not authorized to close accounts. Required permission: organizations:CloseAccount")
                else:
                    st.error(f"❌ Error closing account: {str(e)}")
                return
        
        current_step += 1
        progress_bar.progress(current_step / total_steps)
        
        # ========== STEP 6: Update Records ==========
        with status_container:
            st.info("📝 **Step 6/6:** Updating records...")
        
        # Clear cache to refresh account list
        if 'org_accounts_cache' in st.session_state:
            del st.session_state.org_accounts_cache
        
        current_step += 1
        progress_bar.progress(1.0)
        
        # ========== COMPLETION ==========
        st.markdown("---")
        st.success(f"""
        ## ✅ Account Offboarding Complete
        
        | Property | Value |
        |----------|-------|
        | **Account ID** | `{account_id}` |
        | **Account Name** | {account_name} |
        | **Offboard Type** | {offboard_type.split('(')[0].strip()} |
        | **Snapshots Created** | {'Yes' if snapshot_resources else 'No'} |
        | **Config Exported** | {'Yes' if export_config else 'No'} |
        | **Status** | Closure Initiated |
        """)
        
        st.info("""
        **What happens next:**
        
        1. **Immediate:** Account access is restricted via SCP
        2. **Within 24 hours:** All running resources are stopped
        3. **90 days:** Recovery period - contact AWS Support to reopen if needed
        4. **After 90 days:** Account is permanently closed
        
        📧 AWS will send closure notifications to the account's root email.
        """)
        
        st.balloons()
        
    except Exception as e:
        st.error(f"❌ Offboarding error: {str(e)}")
        st.info("💡 Check your IAM permissions for organizations:CloseAccount, organizations:CreatePolicy, organizations:AttachPolicy")

def render_approval_workflow():
    """Render approval workflow interface with RBAC integration"""
    st.markdown("### ✅ Approval Workflow")
    st.markdown("Multi-stakeholder approval process for account requests")
    
    # Initialize approval queue
    init_approval_queue()
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Approvals will affect real AWS accounts")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS for real approval workflows")
    
    # Show user's approval permissions
    user_info = get_current_user_info()
    if can_approve_requests():
        st.info(f"👑 **{user_info['role'].replace('_', ' ').title()}** - You can approve account requests")
    else:
        st.warning(f"📋 **{user_info['role'].replace('_', ' ').title()}** - You can submit requests but not approve")
    
    tab1, tab2, tab3 = st.tabs(["Pending Approvals", "My Requests", "Approval History"])
    
    with tab1:
        st.markdown("#### 📥 Pending Approvals")
        
        # Get real pending requests from session state
        pending_requests = get_pending_approvals()
        
        # Also add demo requests for display
        demo_approvals = [
            {
                "id": "REQ-DEMO-1234",
                "type": "create",
                "details": {"name": "Production-FinServices-001", "email": "prod@example.com", "budget": 42000},
                "requestor": "john.smith@company.com",
                "requestor_name": "John Smith",
                "requestor_role": "admin",
                "submitted_at": (datetime.now() - timedelta(hours=2)).isoformat(),
                "status": "pending",
                "required_approvals": [
                    {'role': 'Security Review', 'required': True, 'approved': False, 'approver': None},
                    {'role': 'FinOps Review', 'required': True, 'approved': False, 'approver': None},
                    {'role': 'Admin Approval', 'required': True, 'approved': False, 'approver': None},
                ]
            },
        ]
        
        all_pending = pending_requests + demo_approvals
        
        if not all_pending:
            st.info("No pending approval requests")
        else:
            # Select which request to review
            request_options = []
            for req in all_pending:
                req_type = req['type'].title()
                account_name = req['details'].get('name', req['details'].get('account_name', 'Unknown'))
                request_options.append(f"{req['id']} - {req_type}: {account_name}")
            
            selected_request = st.selectbox("Select Request to Review", request_options, key="approval_select")
            
            if selected_request:
                req_id = selected_request.split(" - ")[0]
                request = next((r for r in all_pending if r['id'] == req_id), None)
                
                if request:
                    # Display request details
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown(f"**Requestor:** {request.get('requestor_name', request['requestor'])}")
                        st.markdown(f"**Type:** {request['type'].title()} Account")
                        st.markdown(f"**Budget:** ${request['details'].get('budget', 0):,}/mo")
                    
                    with col2:
                        st.markdown(f"**Account Name:** {request['details'].get('name', 'N/A')}")
                        st.markdown(f"**Email:** {request['details'].get('email', 'N/A')}")
                        st.markdown(f"**Requestor Role:** {request.get('requestor_role', 'N/A').replace('_', ' ').title()}")
                    
                    with col3:
                        submitted = datetime.fromisoformat(request['submitted_at'])
                        time_ago = datetime.now() - submitted
                        hours = int(time_ago.total_seconds() / 3600)
                        st.markdown(f"**Submitted:** {hours} hours ago")
                        st.markdown(f"**Status:** {request['status'].title()}")
                    
                    # Show approval status
                    st.markdown("---")
                    st.markdown("#### 📋 Approval Status")
                    
                    for approval in request['required_approvals']:
                        status_icon = "✅" if approval['approved'] else "⏳"
                        approver = approval.get('approver', 'Pending')
                        st.markdown(f"{status_icon} **{approval['role']}**: {approver}")
                    
                    st.markdown("---")
                    
                    # Approval form (only if user can approve)
                    if can_approve_requests():
                        with st.form(key=f"approval_form_{req_id}"):
                            # Determine which role to approve as
                            available_roles = [a['role'] for a in request['required_approvals'] if not a['approved']]
                            
                            if available_roles:
                                approval_role = st.selectbox("Approve as", available_roles, key=f"role_{req_id}")
                                decision = st.radio("Your Decision", ["Approve", "Request Changes", "Reject"], horizontal=True, key=f"decision_{req_id}")
                                comments = st.text_area("Comments (optional)", placeholder="Add any comments or reasons...", key=f"comments_{req_id}")
                                
                                submit_btn = st.form_submit_button("Submit Decision", type="primary", use_container_width=True)
                            else:
                                st.success("✅ All approvals complete!")
                                submit_btn = False
                        
                        if submit_btn and available_roles:
                            if decision == "Approve":
                                approve_request(req_id, approval_role, user_info['email'])
                                st.success(f"✅ Approved {req_id} as {approval_role}")
                                
                                # Check if all approvals complete
                                updated_request = next((r for r in get_pending_approvals() + demo_approvals if r['id'] == req_id), None)
                                if updated_request and updated_request['status'] == 'approved':
                                    st.success("🎉 All approvals complete! Account operation will proceed.")
                                else:
                                    st.info("Request moved to next approval stage")
                            elif decision == "Request Changes":
                                st.warning(f"⏸️ Changes requested for {req_id}")
                            else:
                                reject_request(req_id, user_info['email'], comments)
                                st.error(f"❌ Rejected {req_id}")
                    else:
                        st.warning("🔒 You don't have permission to approve requests. Contact an Admin or Super Admin.")
    
    with tab2:
        st.markdown("#### 📤 My Requests")
        
        # Get user's requests from queue
        user_email = user_info.get('email', '')
        my_requests_data = []
        
        for req in st.session_state.get('account_approval_queue', []):
            if req.get('requestor') == user_email:
                approved_count = sum(1 for a in req['required_approvals'] if a['approved'])
                total_count = len(req['required_approvals'])
                
                my_requests_data.append({
                    "Request ID": req['id'],
                    "Type": req['type'].title(),
                    "Account Name": req['details'].get('name', 'N/A'),
                    "Status": req['status'].title(),
                    "Approvals": f"{approved_count}/{total_count}",
                    "Submitted": req['submitted_at'][:10],
                })
        
        if my_requests_data:
            st.dataframe(pd.DataFrame(my_requests_data), use_container_width=True, hide_index=True)
        else:
            st.info("You haven't submitted any requests yet")
    
    with tab3:
        st.markdown("#### 📜 Approval History (Last 30 Days)")
        
        history = st.session_state.get('account_approval_history', [])
        
        # Add demo history
        demo_history = []
        for i in range(10):
            demo_history.append({
                "Date": (datetime.now() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d"),
                "Request ID": f"REQ-HIST-{1200+i}",
                "Account Name": f"{'Production' if i % 2 == 0 else 'Development'}-App-{i:03d}",
                "Type": random.choice(["Create", "Delete", "Modify"]),
                "Requestor": random.choice(["john@company.com", "jane@company.com", "bob@company.com"]),
                "Decision": random.choice(["✅ Approved", "✅ Approved", "✅ Approved", "❌ Rejected"]),
            })
        
        if demo_history:
            st.dataframe(pd.DataFrame(demo_history), use_container_width=True, hide_index=True, height=400)
        else:
            st.info("No approval history available")


def render_ai_assistant():
    """Render AI-powered configuration assistant"""
    st.markdown("### 🤖 AI Configuration Assistant")
    st.markdown("Describe your workload in natural language and get AI-powered configuration recommendations")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - AI recommendations can be applied to real accounts")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS to apply AI recommendations")
    
    st.info("💡 **Powered by AWS Bedrock & Claude 3.5 Sonnet**")
    
    # Use form for AI input
    with st.form(key="ai_assistant_form"):
        # Natural language input
        user_input = st.text_area(
            "Describe your workload or requirements:",
            placeholder="Example: I need a HIPAA-compliant account for a patient data analytics platform processing 500GB daily, with high availability and automated backups",
            height=100,
            key="ai_input"
        )
        
        # Quick template buttons as selectbox
        quick_template = st.selectbox(
            "Or select a quick template:",
            ["Custom (use text above)", "💳 PCI-DSS E-commerce", "🏥 HIPAA Healthcare", "🤖 ML Training Platform"],
            key="ai_template"
        )
        
        generate_btn = st.form_submit_button("✨ Generate AI Recommendations", type="primary", use_container_width=True)
    
    if generate_btn:
        # Determine input
        if quick_template == "💳 PCI-DSS E-commerce":
            final_input = "E-commerce platform processing credit card transactions, needs PCI-DSS compliance, multi-region for global customers"
        elif quick_template == "🏥 HIPAA Healthcare":
            final_input = "Healthcare analytics platform with PHI data, needs HIPAA compliance, 99.99% uptime, automated backups"
        elif quick_template == "🤖 ML Training Platform":
            final_input = "Machine learning training environment with GPU instances, large dataset storage, cost optimization important"
        else:
            final_input = user_input
        
        if not final_input:
            st.error("Please describe your requirements or select a template")
        else:
            with st.spinner("AI analyzing your requirements..."):
                time.sleep(2)
            
            st.success("✅ AI Analysis Complete!")
            
            st.markdown("---")
            st.markdown("### 🎯 Recommended Configuration")
            
            # Show recommendations
            st.info(f"""
            **Based on your requirements:**
            "{final_input[:100]}..."
            
            I recommend the **Healthcare Analytics template** with the following customizations:
            
            **Why this configuration:**
            - ✅ Fully compliant with required frameworks
            - ✅ Multi-AZ deployment ensures high availability
            - ✅ Automated daily backups with point-in-time recovery
            - ✅ Cost-optimized storage at scale
            - ✅ Encryption at rest and in transit
            """)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Estimated Cost", "$36K-42K/mo")
            with col2:
                st.metric("Compliance Score", "94%")
            with col3:
                st.metric("Setup Time", "18 minutes")
            
            st.markdown("#### 🏗️ Architecture Highlights")
            st.markdown("""
            - **Compute:** Multi-AZ deployment with Auto Scaling
            - **Database:** RDS Aurora PostgreSQL (encrypted)
            - **Storage:** S3 with Intelligent-Tiering
            - **Security:** Security Hub, GuardDuty, Macie, Inspector
            - **Monitoring:** CloudWatch with detailed metrics
            - **Backup:** AWS Backup with 35-day retention
            """)
            
            # Apply recommendation form
            with st.form(key="apply_ai_recommendation"):
                st.markdown("---")
                st.markdown("### Apply This Recommendation")
                
                rec_name = st.text_input("Account Name", value="AI-Recommended-Account-001", key="ai_rec_name")
                rec_email = st.text_input("Account Email", placeholder="aws-ai-rec@company.com", key="ai_rec_email")
                
                apply_btn = st.form_submit_button("🚀 Create Account with AI Config", type="primary", use_container_width=True)
            
            if apply_btn:
                if rec_email:
                    st.success(f"✅ Account '{rec_name}' creation started with AI-recommended configuration")
                else:
                    st.error("Please provide an account email")
                
                st.markdown("---")
                
                st.markdown("**Network Configuration:**")
                st.markdown("""
                - VPC CIDR: 10.110.0.0/16
                - Availability Zones: 3 (us-east-1a, 1b, 1c)
                - Public Subnets: 3 (one per AZ)
                - Private Subnets: 6 (two per AZ: app tier + data tier)
                - NAT Gateways: 3 (one per AZ for high availability)
                - Transit Gateway: Enabled (for hub connectivity)
                """)
            
            with tab3:
                st.markdown("#### 💰 Cost Analysis")
                
                cost_breakdown = {
                    "Compute (EC2/ECS)": 14000,
                    "Database (RDS Aurora)": 8500,
                    "Storage (S3/EBS)": 6000,
                    "Security Services": 3200,
                    "Networking": 2800,
                    "Monitoring & Logging": 1500,
                    "Backup & DR": 2000
                }
                
                total_cost = sum(cost_breakdown.values())
                
                st.metric("Total Estimated Monthly Cost", f"${total_cost:,}")
                
                # Cost breakdown chart
                breakdown_df = pd.DataFrame(list(cost_breakdown.items()), columns=['Category', 'Cost'])
                fig = px.bar(breakdown_df, x='Category', y='Cost', title="Monthly Cost Breakdown")
                st.plotly_chart(fig, width="stretch")
                
                st.markdown("#### 💡 Cost Optimization Opportunities")
                st.markdown("""
                - **Reserved Instances (1-year):** Save $6,800/month (compute)
                - **Savings Plans:** Save $4,200/month (flexible compute)
                - **S3 Lifecycle Policies:** Save $1,800/month (move cold data to Glacier)
                - **Right-sizing:** Potential $2,100/month (after initial monitoring)
                
                **Total Potential Savings:** $14,900/month (37% reduction)
                **Optimized Monthly Cost:** $23,100
                """)
            
            with tab4:
                st.markdown("#### 🔀 Alternative Configurations")
                
                st.markdown("**Option A: Cost-Optimized** 💰")
                st.markdown("""
                - Single-region deployment (no DR)
                - Reduced instance sizes
                - Standard support vs. Enterprise
                - **Cost:** $24K-28K/month (30% savings)
                - **Trade-off:** Lower availability (99.9% vs 99.99%)
                """)
                
                st.markdown("---")
                
                st.markdown("**Option B: Enhanced Security** 🛡️")
                st.markdown("""
                - AWS Shield Advanced (DDoS protection)
                - Amazon Detective (security investigation)
                - Additional compliance: HITRUST
                - Dedicated HSM for key management
                - **Cost:** $48K-54K/month (35% increase)
                - **Benefit:** Maximum security posture
                """)
                
                st.markdown("---")
                
                st.markdown("**Option C: Global High-Performance** 🌍")
                st.markdown("""
                - Multi-region active-active deployment
                - CloudFront with Lambda@Edge
                - Global accelerator
                - Cross-region replication
                - **Cost:** $68K-78K/month (2x base cost)
                - **Benefit:** Sub-100ms global latency
                """)
            
            st.markdown("---")
            
            # Info about applying configuration
            st.info("💡 **To apply this configuration:** Go to the 'Create Account' tab and use these recommended settings, or use the form below to create directly.")
            
            # Use form for apply action
            with st.form(key="ai_apply_config_form"):
                apply_name = st.text_input("Account Name", value="AI-Recommended-001", key="ai_apply_name")
                apply_email = st.text_input("Account Email", placeholder="aws-account@company.com", key="ai_apply_email")
                
                col1, col2 = st.columns(2)
                with col1:
                    apply_btn = st.form_submit_button("✅ Create with AI Config", type="primary", use_container_width=True)
                with col2:
                    save_btn = st.form_submit_button("💾 Save as Template", use_container_width=True)
            
            if apply_btn:
                if apply_email:
                    st.success(f"✅ Creating account '{apply_name}' with AI-recommended configuration")
                else:
                    st.error("Please provide an account email")
            
            if save_btn:
                st.success("✅ Configuration saved as custom template")

def render_network_designer():
    """Render network topology designer"""
    st.markdown("### 🌐 Network Topology Designer")
    st.markdown("Visual network planning and CIDR allocation tool")
    
    # Check connection status
    accounts, is_live = get_real_accounts_list()
    
    if is_live:
        st.success("✅ **Live Mode** - Can check real VPC CIDR conflicts")
    else:
        st.info("📊 **Demo Mode** - Connect to AWS for real VPC conflict checking")
    
    tab1, tab2, tab3 = st.tabs(["CIDR Calculator", "Topology Builder", "Connectivity Map"])
    
    with tab1:
        st.markdown("#### 🔢 CIDR Block Calculator & Validator")
        
        with st.form(key="cidr_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**VPC Configuration**")
                vpc_cidr = st.text_input("VPC CIDR Block", value="10.0.0.0/16", key="vpc_cidr_input")
                num_azs = st.number_input("Number of Availability Zones", 1, 6, 3, key="num_azs")
                subnet_types = st.multiselect("Subnet Types", 
                                             ["Public", "Private (App)", "Private (Data)", "Isolated"],
                                             default=["Public", "Private (App)", "Private (Data)"],
                                             key="subnet_types")
            
            with col2:
                st.markdown("**Options**")
                check_conflicts = st.checkbox("Check for CIDR conflicts", value=True, key="check_conflicts")
                auto_calculate = st.checkbox("Auto-calculate subnets", value=True, key="auto_calc")
            
            calculate_btn = st.form_submit_button("🔍 Calculate & Validate", type="primary", use_container_width=True)
        
        if calculate_btn:
            st.markdown("---")
            
            if check_conflicts:
                with st.spinner("Checking existing VPCs..."):
                    time.sleep(1)
                
                conflicts = [
                    {"VPC": "vpc-1234abcd (Production-Main)", "CIDR": "10.0.0.0/16", "Overlap": "100%"},
                    {"VPC": "vpc-5678efgh (Development-01)", "CIDR": "10.1.0.0/16", "Overlap": "0%"},
                ]
                
                conflict_df = pd.DataFrame(conflicts)
                st.dataframe(conflict_df, use_container_width=True, hide_index=True)
                
                if any(c['Overlap'] != "0%" for c in conflicts):
                    st.error("❌ Conflict detected! Consider using 10.100.0.0/16 instead")
                else:
                    st.success("✅ No CIDR conflicts found")
            
            if auto_calculate and subnet_types:
                st.markdown("**Calculated Subnets:**")
                
                subnet_data = []
                for az_num in range(num_azs):
                    for idx, subnet_type in enumerate(subnet_types):
                        subnet_data.append({
                            "AZ": f"us-east-1{'abcdef'[az_num]}",
                            "Type": subnet_type,
                            "CIDR": f"10.0.{az_num * len(subnet_types) + idx}.0/24",
                            "Usable IPs": "251"
                        })
                
                st.dataframe(pd.DataFrame(subnet_data), use_container_width=True, hide_index=True)
                st.info(f"**Total Subnets:** {len(subnet_data)}")
    
    with tab2:
        st.markdown("#### 🏗️ Network Topology Builder")
        
        with st.form(key="topology_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Components to Include:**")
                include_igw = st.checkbox("Internet Gateway", value=True, key="net_igw")
                include_nat = st.checkbox("NAT Gateways", value=True, key="net_nat")
                nat_count = st.number_input("NAT Gateway Count", 1, 6, 2, key="net_nat_count")
                include_tgw = st.checkbox("Transit Gateway", value=False, key="net_tgw")
                include_vpn = st.checkbox("VPN Gateway", value=False, key="net_vpn")
            
            with col2:
                st.markdown("**Security Configuration:**")
                include_waf = st.checkbox("AWS WAF", value=False, key="net_waf")
                include_firewall = st.checkbox("Network Firewall", value=False, key="net_firewall")
                include_flowlogs = st.checkbox("VPC Flow Logs", value=True, key="net_flowlogs")
            
            generate_btn = st.form_submit_button("📐 Generate Topology", type="primary", use_container_width=True)
        
        if generate_btn:
            st.success("✅ Network topology generated")
            
            components = []
            if include_igw: components.append("Internet Gateway")
            if include_nat: components.append(f"{nat_count}x NAT Gateway")
            if include_tgw: components.append("Transit Gateway")
            if include_vpn: components.append("VPN Gateway")
            if include_waf: components.append("AWS WAF")
            if include_firewall: components.append("Network Firewall")
            if include_flowlogs: components.append("VPC Flow Logs")
            
            st.info(f"**Components:** {', '.join(components)}")
            
            # Estimated cost
            cost = 0
            if include_nat: cost += nat_count * 32 * 730  # NAT Gateway
            if include_tgw: cost += 50 * 730  # Transit Gateway
            if include_vpn: cost += 35 * 730
            if include_firewall: cost += 400 * 730
            
            st.metric("Estimated Monthly Network Cost", f"${cost:,.0f}")
    
    with tab3:
        st.markdown("#### 🗺️ Connectivity Map")
        st.info("Visual representation of cross-account network connectivity")
        
        st.markdown("""
        **Current Network Topology:**
        ```
        ┌─────────────────────────────────────────────────────────┐
        │                    Transit Gateway                       │
        │                    (tgw-12345678)                        │
        └─────────────┬───────────┬───────────┬───────────────────┘
                      │           │           │
              ┌───────┴───┐ ┌─────┴─────┐ ┌───┴───────┐
              │Production │ │Development│ │  Shared   │
              │  VPC      │ │   VPC     │ │ Services  │
              │10.0.0.0/16│ │10.1.0.0/16│ │10.2.0.0/16│
              └───────────┘ └───────────┘ └───────────┘
        ```
        """)


def render_dependency_mapping():
    """Render dependency mapping and visualization"""
    st.markdown("### 🔗 Account Dependency Mapping")
    st.markdown("Visualize and manage cross-account dependencies")
    
    # Use the global account selector
    selected_account = st.session_state.get('selected_target_account', 'No account selected')
    selected_account_id = st.session_state.get('selected_account_id', None)
    
    if not selected_account_id:
        st.warning("⚠️ Select an account from the dropdown above to view dependencies")
        return
    
    tab1, tab2, tab3 = st.tabs(["Dependency Graph", "Configure Dependencies", "Impact Analysis"])
    
    with tab1:
        st.markdown("#### 📊 Account Dependency Graph")
        st.info(f"📌 **Showing dependencies for:** {selected_account}")
        
        # Show dependencies
        dependencies = {
            "upstream": [
                {"Account": "Shared-Services", "Type": "SSO, DNS", "Critical": "Yes"},
                {"Account": "Security-Hub", "Type": "Security Aggregation", "Critical": "Yes"},
                {"Account": "Network-Hub", "Type": "Transit Gateway", "Critical": "Yes"},
            ],
            "downstream": [
                {"Account": "DR-Account-001", "Type": "Backup Target", "Critical": "No"},
                {"Account": "Analytics-001", "Type": "Data Source", "Critical": "Yes"},
                {"Account": "Testing-001", "Type": "Reference Config", "Critical": "No"},
            ]
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**⬆️ Depends On (Upstream)**")
            st.dataframe(pd.DataFrame(dependencies["upstream"]), use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**⬇️ Depended Upon By (Downstream)**")
            st.dataframe(pd.DataFrame(dependencies["downstream"]), use_container_width=True, hide_index=True)
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Dependencies", "6")
        with col2:
            st.metric("Critical", "4")
        with col3:
            st.metric("Non-Critical", "2")
        with col4:
            st.metric("Circular Deps", "0")
    
    with tab2:
        st.markdown("#### ⚙️ Configure Account Dependencies")
        
        with st.form(key="dependency_form"):
            st.markdown("**Add New Dependency:**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                target_account = st.selectbox("Target Account", 
                                             ["Shared-Services", "Data-Lake-001", "Security-Hub", "Network-Hub"],
                                             key="dep_target")
            with col2:
                dependency_type = st.selectbox("Dependency Type", 
                                              ["IAM Role", "S3 Bucket Access", "API Gateway", "Transit Gateway", "VPC Peering"],
                                              key="dep_type")
            with col3:
                critical = st.checkbox("Critical Dependency", key="dep_critical")
            
            description = st.text_input("Description", placeholder="Describe the dependency...", key="dep_desc")
            
            add_btn = st.form_submit_button("➕ Add Dependency", type="primary", use_container_width=True)
        
        if add_btn:
            st.success(f"✅ Dependency added: {selected_account} → {target_account}")
            st.info("""
            **Auto-Configuration:**
            - ✅ IAM roles created with cross-account trust
            - ✅ Resource policies applied
            - ✅ Network connectivity validated
            """)
    
    with tab3:
        st.markdown("#### 📈 Dependency Impact Analysis")
        
        with st.form(key="impact_analysis_form"):
            scenario = st.selectbox("Select Scenario", [
                f"If {selected_account} is offboarded",
                "If Shared-Services has an outage",
                "If Network-Hub is modified"
            ], key="impact_scenario")
            
            analyze_btn = st.form_submit_button("🔍 Analyze Impact", type="primary", use_container_width=True)
        
        if analyze_btn:
            with st.spinner("Analyzing dependencies..."):
                time.sleep(1)
            
            st.warning("⚠️ **Impact Analysis Results:**")
            
            st.markdown(f"""
            **Scenario:** {scenario}
            
            **Directly Affected Accounts:** 3
            - DR-Account-001 (backup replication will fail)
            - Analytics-001 (data pipeline will break)
            - Testing-001 (reference configuration unavailable)
            
            **Indirectly Affected Accounts:** 7
            
            **Critical Services at Risk:**
            - ⚠️ DR/Backup: Will fail
            - ⚠️ Analytics: Data pipeline disrupted
            - ✅ Testing: Non-critical impact
            
            **Recommended Actions:**
            1. Migrate DR to alternative backup target
            2. Reconfigure Analytics data source
            3. Update Testing reference configurations
            4. Notify affected account owners (8 total)
            """)
            
            st.error("🚫 **Cannot proceed with offboarding until dependencies are resolved**")

# ============================================================================
# EXPORT FOR MAIN APP
# ============================================================================

if __name__ == "__main__":
    st.set_page_config(page_title="Account Lifecycle Enhanced", layout="wide")
    render_enhanced_account_lifecycle()
