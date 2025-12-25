"""
Multi-Account AWS Connector
Cloud Compliance Canvas - Enterprise Multi-Account Management

Supports:
1. AWS Organizations - List and connect to all member accounts
2. Cross-Account IAM Roles - AssumeRole into target accounts
3. Multiple Credential Profiles - Stored in secrets.toml

Usage:
    from multi_account_connector import (
        get_organization_accounts,
        assume_role_to_account,
        get_multi_account_clients,
        aggregate_multi_account_data
    )
"""

import streamlit as st
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json


# ============================================================================
# CONFIGURATION
# ============================================================================

# Default cross-account role name (should exist in all member accounts)
DEFAULT_CROSS_ACCOUNT_ROLE = "OrganizationAccountAccessRole"

# Alternative role names to try
CROSS_ACCOUNT_ROLE_NAMES = [
    "OrganizationAccountAccessRole",  # AWS Organizations default
    "AWSControlTowerExecution",        # Control Tower
    "CloudComplianceCanvasRole",       # Custom role for this app
    "CrossAccountReadOnly",            # Read-only access
]


# ============================================================================
# ORGANIZATION ACCOUNT DISCOVERY
# ============================================================================

def get_organization_accounts(session: boto3.Session = None) -> Tuple[List[Dict], str]:
    """
    Get all accounts from AWS Organizations.
    
    Returns:
        Tuple of (accounts_list, error_message)
        accounts_list: List of account dicts with id, name, email, status
        error_message: None if successful, error string if failed
    """
    accounts = []
    error = None
    
    try:
        if session is None:
            # Use default session from credentials
            org_client = boto3.client('organizations')
        else:
            org_client = session.client('organizations')
        
        # Get organization info first
        try:
            org_info = org_client.describe_organization()
            org_id = org_info['Organization']['Id']
            master_account = org_info['Organization']['MasterAccountId']
        except ClientError as e:
            if 'AWSOrganizationsNotInUseException' in str(e):
                return [], "AWS Organizations is not enabled for this account"
            raise
        
        # List all accounts
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                accounts.append({
                    'id': account['Id'],
                    'name': account.get('Name', f"Account {account['Id']}"),
                    'email': account.get('Email', 'N/A'),
                    'status': account.get('Status', 'UNKNOWN'),
                    'joined': account.get('JoinedTimestamp'),
                    'is_management': account['Id'] == master_account,
                    'arn': account.get('Arn', ''),
                })
        
        # Sort: Management account first, then by name
        accounts.sort(key=lambda x: (not x['is_management'], x['name']))
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            error = "Access denied. Need organizations:ListAccounts permission."
        elif error_code == 'AWSOrganizationsNotInUseException':
            error = "AWS Organizations is not enabled."
        else:
            error = f"AWS Error: {e.response['Error']['Message']}"
    except NoCredentialsError:
        error = "No AWS credentials found."
    except Exception as e:
        error = f"Error: {str(e)}"
    
    return accounts, error


def get_organizational_units(session: boto3.Session = None) -> Tuple[List[Dict], str]:
    """Get all OUs in the organization for hierarchical view."""
    ous = []
    error = None
    
    try:
        if session is None:
            org_client = boto3.client('organizations')
        else:
            org_client = session.client('organizations')
        
        # Get roots
        roots = org_client.list_roots()['Roots']
        
        def get_children_ous(parent_id, level=0):
            """Recursively get all child OUs."""
            children = []
            try:
                paginator = org_client.get_paginator('list_organizational_units_for_parent')
                for page in paginator.paginate(ParentId=parent_id):
                    for ou in page.get('OrganizationalUnits', []):
                        ou_info = {
                            'id': ou['Id'],
                            'name': ou['Name'],
                            'arn': ou['Arn'],
                            'parent_id': parent_id,
                            'level': level,
                        }
                        children.append(ou_info)
                        # Recurse into child OUs
                        children.extend(get_children_ous(ou['Id'], level + 1))
            except ClientError:
                pass
            return children
        
        for root in roots:
            ous.append({
                'id': root['Id'],
                'name': 'Root',
                'arn': root['Arn'],
                'parent_id': None,
                'level': 0,
                'is_root': True
            })
            ous.extend(get_children_ous(root['Id'], 1))
        
    except Exception as e:
        error = str(e)
    
    return ous, error


# ============================================================================
# CROSS-ACCOUNT ROLE ASSUMPTION
# ============================================================================

def assume_role_to_account(
    target_account_id: str,
    role_name: str = None,
    session_name: str = "CloudComplianceCanvas",
    duration_seconds: int = 3600,
    source_session: boto3.Session = None
) -> Tuple[Optional[boto3.Session], str]:
    """
    Assume a role into a target account.
    
    Args:
        target_account_id: AWS account ID to assume into
        role_name: Name of the role to assume (tries defaults if None)
        session_name: Name for the assumed session
        duration_seconds: How long the session should last
        source_session: Source boto3 session (uses default if None)
    
    Returns:
        Tuple of (session, error_message)
        session: boto3.Session for the assumed role, or None if failed
        error_message: None if successful, error string if failed
    """
    
    role_names_to_try = [role_name] if role_name else CROSS_ACCOUNT_ROLE_NAMES
    
    try:
        if source_session:
            sts_client = source_session.client('sts')
        else:
            sts_client = boto3.client('sts')
        
        last_error = None
        
        for role in role_names_to_try:
            role_arn = f"arn:aws:iam::{target_account_id}:role/{role}"
            
            try:
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=duration_seconds
                )
                
                credentials = response['Credentials']
                
                # Create new session with assumed role credentials
                assumed_session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                
                return assumed_session, None
                
            except ClientError as e:
                last_error = e
                continue
        
        # All role attempts failed
        if last_error:
            error_code = last_error.response['Error']['Code']
            if error_code == 'AccessDenied':
                return None, f"Access denied assuming role in {target_account_id}. Ensure cross-account role exists."
            else:
                return None, f"Error: {last_error.response['Error']['Message']}"
        
        return None, "No valid cross-account role found"
        
    except NoCredentialsError:
        return None, "No AWS credentials available"
    except Exception as e:
        return None, f"Error: {str(e)}"


def get_clients_for_account(
    account_id: str,
    region: str = 'us-east-1',
    source_session: boto3.Session = None
) -> Tuple[Optional[Dict], str]:
    """
    Get AWS service clients for a specific account.
    
    Returns:
        Tuple of (clients_dict, error_message)
    """
    
    # If it's the current account, use existing session
    current_account = st.session_state.get('aws_account_id')
    
    if current_account and account_id == current_account:
        # Use existing clients
        return st.session_state.get('aws_clients', {}), None
    
    # Otherwise, assume role into the account
    assumed_session, error = assume_role_to_account(
        target_account_id=account_id,
        source_session=source_session
    )
    
    if error:
        return None, error
    
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
            'ce': assumed_session.client('ce', region_name='us-east-1'),  # Cost Explorer always us-east-1
        }
        return clients, None
    except Exception as e:
        return None, f"Error creating clients: {str(e)}"


# ============================================================================
# MULTI-ACCOUNT DATA AGGREGATION
# ============================================================================

def aggregate_security_hub_findings(accounts: List[Dict], source_session: boto3.Session = None) -> Dict:
    """
    Aggregate Security Hub findings across multiple accounts.
    """
    aggregated = {
        'total_findings': 0,
        'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
        'by_account': {},
        'errors': []
    }
    
    for account in accounts:
        account_id = account['id']
        
        try:
            clients, error = get_clients_for_account(account_id, source_session=source_session)
            
            if error:
                aggregated['errors'].append({'account': account_id, 'error': error})
                continue
            
            # Get findings count
            sec_hub = clients.get('securityhub')
            if sec_hub:
                response = sec_hub.get_findings(
                    Filters={
                        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                    },
                    MaxResults=100
                )
                
                findings = response.get('Findings', [])
                account_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0}
                
                for finding in findings:
                    severity = finding.get('Severity', {}).get('Label', 'LOW')
                    if severity in account_summary:
                        account_summary[severity] += 1
                        aggregated['by_severity'][severity] += 1
                    account_summary['total'] += 1
                    aggregated['total_findings'] += 1
                
                aggregated['by_account'][account_id] = {
                    'name': account['name'],
                    **account_summary
                }
                
        except Exception as e:
            aggregated['errors'].append({'account': account_id, 'error': str(e)})
    
    return aggregated


def aggregate_cost_data(accounts: List[Dict], source_session: boto3.Session = None) -> Dict:
    """
    Aggregate cost data across multiple accounts.
    """
    from datetime import datetime, timedelta
    
    aggregated = {
        'total_mtd': 0,
        'by_account': {},
        'errors': []
    }
    
    # Date range for MTD
    today = datetime.now()
    start_of_month = today.replace(day=1).strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')
    
    for account in accounts:
        account_id = account['id']
        
        try:
            clients, error = get_clients_for_account(account_id, source_session=source_session)
            
            if error:
                aggregated['errors'].append({'account': account_id, 'error': error})
                continue
            
            ce = clients.get('ce')
            if ce:
                response = ce.get_cost_and_usage(
                    TimePeriod={'Start': start_of_month, 'End': end_date},
                    Granularity='MONTHLY',
                    Metrics=['UnblendedCost']
                )
                
                for result in response.get('ResultsByTime', []):
                    cost = float(result['Total']['UnblendedCost']['Amount'])
                    aggregated['total_mtd'] += cost
                    aggregated['by_account'][account_id] = {
                        'name': account['name'],
                        'mtd_cost': cost
                    }
                    
        except Exception as e:
            aggregated['errors'].append({'account': account_id, 'error': str(e)})
    
    return aggregated


# ============================================================================
# STREAMLIT UI COMPONENTS
# ============================================================================

def render_multi_account_selector():
    """
    Render a multi-account selector in Streamlit sidebar.
    """
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🏢 Multi-Account Mode")
    
    # Check if connected
    if not st.session_state.get('aws_connected'):
        st.sidebar.warning("Connect to AWS first")
        return
    
    # Try to get organization accounts
    if 'org_accounts' not in st.session_state:
        with st.sidebar:
            with st.spinner("Loading organization..."):
                accounts, error = get_organization_accounts()
                if error:
                    st.session_state.org_accounts = []
                    st.session_state.org_error = error
                else:
                    st.session_state.org_accounts = accounts
                    st.session_state.org_error = None
    
    accounts = st.session_state.get('org_accounts', [])
    error = st.session_state.get('org_error')
    
    if error:
        st.sidebar.info(f"Single account mode ({error})")
        return
    
    if not accounts:
        st.sidebar.info("No organization accounts found")
        return
    
    # Show account selector
    st.sidebar.success(f"✅ {len(accounts)} accounts in organization")
    
    # Multi-select accounts
    selected = st.sidebar.multiselect(
        "Select accounts to analyze",
        options=[f"{a['name']} ({a['id']})" for a in accounts],
        default=[f"{accounts[0]['name']} ({accounts[0]['id']})"] if accounts else []
    )
    
    # Store selected account IDs
    selected_ids = []
    for sel in selected:
        # Extract account ID from selection string
        account_id = sel.split('(')[-1].rstrip(')')
        selected_ids.append(account_id)
    
    st.session_state.selected_account_ids = selected_ids
    st.session_state.selected_accounts = [a for a in accounts if a['id'] in selected_ids]
    
    if len(selected_ids) > 1:
        st.sidebar.info(f"📊 Aggregating data from {len(selected_ids)} accounts")


def render_account_health_grid(accounts: List[Dict]):
    """
    Render a grid showing health status of multiple accounts.
    """
    import pandas as pd
    
    if not accounts:
        st.info("No accounts selected")
        return
    
    st.markdown("### 🏢 Multi-Account Health Overview")
    
    # Create health data
    health_data = []
    
    for acc in accounts:
        health_data.append({
            "Account": acc['name'],
            "ID": acc['id'],
            "Status": "✅ Active" if acc['status'] == 'ACTIVE' else "⚠️ " + acc['status'],
            "Type": "🏠 Management" if acc.get('is_management') else "📁 Member",
        })
    
    df = pd.DataFrame(health_data)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ============================================================================
# SETUP INSTRUCTIONS
# ============================================================================

SETUP_INSTRUCTIONS = """
## Multi-Account Setup Instructions

### Option 1: AWS Organizations (Recommended)

1. **Enable AWS Organizations** in your management account
2. **Create member accounts** or invite existing accounts
3. **Ensure cross-account role exists** in all member accounts:
   - Default role: `OrganizationAccountAccessRole` (created automatically)
   - Or create custom role: `CloudComplianceCanvasRole`

4. **Required permissions** in management account:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "organizations:ListAccounts",
           "organizations:DescribeOrganization",
           "organizations:ListOrganizationalUnitsForParent",
           "organizations:ListRoots"
         ],
         "Resource": "*"
       },
       {
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
       }
     ]
   }
   ```

### Option 2: Manual Cross-Account Roles

1. **In each target account**, create IAM role:
   - Name: `CloudComplianceCanvasRole`
   - Trust policy: Allow your source account to assume this role
   
2. **Trust Policy** (in target accounts):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:root"
         },
         "Action": "sts:AssumeRole"
       }
     ]
   }
   ```

3. **Attach policies** for required services (SecurityHub, Config, etc.)

### Option 3: Multiple Profiles in secrets.toml

```toml
[aws]
access_key = "your-default-key"
secret_key = "your-default-secret"
region = "us-east-1"

[aws_accounts.production]
account_id = "111111111111"
role_name = "CrossAccountRole"

[aws_accounts.development]  
account_id = "222222222222"
role_name = "CrossAccountRole"
```
"""


def show_setup_instructions():
    """Show multi-account setup instructions."""
    st.markdown(SETUP_INSTRUCTIONS)
