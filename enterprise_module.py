"""
Enterprise Features Module for Future Minds Platform v5.0
Clean, working version with proper navigation
"""

import streamlit as st
import pandas as pd
import random
import time
import uuid
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os

# ============================================================================
# HELPER: GET BOTO3 SESSION WITH CREDENTIALS FROM SECRETS
# ============================================================================

def get_boto3_session():
    """
    Get a boto3 session using credentials from Streamlit secrets or session state.
    This ensures all AWS API calls use the correct credentials.
    """
    import boto3
    
    # First, try to get from session state (already validated)
    if 'boto3_session' in st.session_state and st.session_state.boto3_session:
        return st.session_state.boto3_session
    
    # Second, try to create from Streamlit secrets
    try:
        if 'aws' in st.secrets:
            aws_secrets = st.secrets['aws']
            # Support both naming conventions
            access_key = aws_secrets.get('access_key_id') or aws_secrets.get('management_access_key_id')
            secret_key = aws_secrets.get('secret_access_key') or aws_secrets.get('management_secret_access_key')
            region = aws_secrets.get('region') or aws_secrets.get('default_region', 'us-east-1')
            session_token = aws_secrets.get('session_token') or aws_secrets.get('aws_session_token')
            
            if access_key and secret_key:
                # Strip whitespace from credentials
                access_key = access_key.strip()
                secret_key = secret_key.strip()
                region = region.strip()
                
                session_kwargs = {
                    'aws_access_key_id': access_key,
                    'aws_secret_access_key': secret_key,
                    'region_name': region
                }
                
                # Add session token if present (for temporary credentials)
                if session_token:
                    session_kwargs['aws_session_token'] = session_token.strip()
                
                session = boto3.Session(**session_kwargs)
                return session
    except Exception as e:
        print(f"Could not create boto3 session from secrets: {e}")
    
    # Third, try environment variables
    env_kwargs = {}
    if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
        env_kwargs['aws_access_key_id'] = os.environ['AWS_ACCESS_KEY_ID']
        env_kwargs['aws_secret_access_key'] = os.environ['AWS_SECRET_ACCESS_KEY']
        env_kwargs['region_name'] = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        if os.environ.get('AWS_SESSION_TOKEN'):
            env_kwargs['aws_session_token'] = os.environ['AWS_SESSION_TOKEN']
        return boto3.Session(**env_kwargs)
    
    # Last resort: default boto3 session (may not have credentials)
    return boto3.Session()


def get_aws_client(service_name: str, region_name: str = None):
    """
    Get an AWS client for a specific service using credentials from secrets.
    
    Args:
        service_name: AWS service name (e.g., 'organizations', 'securityhub')
        region_name: Optional region override
    
    Returns:
        boto3 client for the specified service
    """
    # First check if client exists in session state
    if 'aws_clients' in st.session_state and st.session_state.aws_clients:
        client = st.session_state.aws_clients.get(service_name)
        if client:
            return client
    
    # Create new client using session with credentials
    session = get_boto3_session()
    if region_name:
        return session.client(service_name, region_name=region_name)
    return session.client(service_name)


# ============================================================================
# ENTERPRISE AUTHENTICATION & RBAC
# ============================================================================

class EnterpriseAuth:
    """Enterprise Authentication & Authorization System"""
    
    ROLES = {
        'global_admin': {
            'name': 'Global Administrator',
            'permissions': ['*:*:*'],
        },
        'cfo': {
            'name': 'CFO / FinOps Admin',
            'permissions': ['accounts:read:tenant', 'finops:*:tenant', 'reports:*:tenant', 'dashboard:cfo:tenant'],
        },
        'ciso': {
            'name': 'CISO / Security Admin',
            'permissions': ['accounts:read:tenant', 'security:*:tenant', 'compliance:*:tenant', 'reports:*:tenant', 'dashboard:ciso:tenant'],
        },
        'cto': {
            'name': 'CTO / Technology Lead',
            'permissions': ['accounts:*:tenant', 'controltower:*:tenant', 'reports:read:tenant', 'dashboard:cto:tenant'],
        },
    }
    
    DEMO_USERS = {
        'admin@example.com': {
            'id': 'user-001',
            'name': 'Global Administrator',
            'email': 'admin@example.com',
            'tenant_id': 'tenant-001',
            'tenant_name': 'Enterprise Corp',
            'role': 'global_admin',
            'permissions': ROLES['global_admin']['permissions']
        },
        'cfo@example.com': {
            'id': 'user-002',
            'name': 'Chief Financial Officer',
            'email': 'cfo@example.com',
            'tenant_id': 'tenant-001',
            'tenant_name': 'Enterprise Corp',
            'role': 'cfo',
            'permissions': ROLES['cfo']['permissions']
        },
        'ciso@example.com': {
            'id': 'user-003',
            'name': 'Chief Information Security Officer',
            'email': 'ciso@example.com',
            'tenant_id': 'tenant-001',
            'tenant_name': 'Enterprise Corp',
            'role': 'ciso',
            'permissions': ROLES['ciso']['permissions']
        },
        'cto@example.com': {
            'id': 'user-004',
            'name': 'Chief Technology Officer',
            'email': 'cto@example.com',
            'tenant_id': 'tenant-001',
            'tenant_name': 'Enterprise Corp',
            'role': 'cto',
            'permissions': ROLES['cto']['permissions']
        },
    }
    
    @staticmethod
    def authenticate(email, password):
        """Authenticate user (mock for demo)"""
        if email in EnterpriseAuth.DEMO_USERS and password == 'demo123':
            return EnterpriseAuth.DEMO_USERS[email]
        return None
    
    @staticmethod
    def check_permission(user, permission):
        """Check if user has required permission"""
        if not user:
            return False
        user_perms = user.get('permissions', [])
        if '*:*:*' in user_perms:
            return True
        resource, action, scope = permission.split(':')
        for perm in user_perms:
            p_resource, p_action, p_scope = perm.split(':')
            if ((p_resource == '*' or p_resource == resource) and 
                (p_action == '*' or p_action == action) and 
                (p_scope == '*' or p_scope == scope)):
                return True
        return False

class ControlTowerManager:
    """AWS Control Tower Integration with Demo/Live Mode Support"""
    
    def __init__(self, org_client=None):
        """Initialize Control Tower Manager
        
        Args:
            org_client: Optional boto3 organizations client. If not provided,
                       will try to get from session state or create new one.
        """
        self.demo_mode = None  # Will be checked at runtime
        self._org_client = org_client
        
    def _is_demo_mode(self):
        """Check if app is in demo mode"""
        return st.session_state.get('demo_mode', False)
    
    def _get_org_client(self):
        """Get Organizations client from various sources"""
        # First, use the client passed to constructor
        if self._org_client:
            return self._org_client
        
        # Second, try to get from session state (aws_clients)
        aws_clients = st.session_state.get('aws_clients')
        if aws_clients and aws_clients.get('organizations'):
            return aws_clients.get('organizations')
        
        # Third, use the helper function that handles credentials properly
        try:
            return get_aws_client('organizations')
        except Exception as e:
            print(f"Could not create organizations client: {e}")
            return None
    
    def get_landing_zone_status(self):
        """Get Control Tower landing zone status with demo/live support"""
        
        if self._is_demo_mode():
            # DEMO MODE - Return sample data
            return {
                'status': 'ACTIVE',
                'version': '3.3',
                'drift_status': 'IN_SYNC',
                'accounts_managed': 127,
                'guardrails_enabled': 45
            }
        else:
            # LIVE MODE - Connect to real AWS
            try:
                from botocore.exceptions import ClientError
                
                # Get AWS Organizations client from session state
                org_client = self._get_org_client()
                
                if not org_client:
                    st.error("⚠️ AWS Organizations client not available. Please check your AWS credentials.")
                    return {
                        'status': 'ERROR',
                        'version': 'N/A',
                        'drift_status': 'ERROR',
                        'accounts_managed': 0,
                        'guardrails_enabled': 0
                    }
                
                try:
                    # Get actual account count
                    accounts_response = org_client.list_accounts()
                    account_count = len(accounts_response.get('Accounts', []))
                    
                    # Try to get Control Tower status (if available)
                    # Note: Control Tower doesn't have direct API, using Organizations
                    try:
                        # Check if Control Tower is setup by looking for the CT OUs
                        roots = org_client.list_roots()
                        root_id = roots['Roots'][0]['Id'] if roots.get('Roots') else None
                        
                        # Count guardrails as number of SCPs
                        guardrails_count = 0
                        if root_id:
                            policies = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
                            guardrails_count = len(policies.get('Policies', []))
                        
                        return {
                            'status': 'ACTIVE',
                            'version': '3.3',  # Can't get actual version via API
                            'drift_status': 'IN_SYNC',
                            'accounts_managed': account_count,
                            'guardrails_enabled': guardrails_count
                        }
                    except Exception as e:
                        # If Control Tower specific checks fail, return basic org info
                        return {
                            'status': 'ACTIVE',
                            'version': 'N/A',
                            'drift_status': 'UNKNOWN',
                            'accounts_managed': account_count,
                            'guardrails_enabled': 0
                        }
                        
                except ClientError as e:
                    st.error(f"⚠️ AWS Organizations Error: {str(e)}")
                    return {
                        'status': 'ERROR',
                        'version': 'N/A',
                        'drift_status': 'ERROR',
                        'accounts_managed': 0,
                        'guardrails_enabled': 0
                    }
                    
            except ImportError:
                st.error("⚠️ boto3 not installed. Cannot connect to AWS.")
                return {
                    'status': 'ERROR',
                    'version': 'N/A',
                    'drift_status': 'ERROR',
                    'accounts_managed': 0,
                    'guardrails_enabled': 0
                }
            except Exception as e:
                st.error(f"⚠️ Error connecting to AWS: {str(e)}")
                return {
                    'status': 'ERROR',
                    'version': 'N/A',
                    'drift_status': 'ERROR',
                    'accounts_managed': 0,
                    'guardrails_enabled': 0
                }
    
    def get_organizational_units(self):
        """Get organizational units with demo/live support"""
        
        if self._is_demo_mode():
            # DEMO MODE - Return sample OUs
            return [
                {'id': 'ou-prod-001', 'name': 'Production', 'accounts': 45, 'compliance': 98.5},
                {'id': 'ou-dev-001', 'name': 'Development', 'accounts': 32, 'compliance': 95.2},
                {'id': 'ou-stg-001', 'name': 'Staging', 'accounts': 20, 'compliance': 96.8},
                {'id': 'ou-sbx-001', 'name': 'Sandbox', 'accounts': 15, 'compliance': 88.3},
            ]
        else:
            # LIVE MODE - Get real OUs from AWS Organizations
            try:
                from botocore.exceptions import ClientError
                
                org_client = self._get_org_client()
                
                if not org_client:
                    st.error("⚠️ AWS Organizations client not available. Please check your AWS credentials.")
                    return [{'id': 'error', 'name': 'No AWS connection', 'accounts': 0, 'compliance': 0}]
                
                try:
                    # Get root
                    roots = org_client.list_roots()
                    if not roots.get('Roots'):
                        return []
                    
                    root_id = roots['Roots'][0]['Id']
                    
                    # List all OUs under root
                    ous_data = []
                    ous_response = org_client.list_organizational_units_for_parent(ParentId=root_id)
                    
                    for ou in ous_response.get('OrganizationalUnits', []):
                        ou_id = ou['Id']
                        ou_name = ou['Name']
                        
                        # Count accounts in this OU
                        try:
                            accounts = org_client.list_accounts_for_parent(ParentId=ou_id)
                            account_count = len(accounts.get('Accounts', []))
                        except:
                            account_count = 0
                        
                        # Mock compliance for now (would need Security Hub integration)
                        compliance = random.uniform(85.0, 99.0)
                        
                        ous_data.append({
                            'id': ou_id,
                            'name': ou_name,
                            'accounts': account_count,
                            'compliance': round(compliance, 1)
                        })
                    
                    return ous_data if ous_data else [{'id': 'none', 'name': 'No OUs found', 'accounts': 0, 'compliance': 0}]
                    
                except ClientError as e:
                    st.error(f"⚠️ Error fetching OUs: {str(e)}")
                    return [{'id': 'error', 'name': 'Error fetching OUs', 'accounts': 0, 'compliance': 0}]
                    
            except ImportError:
                st.error("⚠️ boto3 not installed")
                return [{'id': 'error', 'name': 'boto3 not available', 'accounts': 0, 'compliance': 0}]
            except Exception as e:
                st.error(f"⚠️ Error: {str(e)}")
                return [{'id': 'error', 'name': str(e), 'accounts': 0, 'compliance': 0}]
    
    def provision_account(self, name, email, ou, sso_user):
        """Provision new account with demo/live support"""
        
        if self._is_demo_mode():
            # DEMO MODE - Simulate account provisioning
            return {
                'status': 'SUCCESS',
                'account_id': f'{random.randint(100000000000, 999999999999)}',
                'provisioning_id': str(uuid.uuid4()),
                'services_enabled': ['SecurityHub', 'GuardDuty', 'Config', 'CloudTrail'],
                'mode': 'DEMO'
            }
        else:
            # LIVE MODE - Actually provision account via AWS Organizations
            try:
                from botocore.exceptions import ClientError
                
                # Use helper function to get client with proper credentials
                org_client = get_aws_client('organizations')
                
                try:
                    # Create actual AWS account
                    response = org_client.create_account(
                        Email=email,
                        AccountName=name
                    )
                    
                    # Get the request ID to track provisioning
                    request_id = response['CreateAccountStatus']['Id']
                    
                    # Note: In production, you'd want to poll for completion
                    # For now, just return the request info
                    return {
                        'status': 'IN_PROGRESS',
                        'account_id': 'Pending...',
                        'provisioning_id': request_id,
                        'services_enabled': ['Will be configured after provisioning'],
                        'mode': 'LIVE',
                        'message': 'Account creation initiated. Check AWS Console for status.'
                    }
                    
                except ClientError as e:
                    st.error(f"⚠️ Error creating account: {str(e)}")
                    return {
                        'status': 'ERROR',
                        'account_id': 'N/A',
                        'provisioning_id': 'N/A',
                        'services_enabled': [],
                        'mode': 'LIVE',
                        'error': str(e)
                    }
                    
            except ImportError:
                st.error("⚠️ boto3 not installed. Cannot provision accounts.")
                return {
                    'status': 'ERROR',
                    'account_id': 'N/A',
                    'provisioning_id': 'N/A',
                    'services_enabled': [],
                    'mode': 'LIVE',
                    'error': 'boto3 not available'
                }
            except Exception as e:
                st.error(f"⚠️ Error: {str(e)}")
                return {
                    'status': 'ERROR',
                    'account_id': 'N/A',
                    'provisioning_id': 'N/A',
                    'services_enabled': [],
                    'mode': 'LIVE',
                    'error': str(e)
                }

class RealTimeCostMonitor:
    """Real-time cost monitoring with Demo/Live mode support"""
    
    def get_current_hourly_cost(self):
        """Get current hourly cost - respects demo/live mode"""
        is_demo = st.session_state.get('demo_mode', False)
        
        if is_demo:
            # DEMO MODE - Sample data
            return {
                'total': 118.64,
                'by_service': {
                    'EC2': 45.30,
                    'RDS': 25.80,
                    'S3': 12.45,
                    'Lambda': 8.20,
                    'Other': 26.89
                },
                'burn_rate': {
                    'hourly': 118.64,
                    'daily': 2847.36,
                    'monthly_projection': 85421.00
                }
            }
        else:
            # LIVE MODE - Return zeros or fetch from AWS
            # TODO: Integrate with AWS Cost Explorer for real-time data
            return {
                'total': 0,
                'by_service': {
                    'EC2': 0,
                    'RDS': 0,
                    'S3': 0,
                    'Lambda': 0,
                    'Other': 0
                },
                'burn_rate': {
                    'hourly': 0,
                    'daily': 0,
                    'monthly_projection': 0
                }
            }
    
    def detect_anomalies(self):
        """Detect cost anomalies - respects demo/live mode"""
        is_demo = st.session_state.get('demo_mode', False)
        
        if is_demo:
            # DEMO MODE - Sample anomaly
            return [
                {
                    'service': 'EC2',
                    'region': 'us-east-1',
                    'current_cost': 2847.50,
                    'expected_cost': 1800.00,
                    'increase_pct': 58.2,
                    'confidence': 'HIGH',
                    'root_cause': '15 new m5.2xlarge instances launched'
                }
            ]
        else:
            # LIVE MODE - Return empty or fetch from AWS Cost Anomaly Detection
            # TODO: Integrate with AWS Cost Anomaly Detection API
            return []
    
    def get_budget_status(self):
        """Get budget status - respects demo/live mode"""
        is_demo = st.session_state.get('demo_mode', False)
        
        if is_demo:
            # DEMO MODE - Sample budget data
            return {
                'monthly_budget': 100000,
                'current_spend': 85421,
                'utilization_pct': 85.4
            }
        else:
            # LIVE MODE - Return zeros or fetch from AWS Budgets
            # TODO: Integrate with AWS Budgets API
            return {
                'monthly_budget': 0,
                'current_spend': 0,
                'utilization_pct': 0
            }
    
    def get_chargeback_data(self):
        """Get chargeback data - respects demo/live mode"""
        is_demo = st.session_state.get('demo_mode', False)
        
        if is_demo:
            # DEMO MODE - Sample chargeback data
            return [
                {'department': 'Engineering', 'cost': 45000, 'budget': 50000, 'utilization': '90%'},
                {'department': 'Product', 'cost': 23000, 'budget': 25000, 'utilization': '92%'},
                {'department': 'Data Science', 'cost': 18000, 'budget': 20000, 'utilization': '90%'},
            ]
        else:
            # LIVE MODE - Return empty or fetch from AWS Cost Explorer with tags
            # TODO: Integrate with AWS Cost Explorer using cost allocation tags
            return []

# ============================================================================
# ENTERPRISE UI FUNCTIONS
# ============================================================================

def init_enterprise_session():
    """Initialize enterprise session state"""
    if 'enterprise_initialized' not in st.session_state:
        st.session_state.enterprise_initialized = True
        st.session_state.authenticated = False
        st.session_state.user = None
        st.session_state.last_activity = datetime.now()
        # Get organizations client from aws_clients if available
        org_client = None
        if 'aws_clients' in st.session_state and st.session_state.aws_clients:
            org_client = st.session_state.aws_clients.get('organizations')
        st.session_state.ct_manager = ControlTowerManager(org_client=org_client)
        st.session_state.cost_monitor = RealTimeCostMonitor()

def render_enterprise_login():
    """Enterprise login page"""
    st.markdown("""
    <div class='main-header'>
        <h1>🛡️ Future Minds Enterprise Platform v5.0</h1>
        <p>Unified Cloud Governance • Security • Compliance • FinOps</p>
        <div style='background: #FF9900; color: #232F3E; padding: 0.4rem 1.2rem; border-radius: 25px; 
                    font-weight: bold; display: inline-block; margin-top: 1rem;'>ENTERPRISE EDITION</div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("### 🔐 Secure Sign In")
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="user@company.com")
            password = st.text_input("Password", type="password", placeholder="demo123")
            submit = st.form_submit_button("Sign In", width="stretch", type="primary")
            
            if submit:
                user = EnterpriseAuth.authenticate(email, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user = user
                    st.success(f"✅ Welcome, {user['name']}!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials. Try: cfo@example.com / demo123")
        
        st.markdown("---")
        st.markdown("**Demo Accounts** (password: `demo123`):")
        st.markdown("- `admin@example.com` - Global Admin")
        st.markdown("- `cfo@example.com` - CFO/FinOps")
        st.markdown("- `ciso@example.com` - CISO/Security")
        st.markdown("- `cto@example.com` - CTO/Operations")

def render_enterprise_header():
    """Show enterprise user banner"""
    user = st.session_state.user
    col1, col2 = st.columns([5, 1])
    with col1:
        role_name = EnterpriseAuth.ROLES[user['role']]['name']
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                    padding: 1rem; border-radius: 10px; color: white; margin-bottom: 1rem;'>
            <strong>👤 {user['name']}</strong> • <em>{role_name}</em> • 
            <small style='background: #FF9900; padding: 0.2rem 0.6rem; border-radius: 10px; 
                         color: #232F3E; font-weight: bold;'>{user['tenant_name']}</small>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        if st.button("🚪 Logout", width="stretch"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()

def render_enterprise_sidebar():
    """Render enterprise navigation menu"""
    st.markdown("## 🎯 Executive Dashboards")
    
    user = st.session_state.user
    
    # CFO Dashboard
    if EnterpriseAuth.check_permission(user, 'dashboard:cfo:tenant'):
        if st.button("💰 CFO Dashboard", width="stretch", key="nav_cfo"):
            st.session_state.enterprise_page = 'cfo'
            st.rerun()
    
    # Control Tower
    if EnterpriseAuth.check_permission(user, 'controltower:read:tenant'):
        if st.button("🏗️ Control Tower", width="stretch", key="nav_ct"):
            st.session_state.enterprise_page = 'controltower'
            st.rerun()
    
    # Real-Time Costs
    if EnterpriseAuth.check_permission(user, 'finops:read:tenant'):
        if st.button("💸 Real-Time Costs", width="stretch", key="nav_rtc"):
            st.session_state.enterprise_page = 'realtime_costs'
            st.rerun()
    
    # Main Dashboard
    if st.button("🏠 Main Dashboard", width="stretch", key="nav_main"):
        st.session_state.enterprise_page = None
        st.rerun()
    
    st.markdown("---")

def fetch_aws_live_data():
    """
    NEW: Fetch REAL data from AWS services
    
    This function connects to:
    - AWS Cost Explorer (spend, trends, forecast)
    - AWS Security Hub (security findings)
    - AWS Config (compliance metrics)
    - AWS Organizations (account data)
    
    Returns: Complete data dictionary with real AWS data
    """
    try:
        from botocore.exceptions import ClientError, NoCredentialsError
        
        # Initialize AWS clients using helper function with proper credentials
        ce_client = get_aws_client('ce', region_name='us-east-1')
        sh_client = get_aws_client('securityhub')
        config_client = get_aws_client('config')
        org_client = get_aws_client('organizations')
        
        # Date range for queries
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30)
        start_date_str = start_date.strftime('%Y-%m-%d')
        end_date_str = end_date.strftime('%Y-%m-%d')
        
        # ================================================================
        # 1. GET MONTHLY SPEND - Cost Explorer
        # ================================================================
        try:
            cost_response = ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date_str, 'End': end_date_str},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )
            monthly_spend = float(cost_response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
        except Exception as e:
            st.warning(f"⚠️ Cost Explorer: {str(e)}")
            monthly_spend = 0
        
        # ================================================================
        # 2. GET 6-MONTH TREND
        # ================================================================
        try:
            trend_start = (end_date - timedelta(days=180)).strftime('%Y-%m-%d')
            trend_response = ce_client.get_cost_and_usage(
                TimePeriod={'Start': trend_start, 'End': end_date_str},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )
            
            spend_trend = []
            months = []
            for result in trend_response['ResultsByTime'][-6:]:
                spend_trend.append(float(result['Total']['UnblendedCost']['Amount']))
                month_name = datetime.strptime(result['TimePeriod']['Start'], '%Y-%m-%d').strftime('%b')
                months.append(month_name)
            
            # Pad if less than 6 months
            while len(spend_trend) < 6:
                spend_trend.insert(0, 0)
                months.insert(0, 'N/A')
        except Exception as e:
            st.warning(f"⚠️ Trend data: {str(e)}")
            spend_trend = [0] * 6
            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        
        # ================================================================
        # 3. GET FORECAST
        # ================================================================
        try:
            forecast_end = (end_date + timedelta(days=90)).strftime('%Y-%m-%d')
            forecast_response = ce_client.get_cost_forecast(
                TimePeriod={'Start': end_date_str, 'End': forecast_end},
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            forecast_next_month = float(forecast_response['Total']['Amount'])
            forecast_next_quarter = forecast_next_month * 3
        except Exception as e:
            forecast_next_month = monthly_spend * 1.05
            forecast_next_quarter = forecast_next_month * 3
        
        # ================================================================
        # 4. GET COST BY SERVICE
        # ================================================================
        try:
            service_response = ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date_str, 'End': end_date_str},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            cost_by_service = {}
            for group in service_response['ResultsByTime'][0]['Groups'][:10]:
                service = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                if cost > 0:
                    cost_by_service[service] = cost
            
            if not cost_by_service:
                cost_by_service = {'No Data': 0}
        except Exception as e:
            cost_by_service = {'No Data': 0}
        
        # ================================================================
        # 5. GET COST BY REGION
        # ================================================================
        try:
            region_response = ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date_str, 'End': end_date_str},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'REGION'}]
            )
            
            cost_by_region = {}
            for group in region_response['ResultsByTime'][0]['Groups'][:10]:
                region = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                if cost > 0:
                    cost_by_region[region] = cost
            
            if not cost_by_region:
                cost_by_region = {'No Data': 0}
        except Exception as e:
            cost_by_region = {'No Data': 0}
        
        # ================================================================
        # 6. GET SECURITY FINDINGS - Security Hub
        # ================================================================
        try:
            findings_response = sh_client.get_findings(
                Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]},
                MaxResults=100
            )
            
            findings = findings_response.get('Findings', [])
            total_findings = len(findings)
            critical_findings = len([f for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL'])
            
            security_findings = {
                'total_findings': total_findings,
                'critical': critical_findings,
                'cost_at_risk': critical_findings * 5000,
                'remediation_cost': total_findings * 750,
                'cost_per_finding': 750
            }
        except Exception as e:
            st.warning(f"⚠️ Security Hub: {str(e)}")
            security_findings = {
                'total_findings': 0,
                'critical': 0,
                'cost_at_risk': 0,
                'remediation_cost': 0,
                'cost_per_finding': 0
            }
        
        # ================================================================
        # 7. GET COMPLIANCE - Config
        # ================================================================
        try:
            compliance_response = config_client.describe_compliance_by_config_rule()
            
            rules = compliance_response.get('ComplianceByConfigRules', [])
            compliant = len([r for r in rules if r.get('Compliance', {}).get('ComplianceType') == 'COMPLIANT'])
            non_compliant = len([r for r in rules if r.get('Compliance', {}).get('ComplianceType') == 'NON_COMPLIANT'])
            total = len(rules)
            
            compliance_score = (compliant / total * 100) if total > 0 else 0
            
            compliance = {
                'overall_score': round(compliance_score, 1),
                'non_compliant_resources': non_compliant,
                'potential_fines': non_compliant * 100,
                'compliance_cost': 25000
            }
        except Exception as e:
            st.warning(f"⚠️ Config: {str(e)}")
            compliance = {
                'overall_score': 0,
                'non_compliant_resources': 0,
                'potential_fines': 0,
                'compliance_cost': 0
            }
        
        # ================================================================
        # 8. GET ACCOUNT DATA - Organizations
        # ================================================================
        try:
            accounts_response = org_client.list_accounts()
            accounts_managed = len(accounts_response.get('Accounts', []))
            cost_per_account = int(monthly_spend / accounts_managed) if accounts_managed > 0 else 0
        except Exception as e:
            st.warning(f"⚠️ Organizations: {str(e)}")
            accounts_managed = 0
            cost_per_account = 0
        
        # ================================================================
        # 9. BUILD COMPLETE RESPONSE
        # ================================================================
        st.success(f"✅ Connected to AWS - Monthly Spend: ${monthly_spend:,.2f} | Accounts: {accounts_managed}")
        
        return {
            # Financial Metrics
            'total_spend': monthly_spend * 12,
            'monthly_spend': monthly_spend,
            'savings_realized': 0,  # TODO: Add Savings Plans data
            'savings_potential': 0,  # TODO: Add Compute Optimizer
            'roi': 0,
            'budget': monthly_spend * 1.2,
            'budget_utilization': (monthly_spend / (monthly_spend * 1.2) * 100) if monthly_spend > 0 else 0,
            'burn_rate_hourly': monthly_spend / 720,
            
            # Trends
            'spend_trend': spend_trend,
            'savings_trend': [0] * 6,
            'months': months,
            
            # Breakdowns
            'cost_by_service': cost_by_service,
            'cost_by_region': cost_by_region,
            'cost_by_environment': {
                'Production': monthly_spend * 0.7,
                'Development': monthly_spend * 0.2,
                'Other': monthly_spend * 0.1
            },
            
            # Departments (requires cost allocation tags)
            'departments': [{
                'name': 'All Departments',
                'cost': monthly_spend,
                'budget': monthly_spend * 1.15,
                'utilization': 86.9,
                'accounts': accounts_managed,
                'top_services': list(cost_by_service.keys())[:3] if cost_by_service else ['N/A'],
                'savings_potential': 0,
                'cost_change': 0
            }],
            
            # Security & Compliance
            'security_findings': security_findings,
            'compliance': compliance,
            
            # Optimizations
            'optimizations': [{
                'category': 'Enable Compute Optimizer',
                'resource_count': 0,
                'potential_savings': 0,
                'confidence': 'N/A',
                'effort': 'N/A'
            }],
            
            # Forecast
            'forecast_next_month': forecast_next_month,
            'forecast_next_quarter': forecast_next_quarter,
            'forecast_confidence': 85.0,
            
            # Anomalies
            'anomalies': [],
            
            # Account Data
            'accounts_managed': accounts_managed,
            'accounts_added_month': 0,
            'cost_per_account': cost_per_account,
            
            # Sustainability
            'carbon_footprint': 0,
            'carbon_cost': 0,
            'renewable_energy_pct': 0
        }
        
    except NoCredentialsError:
        st.error("❌ AWS credentials not configured. Run: aws configure")
        return None
    except Exception as e:
        st.error(f"❌ AWS Error: {str(e)}")
        return None


def get_integrated_dashboard_data():
    """
    Fetch integrated data from multiple sources:
    - FinOps data (costs, optimization)
    - Security findings (cost impact)
    - Compliance metrics
    - Operations metrics
    """
    is_demo = st.session_state.get('demo_mode', False)
    
    if is_demo:
        # DEMO MODE - Comprehensive sample data
        return {
            # Financial Metrics
            'total_spend': 2847360,
            'monthly_spend': 2400000,
            'savings_realized': 287000,
            'savings_potential': 450000,
            'roi': 342,
            'budget': 3200000,
            'budget_utilization': 85.4,
            'burn_rate_hourly': 118.64,
            
            # Trend Data (Last 6 months)
            'spend_trend': [2100000, 2250000, 2300000, 2400000, 2350000, 2400000],
            'savings_trend': [180000, 210000, 235000, 260000, 275000, 287000],
            'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            
            # Cost Breakdown
            'cost_by_service': {
                'EC2': 945000,
                'RDS': 580000,
                'S3': 320000,
                'Lambda': 185000,
                'CloudFront': 145000,
                'Other': 225000
            },
            
            'cost_by_region': {
                'us-east-1': 1100000,
                'us-west-2': 680000,
                'eu-west-1': 420000,
                'ap-southeast-1': 200000
            },
            
            'cost_by_environment': {
                'Production': 1680000,
                'Development': 480000,
                'Staging': 180000,
                'Sandbox': 60000
            },
            
            # Department Breakdown
            'departments': [
                {
                    'name': 'Engineering',
                    'cost': 1245000,
                    'budget': 1400000,
                    'utilization': 88.9,
                    'accounts': 45,
                    'top_services': ['EC2', 'RDS', 'S3'],
                    'savings_potential': 185000,
                    'cost_change': -5.2
                },
                {
                    'name': 'Product',
                    'cost': 580000,
                    'budget': 650000,
                    'utilization': 89.2,
                    'accounts': 23,
                    'top_services': ['Lambda', 'DynamoDB', 'API Gateway'],
                    'savings_potential': 95000,
                    'cost_change': +3.5
                },
                {
                    'name': 'Data Science',
                    'cost': 425000,
                    'budget': 500000,
                    'utilization': 85.0,
                    'accounts': 15,
                    'top_services': ['SageMaker', 'EMR', 'S3'],
                    'savings_potential': 78000,
                    'cost_change': +8.2
                },
                {
                    'name': 'Infrastructure',
                    'cost': 150000,
                    'budget': 180000,
                    'utilization': 83.3,
                    'accounts': 8,
                    'top_services': ['CloudWatch', 'Route53', 'CloudTrail'],
                    'savings_potential': 22000,
                    'cost_change': -2.1
                }
            ],
            
            # Security Impact on Costs
            'security_findings': {
                'total_findings': 1247,
                'critical': 23,
                'cost_at_risk': 125000,  # Potential cost if exploited
                'remediation_cost': 18000,
                'cost_per_finding': 14.43
            },
            
            # Compliance Metrics
            'compliance': {
                'overall_score': 92.4,
                'non_compliant_resources': 780,
                'potential_fines': 50000,  # Risk if not addressed
                'compliance_cost': 25000  # Monthly compliance tooling
            },
            
            # Optimization Opportunities
            'optimizations': [
                {
                    'category': 'Right-sizing',
                    'resource_count': 234,
                    'potential_savings': 185000,
                    'confidence': 'High',
                    'effort': 'Low'
                },
                {
                    'category': 'Reserved Instances',
                    'resource_count': 89,
                    'potential_savings': 125000,
                    'confidence': 'High',
                    'effort': 'Medium'
                },
                {
                    'category': 'Storage Lifecycle',
                    'resource_count': 567,
                    'potential_savings': 78000,
                    'confidence': 'Medium',
                    'effort': 'Low'
                },
                {
                    'category': 'Idle Resources',
                    'resource_count': 123,
                    'potential_savings': 62000,
                    'confidence': 'High',
                    'effort': 'Low'
                }
            ],
            
            # Forecast
            'forecast_next_month': 2520000,
            'forecast_next_quarter': 7450000,
            'forecast_confidence': 87.5,
            
            # Anomalies
            'anomalies': [
                {
                    'service': 'EC2',
                    'region': 'us-east-1',
                    'cost_increase': 58.2,
                    'amount': 47500,
                    'root_cause': '15 new m5.2xlarge instances launched',
                    'department': 'Engineering'
                },
                {
                    'service': 'S3',
                    'region': 'us-west-2',
                    'cost_increase': 234.5,
                    'amount': 12800,
                    'root_cause': 'Unexpected data transfer surge',
                    'department': 'Data Science'
                }
            ],
            
            # Account Growth
            'accounts_managed': 127,
            'accounts_added_month': 5,
            'cost_per_account': 18897,
            
            # Sustainability
            'carbon_footprint': 145.8,  # metric tons CO2
            'carbon_cost': 7300,  # implied carbon cost
            'renewable_energy_pct': 65.2
        }
    else:
        # ============================================================
        # LIVE MODE - Choose your data source
        # ============================================================
        
        # 🔧 CONFIGURATION: Set this to True to fetch real AWS data
        USE_AWS_LIVE_DATA = False  # Change to True to enable AWS integration
        
        if USE_AWS_LIVE_DATA:
            # ========================================================
            # OPTION 1: FETCH REAL AWS DATA
            # ========================================================
            # This will connect to your AWS account and fetch real data
            # Prerequisites:
            # 1. Run: pip install boto3
            # 2. Run: aws configure (set your credentials)
            # 3. Ensure IAM permissions for Cost Explorer, Security Hub, Config, Organizations
            
            aws_data = fetch_aws_live_data()
            
            if aws_data:
                return aws_data
            else:
                # If AWS fetch fails, fall back to placeholder
                st.warning("⚠️ AWS connection failed. Showing placeholder data.")
        
        # ========================================================
        # OPTION 2: PLACEHOLDER DATA (Current Default)
        # ========================================================
        # Returns zeros - useful for testing UI without AWS connection
        try:
            return {
                # Financial Metrics (placeholders - connect to AWS Cost Explorer)
                'total_spend': 0,
                'monthly_spend': 0,
                'savings_realized': 0,
                'savings_potential': 0,
                'roi': 0,
                'budget': 0,
                'budget_utilization': 0,
                'burn_rate_hourly': 0,
                
                # Trend Data (empty - connect to Cost Explorer history)
                'spend_trend': [0, 0, 0, 0, 0, 0],
                'savings_trend': [0, 0, 0, 0, 0, 0],
                'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                
                # Cost Breakdown (empty - connect to Cost Explorer)
                'cost_by_service': {
                    'EC2': 0,
                    'RDS': 0,
                    'S3': 0,
                    'Lambda': 0,
                    'CloudFront': 0,
                    'Other': 0
                },
                
                'cost_by_region': {
                    'us-east-1': 0,
                    'us-west-2': 0,
                    'eu-west-1': 0,
                    'ap-southeast-1': 0
                },
                
                'cost_by_environment': {
                    'Production': 0,
                    'Development': 0,
                    'Staging': 0,
                    'Sandbox': 0
                },
                
                # Department Breakdown (placeholder - connect to billing tags)
                'departments': [
                    {
                        'name': 'No Data',
                        'cost': 0,
                        'budget': 0,
                        'utilization': 0,
                        'accounts': 0,
                        'top_services': ['N/A'],
                        'savings_potential': 0,
                        'cost_change': 0
                    }
                ],
                
                # Security Impact (connect to Security Hub)
                'security_findings': {
                    'total_findings': 0,
                    'critical': 0,
                    'cost_at_risk': 0,
                    'remediation_cost': 0,
                    'cost_per_finding': 0
                },
                
                # Compliance Metrics (connect to Config)
                'compliance': {
                    'overall_score': 0,
                    'non_compliant_resources': 0,
                    'potential_fines': 0,
                    'compliance_cost': 0
                },
                
                # Optimization Opportunities (connect to Compute Optimizer, Trusted Advisor)
                'optimizations': [
                    {
                        'category': 'No Data Available',
                        'resource_count': 0,
                        'potential_savings': 0,
                        'confidence': 'N/A',
                        'effort': 'N/A'
                    }
                ],
                
                # Forecast (connect to Cost Explorer forecast)
                'forecast_next_month': 0,
                'forecast_next_quarter': 0,
                'forecast_confidence': 0,
                
                # Anomalies (connect to Cost Anomaly Detection)
                'anomalies': [],
                
                # Account Growth (connect to Organizations)
                'accounts_managed': 0,
                'accounts_added_month': 0,
                'cost_per_account': 0,
                
                # Sustainability (connect to Customer Carbon Footprint Tool)
                'carbon_footprint': 0,
                'carbon_cost': 0,
                'renewable_energy_pct': 0
            }
        except Exception as e:
            st.error(f"Error fetching live data: {str(e)}")
            # Return empty structure on error to prevent crashes
            return {
                'total_spend': 0,
                'monthly_spend': 0,
                'savings_realized': 0,
                'savings_potential': 0,
                'roi': 0,
                'budget': 0,
                'budget_utilization': 0,
                'burn_rate_hourly': 0,
                'spend_trend': [0, 0, 0, 0, 0, 0],
                'savings_trend': [0, 0, 0, 0, 0, 0],
                'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                'cost_by_service': {'No Data': 0},
                'cost_by_region': {'No Data': 0},
                'cost_by_environment': {'No Data': 0},
                'departments': [{'name': 'No Data', 'cost': 0, 'budget': 0, 'utilization': 0, 'accounts': 0, 'top_services': ['N/A'], 'savings_potential': 0, 'cost_change': 0}],
                'security_findings': {'total_findings': 0, 'critical': 0, 'cost_at_risk': 0, 'remediation_cost': 0, 'cost_per_finding': 0},
                'compliance': {'overall_score': 0, 'non_compliant_resources': 0, 'potential_fines': 0, 'compliance_cost': 0},
                'optimizations': [{'category': 'No Data', 'resource_count': 0, 'potential_savings': 0, 'confidence': 'N/A', 'effort': 'N/A'}],
                'forecast_next_month': 0,
                'forecast_next_quarter': 0,
                'forecast_confidence': 0,
                'anomalies': [],
                'accounts_managed': 0,
                'accounts_added_month': 0,
                'cost_per_account': 0,
                'carbon_footprint': 0,
                'carbon_cost': 0,
                'renewable_energy_pct': 0
            }

def render_cfo_dashboard():
    """CFO Executive Dashboard"""
    if not EnterpriseAuth.check_permission(st.session_state.user, 'dashboard:cfo:tenant'):
        st.error("❌ Access Denied")
        return
    
    # Back button
    if st.button("⬅️ Back to Main Dashboard", key="cfo_back"):
        st.session_state.enterprise_page = None
        st.rerun()
    
    st.title("💰 CFO Dashboard - Financial Overview")
    
    cost_data = st.session_state.cost_monitor.get_current_hourly_cost()
    budget_data = st.session_state.cost_monitor.get_budget_status()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Cloud Spend", "$2.4M", "-8.2%", delta_color="inverse")
    with col2:
        st.metric("Savings Realized", "$287K", "+$45K")
    with col3:
        st.metric("ROI on Cloud", "342%", "+12%")
    with col4:
        st.metric("Budget Utilization", f"{budget_data['utilization_pct']:.1f}%")
    
    st.markdown("---")
    st.markdown("### 💳 Department Chargeback/Showback")
    chargeback = st.session_state.cost_monitor.get_chargeback_data()
    st.dataframe(pd.DataFrame(chargeback), width="stretch", hide_index=True)

def render_enhanced_cfo_dashboard():
    """Enhanced CFO Executive Dashboard with comprehensive data integration"""
    
    if not hasattr(st.session_state, 'user'):
        st.error("❌ Authentication required")
        return
    
    # Permission check (if using enterprise auth)
    if not EnterpriseAuth.check_permission(st.session_state.user, 'dashboard:cfo:tenant'):
        st.error("❌ Access Denied")
        return
    
    # Back button
    if st.button("⬅️ Back to Main Dashboard", key="cfo_back_enhanced"):
        st.session_state.enterprise_page = None
        st.rerun()
    
    # Check mode
    is_demo = st.session_state.get('demo_mode', False)
    
    # Get integrated data FIRST
    data = get_integrated_dashboard_data()
    
    if not data or 'total_spend' not in data:
        st.warning("⚠️ Unable to load dashboard data")
        return
    
    # Wrap entire dashboard in try-except to catch any calculation errors
    try:
        # Header with mode indicator
        if is_demo:
            st.title("💰 CFO Dashboard - Executive Financial Overview 🟠 DEMO MODE")
            st.info("📊 Demo Mode: Showing comprehensive sample financial data")
        else:
            st.title("💰 CFO Dashboard - Executive Financial Overview 🟢 LIVE MODE")
            # Check if we have real data or just placeholders
            if data.get('monthly_spend', 0) == 0 and data.get('total_spend', 0) == 0:
                st.warning("""
                ⚠️ **LIVE MODE - Data Sources Not Connected**
                
                This dashboard is ready for live data but is currently showing placeholder values (zeros).
                
                **To connect real data, update the `get_integrated_dashboard_data()` function to integrate with:**
                - AWS Cost Explorer (for spend, trends, forecasts)
                - AWS Security Hub (for security findings)
                - AWS Config (for compliance metrics)
                - AWS Compute Optimizer / Trusted Advisor (for optimization opportunities)
                - AWS Organizations (for account data)
                - Customer Carbon Footprint Tool (for sustainability metrics)
                
                **Toggle to Demo Mode** in the sidebar to see sample data and explore all features.
                """)
            else:
                st.info("🔗 Connected to your AWS Cost Explorer and compliance systems")
        
        
        # ========================================================================
        # SECTION 1: EXECUTIVE KPIs
        # ========================================================================
        st.markdown("### 📊 Executive KPIs - Current Month")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                "Total Cloud Spend",
                f"${data['monthly_spend']/1000000:.1f}M",
                f"-{abs(random.uniform(5, 12)):.1f}%",
                delta_color="inverse"
            )
            st.caption("Monthly cloud expenditure")
        
        with col2:
            st.metric(
                "Savings Realized",
                f"${data['savings_realized']/1000:.0f}K",
                f"+${random.randint(30, 60)}K"
            )
            st.caption("YTD cost optimizations")
        
        with col3:
            # Safe division - avoid divide by zero
            if data['monthly_spend'] > 0:
                savings_pct = (data['savings_realized'] / data['monthly_spend'] * 100)
            else:
                savings_pct = 0
            
            st.metric(
                "Savings Rate",
                f"{savings_pct:.1f}%",
                f"+{random.uniform(1, 3):.1f}%"
            )
            st.caption("% of spend optimized")
        
        with col4:
            st.metric(
                "Budget Utilization",
                f"{data['budget_utilization']:.1f}%",
                f"+{random.uniform(2, 5):.1f}%"
            )
            st.caption(f"${data['budget']/1000000:.1f}M allocated")
        
        with col5:
            st.metric(
                "ROI on Cloud",
                f"{data['roi']}%",
                f"+{random.randint(10, 20)}%"
            )
            st.caption("Business value delivered")
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 2: SPEND TRENDS & FORECAST
        # ========================================================================
        st.markdown("### 📈 Spend Trends & Forecast")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Spend trend chart
            fig = go.Figure()
            
            # Historical spend
            fig.add_trace(go.Scatter(
                x=data['months'],
                y=data['spend_trend'],
                mode='lines+markers',
                name='Monthly Spend',
                line=dict(color='#FF6B6B', width=3),
                marker=dict(size=8)
            ))
            
            # Savings trend
            fig.add_trace(go.Scatter(
                x=data['months'],
                y=data['savings_trend'],
                mode='lines+markers',
                name='Cumulative Savings',
                line=dict(color='#4ECDC4', width=3),
                marker=dict(size=8),
                yaxis='y2'
            ))
            
            fig.update_layout(
                title="6-Month Spend & Savings Trend",
                xaxis_title="Month",
                yaxis=dict(title="Monthly Spend ($)", tickformat='$,.0f'),
                yaxis2=dict(title="Savings ($)", overlaying='y', side='right', tickformat='$,.0f'),
                hovermode='x unified',
                height=350
            )
            
            st.plotly_chart(fig, width="stretch")
        
        with col2:
            st.markdown("#### 🔮 Forecast")
            
            # Safe calculation of forecast change percentage
            if data['monthly_spend'] > 0:
                forecast_change_pct = ((data['forecast_next_month']/data['monthly_spend']-1)*100)
            else:
                forecast_change_pct = 0
            
            st.metric(
                "Next Month",
                f"${data['forecast_next_month']/1000000:.2f}M",
                f"+{forecast_change_pct:.1f}%"
            )
            
            st.metric(
                "Next Quarter",
                f"${data['forecast_next_quarter']/1000000:.2f}M",
                f"Confidence: {data['forecast_confidence']:.1f}%"
            )
            
            st.metric(
                "Savings Potential",
                f"${data['savings_potential']/1000:.0f}K",
                "Available optimizations"
            )
            
            st.caption(f"💡 Burn rate: ${data['burn_rate_hourly']:.2f}/hour")
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 3: COST BREAKDOWN
        # ========================================================================
        st.markdown("### 💳 Cost Breakdown Analysis")
        
        tab1, tab2, tab3 = st.tabs(["By Service", "By Region", "By Environment"])
        
        with tab1:
            # Service breakdown pie chart
            fig = px.pie(
                values=list(data['cost_by_service'].values()),
                names=list(data['cost_by_service'].keys()),
                title="Cost Distribution by AWS Service",
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, width="stretch")
        
        with tab2:
            # Region breakdown bar chart
            fig = px.bar(
                x=list(data['cost_by_region'].keys()),
                y=list(data['cost_by_region'].values()),
                title="Cost Distribution by Region",
                labels={'x': 'Region', 'y': 'Cost ($)'},
                color=list(data['cost_by_region'].values()),
                color_continuous_scale='Viridis'
            )
            fig.update_layout(showlegend=False, yaxis_tickformat='$,.0f')
            st.plotly_chart(fig, width="stretch")
        
        with tab3:
            # Environment breakdown
            fig = px.funnel(
                y=list(data['cost_by_environment'].keys()),
                x=list(data['cost_by_environment'].values()),
                title="Cost Distribution by Environment"
            )
            fig.update_traces(textinfo='value+percent total')
            st.plotly_chart(fig, width="stretch")
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 4: DEPARTMENT DEEP DIVE
        # ========================================================================
        st.markdown("### 🏢 Department Financial Performance")
        
        # Create department comparison chart
        dept_df = pd.DataFrame(data['departments'])
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Department spend comparison
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                name='Actual Cost',
                x=dept_df['name'],
                y=dept_df['cost'],
                marker_color='#FF6B6B'
            ))
            
            fig.add_trace(go.Bar(
                name='Budget',
                x=dept_df['name'],
                y=dept_df['budget'],
                marker_color='#4ECDC4'
            ))
            
            fig.update_layout(
                title="Department: Actual vs Budget",
                xaxis_title="Department",
                yaxis_title="Cost ($)",
                yaxis_tickformat='$,.0f',
                barmode='group',
                height=350
            )
            
            st.plotly_chart(fig, width="stretch")
        
        with col2:
            st.markdown("#### 🎯 Efficiency Scores")
            for dept in data['departments'][:3]:
                efficiency = 100 - dept['utilization']
                st.metric(
                    dept['name'],
                    f"{dept['utilization']:.1f}%",
                    f"{dept['cost_change']:+.1f}% MoM",
                    delta_color="inverse" if dept['cost_change'] > 0 else "normal"
                )
        
        # Detailed department table
        st.markdown("#### 📋 Department Details")
        dept_display = []
        for dept in data['departments']:
            dept_display.append({
                'Department': dept['name'],
                'Cost': f"${dept['cost']/1000:.0f}K",
                'Budget': f"${dept['budget']/1000:.0f}K",
                'Utilization': f"{dept['utilization']:.1f}%",
                'Accounts': dept['accounts'],
                'Top Services': ', '.join(dept['top_services']),
                'Savings Potential': f"${dept['savings_potential']/1000:.0f}K",
                'MoM Change': f"{dept['cost_change']:+.1f}%"
            })
        
        st.dataframe(pd.DataFrame(dept_display), width="stretch", hide_index=True)
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 5: SECURITY & COMPLIANCE FINANCIAL IMPACT
        # ========================================================================
        st.markdown("### 🛡️ Security & Compliance Financial Impact")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Cost at Risk",
                f"${data['security_findings']['cost_at_risk']/1000:.0f}K",
                f"{data['security_findings']['critical']} critical findings"
            )
            st.caption("Potential loss if exploited")
        
        with col2:
            st.metric(
                "Remediation Cost",
                f"${data['security_findings']['remediation_cost']/1000:.0f}K",
                f"{data['security_findings']['total_findings']} findings"
            )
            st.caption("To fix all findings")
        
        with col3:
            st.metric(
                "Compliance Risk",
                f"${data['compliance']['potential_fines']/1000:.0f}K",
                f"{data['compliance']['non_compliant_resources']} resources"
            )
            st.caption("Potential regulatory fines")
        
        with col4:
            st.metric(
                "Compliance Cost",
                f"${data['compliance']['compliance_cost']/1000:.0f}K/mo",
                f"{data['compliance']['overall_score']:.1f}% compliant"
            )
            st.caption("Monthly compliance tooling")
        
        # ROI comparison
        col1, col2 = st.columns(2)
        
        # Calculate security ROI safely
        if data['security_findings']['remediation_cost'] > 0:
            security_roi = (data['security_findings']['cost_at_risk']/data['security_findings']['remediation_cost']*100-100)
        else:
            security_roi = 0
        
        with col1:
            st.info(f"""
            **💡 Security ROI Analysis**
            - Investment: ${data['security_findings']['remediation_cost']:,}
            - Risk Reduction: ${data['security_findings']['cost_at_risk']:,}
            - ROI: {security_roi:.0f}%
            - Payback Period: ~2.3 months
            """)
        
        # Calculate compliance risk mitigation safely
        if data['compliance']['compliance_cost'] > 0:
            risk_mitigation = (data['compliance']['potential_fines']/data['compliance']['compliance_cost'])
        else:
            risk_mitigation = 0
        
        with col2:
            st.info(f"""
            **📊 Compliance Investment**
            - Monthly Cost: ${data['compliance']['compliance_cost']:,}
            - Avoided Fines: ${data['compliance']['potential_fines']:,}
            - Risk Mitigation: {risk_mitigation:.1f}x
            - Score: {data['compliance']['overall_score']}%
            """)
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 6: OPTIMIZATION OPPORTUNITIES
        # ========================================================================
        st.markdown("### 💡 Cost Optimization Opportunities")
        
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1.5rem; border-radius: 10px; color: white; margin-bottom: 1rem;'>
            <h3 style='margin: 0; color: white;'>💰 Total Savings Potential: ${data['savings_potential']/1000:.0f}K/month</h3>
            <p style='margin: 0.5rem 0 0 0; opacity: 0.9;'>Identified {sum(opt['resource_count'] for opt in data['optimizations'])} optimization opportunities</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Optimization opportunities table
        opt_display = []
        for opt in data['optimizations']:
            opt_display.append({
                'Category': opt['category'],
                'Resources': opt['resource_count'],
                'Monthly Savings': f"${opt['potential_savings']/1000:.0f}K",
                'Annual Impact': f"${opt['potential_savings']*12/1000:.0f}K",
                'Confidence': opt['confidence'],
                'Implementation': opt['effort']
            })
        
        st.dataframe(pd.DataFrame(opt_display), width="stretch", hide_index=True)
        
        # Quick wins vs Strategic initiatives (Dynamic from data)
        col1, col2 = st.columns(2)
        
        # Categorize optimizations by effort level
        quick_wins = [opt for opt in data['optimizations'] if opt.get('effort') == 'Low']
        strategic = [opt for opt in data['optimizations'] if opt.get('effort') in ['Medium', 'High']]
        
        with col1:
            # Build quick wins text dynamically
            if quick_wins:
                quick_text = "\n            ".join([
                    f"- {opt['category']}: {opt['resource_count']} resources → ${opt['potential_savings']/1000:.0f}K/mo"
                    for opt in quick_wins
                ])
                total_quick = sum(opt['potential_savings'] for opt in quick_wins)
                
                st.success(f"""
            **🎯 Quick Wins (This Month)**
            {quick_text}
            
            **Total Quick Wins: ${total_quick/1000:.0f}K/month savings**
            """)
            else:
                st.info("""
            **🎯 Quick Wins (This Month)**
            
            No low-effort optimizations identified at this time.
            
            Check back after enabling AWS Compute Optimizer.
            """)
        
        with col2:
            # Build strategic initiatives text dynamically
            if strategic:
                strategic_text = "\n            ".join([
                    f"- {opt['category']}: {opt['resource_count']} resources → ${opt['potential_savings']/1000:.0f}K/mo"
                    for opt in strategic
                ])
                total_strategic = sum(opt['potential_savings'] for opt in strategic)
                
                st.warning(f"""
            **📅 Strategic Initiatives (This Quarter)**
            {strategic_text}
            
            **Total Strategic: ${total_strategic/1000:.0f}K/month savings**
            """)
            else:
                st.info("""
            **📅 Strategic Initiatives (This Quarter)**
            
            No medium/high-effort optimizations identified at this time.
            
            Check back after enabling AWS Compute Optimizer.
            """)
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 7: ANOMALIES & ALERTS
        # ========================================================================
        if data['anomalies']:
            st.markdown("### 🚨 Cost Anomalies Detected")
            
            for anomaly in data['anomalies']:
                st.warning(f"""
                **{anomaly['service']}** in {anomaly['region']} ({anomaly['department']})
                - Cost Increase: **+{anomaly['cost_increase']:.1f}%** (${anomaly['amount']:,})
                - Root Cause: {anomaly['root_cause']}
                - Action Required: Review and optimize
                """)
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 8: SUSTAINABILITY METRICS
        # ========================================================================
        st.markdown("### 🌱 Sustainability & ESG Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Carbon Footprint",
                f"{data['carbon_footprint']:.1f} tons",
                "-12.3% YoY",
                delta_color="inverse"
            )
            st.caption("CO2 emissions this month")
        
        with col2:
            st.metric(
                "Implied Carbon Cost",
                f"${data['carbon_cost']:,}",
                "-8.5%",
                delta_color="inverse"
            )
            st.caption("At $50/ton CO2")
        
        with col3:
            st.metric(
                "Renewable Energy",
                f"{data['renewable_energy_pct']:.1f}%",
                "+5.2%"
            )
            st.caption("Of total energy consumption")
        
        with col4:
            # Safe division - avoid divide by zero
            if data['monthly_spend'] > 0:
                carbon_per_dollar = data['carbon_footprint'] / (data['monthly_spend']/1000000)
            else:
                carbon_per_dollar = 0
            
            st.metric(
                "Carbon Efficiency",
                f"{carbon_per_dollar:.1f} kg/$K",
                "-3.8%",
                delta_color="inverse"
            )
            st.caption("Emissions per $1K spend")
        
        st.markdown("---")
        
        # ========================================================================
        # SECTION 9: ACCOUNT GROWTH & SCALE
        # ========================================================================
        st.markdown("### 📊 Account Growth & Economics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Accounts",
                data['accounts_managed'],
                f"+{data['accounts_added_month']} this month"
            )
        
        with col2:
            st.metric(
                "Cost per Account",
                f"${data['cost_per_account']:,}",
                "-2.3%",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "Active Accounts",
                f"{int(data['accounts_managed'] * 0.87)}",
                "86.7% utilization"
            )
        
        with col4:
            st.metric(
                "Dormant Accounts",
                f"{int(data['accounts_managed'] * 0.13)}",
                "Potential to close"
            )
        
        st.markdown("---")
        
        # ========================================================================
        # FOOTER: EXECUTIVE SUMMARY
        # ========================================================================
        st.markdown("### 📋 Executive Summary")
        
        # Calculate savings percentage safely
        if data['monthly_spend'] > 0:
            savings_pct_summary = (data['savings_realized']/data['monthly_spend']*100)
        else:
            savings_pct_summary = 0
        
        # Build recommendations based on available data
        recommendations = [
            "1. Implement quick-win optimizations → $270K/month savings",
            f"2. Address critical security findings → Protect ${data['security_findings']['cost_at_risk']/1000:.0f}K at risk"
        ]
        
        # Add anomaly recommendation if anomalies exist
        if data['anomalies'] and len(data['anomalies']) > 0:
            recommendations.append(f"3. Review {data['anomalies'][0]['department']} department's {data['anomalies'][0]['service']} spike")
        
        # Add dormant accounts recommendation
        dormant_count = int(data['accounts_managed'] * 0.13)
        if dormant_count > 0 and data['cost_per_account'] > 0:
            dormant_savings = int(dormant_count * data['cost_per_account']/1000)
            recommendations.append(f"4. Close {dormant_count} dormant accounts → ~${dormant_savings}K/month")
        
        recommendations_text = "\n        ".join(recommendations)
        
        st.markdown(f"""
        <div style='background: #f8f9fa; padding: 1.5rem; border-radius: 10px; border-left: 4px solid #667eea;'>
            <h4 style='margin-top: 0; color: #333;'>Financial Health: <span style='color: #4ECDC4;'>Strong</span></h4>
            
            **Key Highlights:**
            - Monthly spend: ${data['monthly_spend']/1000000:.1f}M (within budget at {data['budget_utilization']:.1f}% utilization)
            - YTD savings: ${data['savings_realized']/1000:.0f}K ({savings_pct_summary:.1f}% of spend)
            - Optimization potential: ${data['savings_potential']/1000:.0f}K/month identified
            - ROI on cloud investments: {data['roi']}%
            
            **Risk Factors:**
            - ${data['security_findings']['cost_at_risk']/1000:.0f}K at risk from {data['security_findings']['critical']} critical security findings
            - ${data['compliance']['potential_fines']/1000:.0f}K potential compliance fines
            - {len(data['anomalies'])} cost anomalies detected requiring attention
            
            **Recommendations:**
            {recommendations_text}
        </div>
        """, unsafe_allow_html=True)
        
        # Export buttons
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📊 Export to PDF", width="stretch"):
                st.info("PDF export functionality coming soon")
        with col2:
            if st.button("📧 Email Report", width="stretch"):
                st.info("Email functionality coming soon")
        with col3:
            if st.button("📅 Schedule Report", width="stretch"):
                st.info("Scheduling functionality coming soon")
        
    except ZeroDivisionError as e:
        st.error(f"""
        ❌ **Calculation Error**: A division by zero occurred while rendering the dashboard.
        
        This typically happens when cost data is zero. Please ensure:
        - Toggle to **Demo Mode** to see sample data, OR
        - Connect to real AWS data sources (see warning above)
        
        **Technical Details**: {str(e)}
        """)
    except Exception as e:
        st.error(f"❌ An unexpected error occurred: {str(e)}")

def render_control_tower():
    """Control Tower Management Dashboard with Demo/Live Mode Support"""
    if not EnterpriseAuth.check_permission(st.session_state.user, 'controltower:read:tenant'):
        st.error("❌ Access Denied")
        return
    
    # Back button
    if st.button("⬅️ Back to Main Dashboard", key="ct_back"):
        st.session_state.enterprise_page = None
        st.rerun()
    
    # ⚠️ CRITICAL: Check and display mode
    is_demo = st.session_state.get('demo_mode', False)
    
    # ⚠️ CRITICAL: Re-initialize ct_manager with current AWS credentials
    # This ensures we use the latest credentials from session state
    org_client = None
    if 'aws_clients' in st.session_state and st.session_state.aws_clients:
        org_client = st.session_state.aws_clients.get('organizations')
    st.session_state.ct_manager = ControlTowerManager(org_client=org_client)
    
    # Title with mode indicator
    if is_demo:
        st.title("🏗️ AWS Control Tower Management 🟠 DEMO MODE")
        st.warning("📊 Demo Mode: Showing sample data (127 accounts, 45 guardrails)")
    else:
        st.title("🏗️ AWS Control Tower Management 🟢 LIVE MODE")
        # Check if AWS is connected
        if st.session_state.get('aws_connected') and org_client:
            st.info("🔗 Connected to your AWS Organization")
        else:
            st.warning("⚠️ AWS credentials not configured. Please configure AWS credentials in sidebar.")
    
    ct = st.session_state.ct_manager
    lz = ct.get_landing_zone_status()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        status_color = "🟢" if lz['status'] == 'ACTIVE' else "🔴"
        st.metric("Status", f"{status_color} {lz['status']}")
    with col2:
        st.metric("Accounts Managed", lz['accounts_managed'])
    with col3:
        st.metric("Guardrails Enabled", lz['guardrails_enabled'])
    
    st.markdown("---")
    st.markdown("### 🏢 Organizational Units")
    ous = ct.get_organizational_units()
    st.dataframe(pd.DataFrame(ous), width="stretch", hide_index=True)
    
    st.markdown("---")
    
    # Account provisioning section with mode-aware messaging
    if is_demo:
        st.markdown("### ➕ Provision New Account (60-second target) - **DEMO SIMULATION**")
        st.caption("Note: In Demo mode, this simulates account provisioning without creating real AWS accounts")
    else:
        st.markdown("### ➕ Provision New Account (60-second target) - **LIVE PROVISIONING**")
        st.caption("⚠️ Warning: This will create an actual AWS account in your organization!")
    
    with st.form("provision_account"):
        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Account Name", placeholder="prod-app-2024")
            email = st.text_input("Email", placeholder="aws+prod@company.com")
        with col2:
            ou = st.selectbox("Organizational Unit", [o['name'] for o in ous])
            sso = st.text_input("SSO User Email", placeholder="owner@company.com")
        
        button_label = "🚀 Provision Account (Simulation)" if is_demo else "🚀 Provision Account (LIVE - Creates Real Account!)"
        
        if st.form_submit_button(button_label, type="primary", width="stretch"):
            start_time = time.time()
            with st.spinner("Provisioning via Account Factory..."):
                progress = st.progress(0)
                for i in range(21):
                    progress.progress(i * 5)
                    time.sleep(0.05)
                
                result = ct.provision_account(name, email, ou, sso)
                elapsed = time.time() - start_time
                
                progress.empty()
                
                if result['status'] == 'SUCCESS':
                    st.success(f"✅ **SUCCESS!** Account {result['account_id']} provisioned in {elapsed:.1f} seconds!")
                    st.info(f"**Services Enabled:** {', '.join(result['services_enabled'])}")
                    if result.get('mode') == 'DEMO':
                        st.caption("🟠 This was a demo simulation - no real account was created")
                elif result['status'] == 'IN_PROGRESS':
                    st.info(f"⏳ **PROVISIONING STARTED** - Request ID: {result['provisioning_id']}")
                    st.info(result.get('message', 'Account creation in progress'))
                else:
                    st.error(f"❌ **ERROR** - {result.get('error', 'Unknown error')}")

def render_realtime_costs():
    """Real-Time Cost Operations Dashboard"""
    if not EnterpriseAuth.check_permission(st.session_state.user, 'finops:read:tenant'):
        st.error("❌ Access Denied")
        return
    
    # Back button
    if st.button("⬅️ Back to Main Dashboard", key="rtc_back"):
        st.session_state.enterprise_page = None
        st.rerun()
    
    # CRITICAL: Reinitialize cost_monitor to pick up mode changes
    # This ensures the monitor uses the current demo_mode setting
    st.session_state.cost_monitor = RealTimeCostMonitor()
    
    # Check mode
    is_demo = st.session_state.get('demo_mode', False)
    
    # Title with mode indicator
    if is_demo:
        st.title("💸 Real-Time Cost Operations 🟠 DEMO MODE")
        st.info("📊 Demo Mode: Showing sample real-time cost data")
    else:
        st.title("💸 Real-Time Cost Operations 🟢 LIVE MODE")
    
    cost_data = st.session_state.cost_monitor.get_current_hourly_cost()
    anomalies = st.session_state.cost_monitor.detect_anomalies()
    
    # Show warning in LIVE mode if no data
    if not is_demo and cost_data['total'] == 0:
        st.warning("""
        ⚠️ **LIVE MODE - Real-Time Data Not Connected**
        
        This dashboard is ready for real-time cost monitoring but is currently showing zeros.
        
        **To connect real data, integrate with:**
        - AWS Cost Explorer (for hourly/daily spend)
        - AWS Cost Anomaly Detection (for anomaly alerts)
        - CloudWatch Metrics (for real-time usage)
        
        **Toggle to Demo Mode** in the sidebar to see sample data.
        """)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        delta = "+12.3%" if is_demo else None
        st.metric("Hourly Burn Rate", f"${cost_data['burn_rate']['hourly']:.2f}/hr", delta)
    with col2:
        st.metric("Today's Spend", f"${cost_data['burn_rate']['daily']:,.2f}")
    with col3:
        delta = "+8.5%" if is_demo else None
        st.metric("Monthly Projection", f"${cost_data['burn_rate']['monthly_projection']:,.0f}", delta)
    
    if anomalies:
        st.markdown("### ⚠️ Cost Anomalies Detected (Real-Time)")
        for a in anomalies:
            st.warning(f"🚨 **{a['service']}** in {a['region']}: +{a['increase_pct']:.1f}% increase - {a['root_cause']}")
    elif not is_demo:
        st.success("✅ No cost anomalies detected")

def check_enterprise_routing():
    """Check if enterprise page is requested and route accordingly"""
    enterprise_page = st.session_state.get('enterprise_page')
    if enterprise_page == 'cfo':
        render_enhanced_cfo_dashboard()  # Using enhanced version
        return True
    elif enterprise_page == 'controltower':
        render_control_tower()
        return True
    elif enterprise_page == 'realtime_costs':
        render_realtime_costs()
        return True
    return False