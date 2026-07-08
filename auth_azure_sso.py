"""
Azure AD SSO Authentication for Cloud Compliance Canvas
========================================================
Enterprise authentication with Microsoft Azure AD / Entra ID SSO
and Firebase Realtime Database for user management.

Features:
- Azure AD SSO (Microsoft Sign-In)
- Role-Based Access Control (RBAC)
- Firebase user persistence
- Session management
- Tab-level access control

Roles:
- super_admin: Full system access, manage all users and settings
- admin: Manage users, run remediation, full compliance access
- security_manager: Security findings, compliance, view remediation
- finops_analyst: Cost analysis, optimization, FinOps dashboards
- compliance_viewer: Read-only compliance data
- viewer: Dashboard view only

Version: 1.0.0
"""

import streamlit as st
from typing import Optional, Dict, List, Callable, Any
from functools import wraps
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import uuid

# ============================================================================
# ROLE DEFINITIONS
# ============================================================================

class UserRole(Enum):
    """User role hierarchy (higher value = more permissions)"""
    GUEST = 0
    VIEWER = 1
    COMPLIANCE_VIEWER = 2
    FINOPS_ANALYST = 3
    SECURITY_MANAGER = 4
    ADMIN = 5
    SUPER_ADMIN = 6
    
    @classmethod
    def from_string(cls, role_str: str) -> 'UserRole':
        """Convert string to UserRole"""
        mapping = {
            'guest': cls.GUEST,
            'viewer': cls.VIEWER,
            'compliance_viewer': cls.COMPLIANCE_VIEWER,
            'finops_analyst': cls.FINOPS_ANALYST,
            'security_manager': cls.SECURITY_MANAGER,
            'admin': cls.ADMIN,
            'super_admin': cls.SUPER_ADMIN,
            'superadmin': cls.SUPER_ADMIN,
        }
        return mapping.get(role_str.lower(), cls.GUEST)
    
    def __str__(self):
        return self.name.lower()


# Permission definitions per role
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        "manage_all_users": True,
        "manage_settings": True,
        "view_audit_logs": True,
        "run_remediation": True,
        "approve_remediation": True,
        "view_all_accounts": True,
        "view_compliance": True,
        "view_security_findings": True,
        "view_finops": True,
        "export_reports": True,
        "manage_policies": True,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
        # Account lifecycle permissions
        "create_account_direct": True,      # Can create accounts without approval
        "delete_account_direct": True,      # Can delete accounts without approval
        "approve_account_requests": True,   # Can approve others' requests
        "bypass_approval_workflow": True,   # Skip approval workflow entirely
    },
    UserRole.ADMIN: {
        "manage_all_users": False,
        "manage_settings": True,
        "view_audit_logs": True,
        "run_remediation": True,
        "approve_remediation": True,
        "view_all_accounts": True,
        "view_compliance": True,
        "view_security_findings": True,
        "view_finops": True,
        "export_reports": True,
        "manage_policies": True,
        "access_all_tabs": True,
        "use_demo_mode": True,
        "use_live_mode": True,
        "manage_org_users": True,
        # Account lifecycle permissions
        "create_account_direct": False,     # Requires approval
        "delete_account_direct": False,     # Requires approval
        "approve_account_requests": True,   # Can approve others' requests
        "bypass_approval_workflow": False,
    },
    UserRole.SECURITY_MANAGER: {
        "manage_all_users": False,
        "manage_settings": False,
        "view_audit_logs": True,
        "run_remediation": True,
        "approve_remediation": False,
        "view_all_accounts": True,
        "view_compliance": True,
        "view_security_findings": True,
        "view_finops": False,
        "export_reports": True,
        "manage_policies": True,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": True,
        # Account lifecycle permissions
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,  # Security review only
        "bypass_approval_workflow": False,
    },
    UserRole.FINOPS_ANALYST: {
        "manage_all_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "run_remediation": False,
        "approve_remediation": False,
        "view_all_accounts": True,
        "view_compliance": False,
        "view_security_findings": False,
        "view_finops": True,
        "export_reports": True,
        "manage_policies": False,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": True,
        # Account lifecycle permissions
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,  # FinOps review only
        "bypass_approval_workflow": False,
    },
    UserRole.COMPLIANCE_VIEWER: {
        "manage_all_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "run_remediation": False,
        "approve_remediation": False,
        "view_all_accounts": True,
        "view_compliance": True,
        "view_security_findings": True,
        "view_finops": False,
        "export_reports": True,
        "manage_policies": False,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": False,
        # Account lifecycle permissions
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,
        "bypass_approval_workflow": False,
    },
    UserRole.VIEWER: {
        "manage_all_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "run_remediation": False,
        "approve_remediation": False,
        "view_all_accounts": False,
        "view_compliance": True,
        "view_security_findings": False,
        "view_finops": False,
        "export_reports": False,
        "manage_policies": False,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": False,
        # Account lifecycle permissions
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,
        "bypass_approval_workflow": False,
    },
    UserRole.GUEST: {
        "manage_all_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "run_remediation": False,
        "approve_remediation": False,
        "view_all_accounts": False,
        "view_compliance": False,
        "view_security_findings": False,
        "view_finops": False,
        "export_reports": False,
        "manage_policies": False,
        "access_all_tabs": False,
        "use_demo_mode": True,
        "use_live_mode": False,
        # Account lifecycle permissions
        "create_account_direct": False,
        "delete_account_direct": False,
        "approve_account_requests": False,
        "bypass_approval_workflow": False,
    },
}

# Tab access definitions
TAB_ACCESS = {
    "Unified Compliance": ["super_admin", "admin", "security_manager", "compliance_viewer", "viewer"],
    "Overview Dashboard": ["super_admin", "admin", "security_manager", "finops_analyst", "compliance_viewer", "viewer"],
    "Inspector Vulnerabilities": ["super_admin", "admin", "security_manager"],
    "Tech Guardrails": ["super_admin", "admin", "security_manager"],
    "AI Remediation": ["super_admin", "admin", "security_manager"],
    "Unified Remediation": ["super_admin", "admin", "security_manager"],
    "GitHub & GitOps": ["super_admin", "admin", "security_manager"],
    "Account Lifecycle": ["super_admin", "admin"],
    "Security Findings": ["super_admin", "admin", "security_manager", "compliance_viewer"],
    "FinOps & Cost Management": ["super_admin", "admin", "finops_analyst"],
}


# ============================================================================
# ROLE MANAGER
# ============================================================================

class RoleManager:
    """Manages role-based permissions"""
    
    ROLES = {
        'super_admin': {
            'display_name': 'Super Administrator',
            'description': 'Full system access, manage all users and settings',
            'color': '#dc3545',
            'permissions': ['*']
        },
        'admin': {
            'display_name': 'Administrator',
            'description': 'Full feature access, manage organization users',
            'color': '#fd7e14',
            'permissions': ['manage_org_users', 'run_remediation', 'approve_remediation', 'view_all', 'export_reports']
        },
        'security_manager': {
            'display_name': 'Security Manager',
            'description': 'Security findings, compliance, remediation',
            'color': '#ffc107',
            'permissions': ['view_security', 'view_compliance', 'run_remediation', 'export_reports']
        },
        'finops_analyst': {
            'display_name': 'FinOps Analyst',
            'description': 'Cost analysis, optimization, FinOps dashboards',
            'color': '#28a745',
            'permissions': ['view_finops', 'view_costs', 'export_reports']
        },
        'compliance_viewer': {
            'display_name': 'Compliance Viewer',
            'description': 'Read-only compliance and security data',
            'color': '#17a2b8',
            'permissions': ['view_compliance', 'view_security', 'export_reports']
        },
        'viewer': {
            'display_name': 'Viewer',
            'description': 'Read-only dashboard access',
            'color': '#6c757d',
            'permissions': ['view_dashboard']
        }
    }
    
    @staticmethod
    def has_permission(user_role: str, required_permission: str) -> bool:
        """Check if user role has the required permission"""
        if not user_role:
            return False
        
        role_enum = UserRole.from_string(user_role)
        role_perms = ROLE_PERMISSIONS.get(role_enum, {})
        
        # Super admin has all permissions
        if role_perms.get('manage_all_users') and role_perms.get('manage_settings'):
            return True
        
        return role_perms.get(required_permission, False)
    
    @staticmethod
    def get_user_permissions(user_role: str) -> List[str]:
        """Get list of permissions for a role"""
        role_enum = UserRole.from_string(user_role)
        role_perms = ROLE_PERMISSIONS.get(role_enum, {})
        return [k for k, v in role_perms.items() if v]
    
    @staticmethod
    def get_role_display_name(role: str) -> str:
        """Get display name for a role"""
        return RoleManager.ROLES.get(role, {}).get('display_name', role.title())
    
    @staticmethod
    def get_role_color(role: str) -> str:
        """Get color for a role badge"""
        return RoleManager.ROLES.get(role, {}).get('color', '#6c757d')


def check_tab_access(tab_name: str, user_role: str) -> bool:
    """Check if user role has access to a specific tab"""
    if not user_role:
        return False
    
    # Super admin and admin have access to all tabs
    if user_role in ['super_admin', 'admin']:
        return True
    
    allowed_roles = TAB_ACCESS.get(tab_name, [])
    return user_role in allowed_roles


# ============================================================================
# DECORATORS
# ============================================================================

def require_permission(permission: str) -> Callable:
    """Decorator to require specific permission for a function"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not st.session_state.get('authenticated', False):
                st.error("❌ Authentication required")
                return
            
            user_info = st.session_state.get('user_info', {})
            user_role = user_info.get('role', 'viewer')
            
            if not RoleManager.has_permission(user_role, permission):
                st.error("❌ You don't have permission to access this feature")
                st.info(f"**Required permission:** `{permission}` | **Your role:** `{user_role}`")
                return
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(min_role: str) -> Callable:
    """Decorator to require minimum role level"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not st.session_state.get('authenticated', False):
                st.error("❌ Authentication required")
                return
            
            user_info = st.session_state.get('user_info', {})
            user_role = user_info.get('role', 'viewer')
            
            user_role_enum = UserRole.from_string(user_role)
            min_role_enum = UserRole.from_string(min_role)
            
            if user_role_enum.value < min_role_enum.value:
                st.error(f"❌ Insufficient permissions. Minimum role required: {min_role}")
                return
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    """Manages user sessions"""
    
    SESSION_TIMEOUT_HOURS = 8
    
    @staticmethod
    def login(user_info: Dict[str, Any]) -> bool:
        """Login user and create session"""
        try:
            st.session_state.authenticated = True
            st.session_state.user_info = user_info
            st.session_state.user_id = user_info.get('id')
            st.session_state.session_start = datetime.utcnow().isoformat()
            st.session_state.user_manager = SimpleUserManager()
            return True
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    @staticmethod
    def logout():
        """Logout user and clear session"""
        keys_to_clear = [
            'authenticated', 'user_info', 'user_id', 'session_start',
            'user_manager', 'oauth_state'
        ]
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
    
    @staticmethod
    def is_session_valid() -> bool:
        """Check if session is still valid"""
        if not st.session_state.get('authenticated', False):
            return False
        
        session_start = st.session_state.get('session_start')
        if not session_start:
            return False
        
        try:
            start_time = datetime.fromisoformat(session_start)
            elapsed = datetime.utcnow() - start_time
            if elapsed > timedelta(hours=SessionManager.SESSION_TIMEOUT_HOURS):
                SessionManager.logout()
                return False
        except:
            return False
        
        return True
    
    @staticmethod
    def get_current_user() -> Optional[Dict[str, Any]]:
        """Get current logged in user"""
        if SessionManager.is_session_valid():
            return st.session_state.get('user_info')
        return None


class SimpleUserManager:
    """Simple user manager for session"""
    
    def get_current_user(self):
        return st.session_state.get('user_info')
    
    def is_authenticated(self):
        return st.session_state.get('authenticated', False)


# ============================================================================
# AZURE AD AUTHENTICATION
# ============================================================================

def exchange_code_for_token(code: str, client_id: str, client_secret: str, 
                           redirect_uri: str, tenant_id: str = "common") -> Optional[Dict]:
    """Exchange authorization code for access token"""
    import requests
    
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        'scope': 'openid profile email https://graph.microsoft.com/User.Read'
    }
    
    try:
        response = requests.post(token_url, data=token_data, timeout=10)
        
        if response.status_code != 200:
            error_data = response.json() if response.content else {}
            error_desc = error_data.get('error_description', f'HTTP {response.status_code}')
            
            st.error(f"❌ Authentication Failed")
            
            with st.expander("🔍 View Error Details", expanded=True):
                st.code(error_desc)
                
                if 'redirect_uri' in error_desc.lower():
                    st.warning(f"""
                    **Redirect URI Mismatch**
                    
                    The redirect_uri must match EXACTLY in Azure AD.
                    
                    Current redirect_uri: `{redirect_uri}`
                    """)
                
                elif 'unauthorized_client' in error_desc.lower():
                    st.warning("""
                    **Unauthorized Client**
                    
                    **Fix:**
                    - Go to Azure Portal → App registrations → Your App
                    - Change "Supported account types" to include the account type being used
                    """)
                
                elif 'client_secret' in error_desc.lower() or 'invalid_client' in error_desc.lower():
                    st.warning("""
                    **Invalid Client Secret**
                    
                    **Steps to fix:**
                    1. Go to Azure Portal → App Registrations → Your App
                    2. Go to Certificates & secrets
                    3. Create a new client secret
                    4. Update the secret in Streamlit secrets
                    """)
            
            return None
        
        return response.json()
        
    except requests.exceptions.Timeout:
        st.error("❌ Connection timeout - please try again")
        return None
    except requests.exceptions.ConnectionError:
        st.error("❌ Network connection error")
        return None
    except Exception as e:
        st.error(f"❌ Unexpected error: {str(e)}")
        return None


def get_user_info(access_token: str) -> Optional[Dict]:
    """Get user information from Microsoft Graph"""
    import requests
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get('https://graph.microsoft.com/v1.0/me', 
                              headers=headers, 
                              timeout=10)
        response.raise_for_status()
        
        user_data = response.json()
        
        return {
            'id': user_data.get('id'),
            'email': user_data.get('mail') or user_data.get('userPrincipalName'),
            'name': user_data.get('displayName'),
            'given_name': user_data.get('givenName'),
            'family_name': user_data.get('surname'),
            'job_title': user_data.get('jobTitle'),
            'department': user_data.get('department'),
            'office_location': user_data.get('officeLocation'),
            'auth_provider': 'azure_ad'
        }
        
    except Exception as e:
        st.error(f"❌ Error getting user info: {str(e)}")
        return None


def get_role_for_email(email: str) -> str:
    """
    Determine user role based on email address.
    Checks secrets for admin_emails list, or uses default rules.
    """
    if not email:
        return 'viewer'
    
    email_lower = email.lower()
    
    # Check secrets for explicit role mappings
    try:
        azure_config = st.secrets.get('azure_ad', {})
        
        # Super admin emails (comma-separated or list)
        super_admin_emails = azure_config.get('super_admin_emails', '')
        if isinstance(super_admin_emails, str):
            super_admin_emails = [e.strip().lower() for e in super_admin_emails.split(',') if e.strip()]
        else:
            super_admin_emails = [e.lower() for e in super_admin_emails]
        
        if email_lower in super_admin_emails:
            return 'super_admin'
        
        # Admin emails
        admin_emails = azure_config.get('admin_emails', '')
        if isinstance(admin_emails, str):
            admin_emails = [e.strip().lower() for e in admin_emails.split(',') if e.strip()]
        else:
            admin_emails = [e.lower() for e in admin_emails]
        
        if email_lower in admin_emails:
            return 'admin'
        
        # Security manager emails
        security_emails = azure_config.get('security_manager_emails', '')
        if isinstance(security_emails, str):
            security_emails = [e.strip().lower() for e in security_emails.split(',') if e.strip()]
        else:
            security_emails = [e.lower() for e in security_emails]
        
        if email_lower in security_emails:
            return 'security_manager'
        
        # FinOps analyst emails
        finops_emails = azure_config.get('finops_analyst_emails', '')
        if isinstance(finops_emails, str):
            finops_emails = [e.strip().lower() for e in finops_emails.split(',') if e.strip()]
        else:
            finops_emails = [e.lower() for e in finops_emails]
        
        if email_lower in finops_emails:
            return 'finops_analyst'
            
    except Exception as e:
        print(f"Error reading role config: {e}")
    
    # Default role-based rules (fallback)
    # Example: admin@company.com, ciso@company.com, etc.
    if any(prefix in email_lower for prefix in ['admin@', 'administrator@', 'superadmin@']):
        return 'super_admin'
    elif any(prefix in email_lower for prefix in ['security@', 'ciso@', 'secops@']):
        return 'security_manager'
    elif any(prefix in email_lower for prefix in ['finops@', 'cfo@', 'finance@', 'cost@']):
        return 'finops_analyst'
    elif any(prefix in email_lower for prefix in ['compliance@', 'audit@', 'grc@']):
        return 'compliance_viewer'
    
    # Default role for new users
    return 'viewer'


def get_auth_manager():
    """Get authentication manager singleton"""
    if 'auth_manager' not in st.session_state:
        st.session_state.auth_manager = SimpleUserManager()
    return st.session_state.auth_manager


# ============================================================================
# LOGIN PAGE
# ============================================================================

def render_login():
    """Render login page with Azure AD / Microsoft SSO"""
    
    # Check if already authenticated
    if st.session_state.get('authenticated', False):
        return
    
    # Get Azure AD config from secrets
    try:
        azure_config = st.secrets.get('azure_ad', {})
        client_id = azure_config.get('client_id', '')
        client_secret = azure_config.get('client_secret', '')
        tenant_id = azure_config.get('tenant_id', 'common')
        redirect_uri = azure_config.get('redirect_uri', '')
    except Exception as e:
        st.error("❌ Azure AD not configured. Please add azure_ad section to secrets.toml")
        st.stop()
        return
    
    if not client_id or not client_secret:
        st.error("❌ Azure AD credentials missing. Please configure azure_ad in secrets.toml")
        st.info("""
        **Required secrets.toml configuration:**
        ```toml
        [azure_ad]
        tenant_id = "your-tenant-id"
        client_id = "your-client-id"
        client_secret = "your-client-secret"
        redirect_uri = "https://your-app.streamlit.app"
        ```
        """)
        st.stop()
        return
    
    # Handle OAuth callback
    query_params = st.query_params
    
    if 'code' in query_params:
        # Exchange code for token
        with st.spinner("🔐 Signing in with Microsoft..."):
            code = query_params.get('code')
            
            token_response = exchange_code_for_token(
                code=code,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                tenant_id=tenant_id
            )
            
            if token_response and 'access_token' in token_response:
                user_info = get_user_info(token_response['access_token'])
                
                if user_info:
                    # Determine role based on email
                    email = user_info.get('email', '')
                    default_role = get_role_for_email(email)
                    
                    # Try to get/create user in Firebase
                    try:
                        from auth_database_firebase import get_database_manager
                        db_manager = get_database_manager()
                        
                        if db_manager:
                            user_id = user_info['id']
                            
                            # Check if user exists
                            try:
                                existing_user = db_manager.get_user(user_id)
                                is_new_user = not (existing_user and isinstance(existing_user, dict))
                            except:
                                is_new_user = True
                            
                            if is_new_user:
                                # New user - assign role based on email
                                user_info['role'] = default_role
                                user_info['is_active'] = True
                                db_manager.create_or_update_user(user_info)
                                final_user_info = user_info
                            else:
                                # Existing user - update info but preserve role from Firebase
                                update_data = {
                                    'id': user_info['id'],
                                    'email': user_info['email'],
                                    'name': user_info.get('name', ''),
                                    'given_name': user_info.get('given_name', ''),
                                    'family_name': user_info.get('family_name', '')
                                }
                                db_manager.create_or_update_user(update_data)
                                
                                # Load from Firebase to get actual role
                                final_user_info = db_manager.get_user(user_id) or user_info
                                
                                # If Firebase role is viewer but email warrants higher role, upgrade
                                firebase_role = final_user_info.get('role', 'viewer')
                                if firebase_role == 'viewer' and default_role != 'viewer':
                                    final_user_info['role'] = default_role
                                    db_manager.create_or_update_user(final_user_info)
                        else:
                            # No Firebase - use email-based role
                            user_info['role'] = default_role
                            final_user_info = user_info
                            
                    except ImportError:
                        # Firebase not available - use email-based role
                        user_info['role'] = default_role
                        final_user_info = user_info
                    except Exception as e:
                        print(f"Firebase error: {e}")
                        user_info['role'] = default_role
                        final_user_info = user_info
                    
                    # Set session state
                    SessionManager.login(final_user_info)
                    
                    # Clear query params and rerun
                    st.query_params.clear()
                    st.success(f"✅ Login successful! Role: {final_user_info.get('role', 'viewer')}")
                    st.rerun()
                else:
                    st.error("❌ Could not retrieve user information")
                    if st.button("🔄 Try Again"):
                        st.query_params.clear()
                        st.rerun()
            else:
                if st.button("🔄 Try Again"):
                    st.query_params.clear()
                    st.rerun()
    
    elif 'error' in query_params:
        error = query_params.get('error', 'unknown')
        error_desc = query_params.get('error_description', 'No description')
        
        st.error("❌ Authentication Error")
        st.warning(f"**Error:** {error}")
        st.info(error_desc)
        
        if st.button("🔄 Try Again"):
            st.query_params.clear()
            st.rerun()
    
    else:
        # Show login page
        from urllib.parse import quote
        
        # Build OAuth authorization URL
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        scopes = "openid profile email https://graph.microsoft.com/User.Read"
        
        auth_url = (
            f"{authority}/oauth2/v2.0/authorize?"
            f"client_id={client_id}&"
            f"response_type=code&"
            f"redirect_uri={quote(redirect_uri, safe='')}&"
            f"response_mode=query&"
            f"scope={quote(scopes)}&"
            f"prompt=select_account"
        )
        
        # Stunning, dynamic SSO login experience
        st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');
#MainMenu, header[data-testid="stHeader"], [data-testid="stSidebar"], [data-testid="stToolbar"]{display:none!important;}
.block-container{padding-top:0!important;max-width:100%!important;}
.stApp{background:#040a17;background-image:
 radial-gradient(closest-side at 15% 20%, rgba(34,211,238,.40), transparent 70%),
 radial-gradient(closest-side at 85% 15%, rgba(0,124,195,.45), transparent 70%),
 radial-gradient(closest-side at 25% 85%, rgba(20,184,166,.34), transparent 70%),
 radial-gradient(closest-side at 80% 82%, rgba(99,102,241,.40), transparent 70%);
 background-size:200% 200%,200% 200%,200% 200%,200% 200%;animation:ccaurora 20s ease-in-out infinite;}
@keyframes ccaurora{0%,100%{background-position:0% 0%,100% 0%,0% 100%,100% 100%;}50%{background-position:100% 50%,0% 50%,100% 0%,0% 100%;}}
.cc-orb{position:fixed;border-radius:50%;filter:blur(8px);opacity:.5;z-index:0;animation:ccfloat 14s ease-in-out infinite;}
.cc-orb.o1{width:140px;height:140px;top:14%;left:8%;background:radial-gradient(circle,#22D3EE,transparent);}
.cc-orb.o2{width:90px;height:90px;top:70%;left:14%;background:radial-gradient(circle,#14B8A6,transparent);animation-delay:-4s;}
.cc-orb.o3{width:160px;height:160px;top:20%;right:9%;background:radial-gradient(circle,#007CC3,transparent);animation-delay:-7s;}
@keyframes ccfloat{0%,100%{transform:translateY(0);}50%{transform:translateY(-28px);}}
.cc-wrap{position:relative;z-index:2;display:flex;flex-wrap:wrap;gap:2.5rem;align-items:center;justify-content:center;min-height:88vh;max-width:1180px;margin:0 auto;padding:2rem 1rem;font-family:'Inter',sans-serif;animation:ccrise .8s cubic-bezier(.2,.8,.2,1) both;}
@keyframes ccrise{from{opacity:0;transform:translateY(24px);}to{opacity:1;transform:none;}}
.cc-hero{flex:1 1 440px;max-width:560px;}
.cc-eyebrow{display:inline-flex;align-items:center;gap:6px;color:#67E8F9;font-weight:700;font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;padding:6px 13px;border:1px solid rgba(103,232,249,.35);border-radius:999px;background:rgba(103,232,249,.08);}
.cc-title{font-family:'Plus Jakarta Sans',sans-serif;font-weight:800;font-size:3.1rem;line-height:1.05;margin:1.1rem 0 .6rem;background:linear-gradient(90deg,#ffffff,#67E8F9,#5EEAD4,#ffffff);background-size:300% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:ccshimmer 7s linear infinite;}
@keyframes ccshimmer{to{background-position:300% 0;}}
.cc-sub{color:#cbd5e1;font-size:1.05rem;max-width:480px;line-height:1.6;}
.cc-chips{margin-top:1.4rem;display:flex;flex-wrap:wrap;gap:.5rem;}
.cc-chip{color:#e2e8f0;font-size:.82rem;font-weight:600;padding:7px 13px;border-radius:10px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);}
.cc-chip b{color:#67E8F9;}
.cc-stats{margin-top:1.8rem;display:flex;gap:2rem;flex-wrap:wrap;}
.cc-stat .n{font-family:'Plus Jakarta Sans',sans-serif;font-weight:800;font-size:1.35rem;color:#fff;}
.cc-stat .l{color:#94a3b8;font-size:.76rem;}
.cc-card{flex:0 0 380px;max-width:400px;background:rgba(255,255,255,.96);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.5);border-radius:22px;box-shadow:0 30px 70px rgba(2,8,23,.55);padding:2.2rem 2rem;text-align:center;}
.cc-brand{display:flex;align-items:center;justify-content:center;gap:8px;font-size:26px;font-weight:800;color:#007CC3;letter-spacing:-.5px;font-family:'Plus Jakarta Sans',sans-serif;}
.cc-brand .bar{width:4px;height:24px;background:linear-gradient(180deg,#007CC3,#5B2D8E);border-radius:2px;}
.cc-appname{margin-top:1rem;font-size:1.25rem;font-weight:700;color:#0F172A;font-family:'Plus Jakarta Sans',sans-serif;}
.cc-apptag{font-size:.85rem;color:#64748B;margin-top:.25rem;margin-bottom:1.5rem;}
.cc-signin{display:inline-flex;align-items:center;justify-content:center;gap:11px;width:100%;padding:13px 20px;color:#fff!important;text-decoration:none!important;font-size:.95rem;font-weight:600;border-radius:11px;background:linear-gradient(135deg,#0078D4,#005A9E);box-shadow:0 10px 24px rgba(0,120,212,.4);transition:transform .18s ease,box-shadow .18s ease,filter .18s ease;}
.cc-signin:hover{transform:translateY(-2px);box-shadow:0 14px 30px rgba(0,120,212,.5);filter:brightness(1.05);color:#fff!important;}
.cc-ms{width:18px;height:18px;}
.cc-secure{margin-top:1.3rem;font-size:.75rem;color:#94A3B8;display:flex;align-items:center;justify-content:center;gap:6px;}
.cc-foot{margin-top:.4rem;font-size:.68rem;color:#CBD5E1;letter-spacing:.12em;}
@media (max-width:820px){.cc-title{font-size:2.4rem;}.cc-wrap{min-height:auto;padding-top:3rem;}.cc-card{flex:1 1 320px;}}
</style>
<div class="cc-orb o1"></div><div class="cc-orb o2"></div><div class="cc-orb o3"></div>
""", unsafe_allow_html=True)

        st.markdown(f"""
<div class="cc-wrap">
<div class="cc-hero">
<span class="cc-eyebrow">◆ Infosys · Enterprise Cloud Governance</span>
<div class="cc-title">Cloud Compliance<br>Canvas</div>
<div class="cc-sub">Unify AWS compliance, security posture, guardrails and FinOps in one AI-powered control plane — from policy-as-code to automated remediation and cost intelligence.</div>
<div class="cc-chips">
<span class="cc-chip">🛡️ <b>Compliance</b></span>
<span class="cc-chip">💰 <b>FinOps</b></span>
<span class="cc-chip">🔒 <b>Security</b></span>
<span class="cc-chip">📜 <b>Guardrails</b></span>
<span class="cc-chip">⚡ <b>Remediation</b></span>
</div>
<div class="cc-stats">
<div class="cc-stat"><div class="n">Multi-Account</div><div class="l">AWS Organizations</div></div>
<div class="cc-stat"><div class="n">Policy-as-Code</div><div class="l">SCP &amp; guardrails</div></div>
<div class="cc-stat"><div class="n">AI-Powered</div><div class="l">Predictions &amp; fixes</div></div>
</div>
</div>
<div class="cc-card">
<div class="cc-brand"><div class="bar"></div>Infosys</div>
<div class="cc-appname">Cloud Compliance Canvas</div>
<div class="cc-apptag">Enterprise AWS Governance &amp; FinOps Platform</div>
<a href="{auth_url}" class="cc-signin" target="_self">
<svg class="cc-ms" viewBox="0 0 21 21"><rect width="10" height="10" fill="#F25022"/><rect x="11" width="10" height="10" fill="#7FBA00"/><rect y="11" width="10" height="10" fill="#00A4EF"/><rect x="11" y="11" width="10" height="10" fill="#FFB900"/></svg>
Sign in with Microsoft
</a>
<div class="cc-secure">🔒 Secured with Microsoft Entra ID · Role-based access</div>
<div class="cc-foot">ENTERPRISE CLOUD SOLUTIONS</div>
</div>
</div>
""", unsafe_allow_html=True)
        
        st.stop()


# ============================================================================
# USER MENU & ADMIN PANEL
# ============================================================================

def render_user_menu():
    """Render user menu in sidebar"""
    if not st.session_state.get('authenticated', False):
        return
    
    user_info = st.session_state.get('user_info', {})
    user_name = user_info.get('name', 'User')
    user_email = user_info.get('email', '')
    user_role = user_info.get('role', 'viewer')
    
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 User")
        
        # User info
        role_color = RoleManager.get_role_color(user_role)
        role_display = RoleManager.get_role_display_name(user_role)
        
        st.markdown(f"""
        <div style="padding: 10px; background: #f8f9fa; border-radius: 8px; margin-bottom: 10px;">
            <div style="font-weight: 600; color: #333;">{user_name}</div>
            <div style="font-size: 12px; color: #666;">{user_email}</div>
            <div style="margin-top: 8px;">
                <span style="background: {role_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">
                    {role_display}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Logout button
        if st.button("🚪 Logout", key="logout_btn", use_container_width=True):
            SessionManager.logout()
            st.rerun()


def render_admin_panel():
    """Render admin panel for user management"""
    if not st.session_state.get('authenticated', False):
        st.error("❌ Authentication required")
        return
    
    user_info = st.session_state.get('user_info', {})
    user_role = user_info.get('role', 'viewer')
    
    if user_role not in ['super_admin', 'admin']:
        st.error("❌ Admin access required")
        return
    
    st.markdown("## 👥 User Management")
    
    # Try to load users from Firebase
    try:
        from auth_database_firebase import get_database_manager
        db_manager = get_database_manager()
        
        if db_manager:
            users = db_manager.get_all_users() or []
            
            if users:
                st.markdown(f"**Total Users:** {len(users)}")
                
                for user in users:
                    with st.expander(f"👤 {user.get('name', 'Unknown')} ({user.get('email', 'N/A')})"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**ID:** {user.get('id', 'N/A')}")
                            st.write(f"**Email:** {user.get('email', 'N/A')}")
                            st.write(f"**Current Role:** {user.get('role', 'viewer')}")
                        
                        with col2:
                            # Role selector (only super_admin can change roles)
                            if user_role == 'super_admin':
                                new_role = st.selectbox(
                                    "Change Role",
                                    options=list(RoleManager.ROLES.keys()),
                                    index=list(RoleManager.ROLES.keys()).index(user.get('role', 'viewer')),
                                    key=f"role_{user.get('id')}"
                                )
                                
                                if st.button("Update Role", key=f"update_{user.get('id')}"):
                                    user['role'] = new_role
                                    db_manager.create_or_update_user(user)
                                    st.success(f"✅ Role updated to {new_role}")
                                    st.rerun()
            else:
                st.info("No users found in database")
        else:
            st.warning("⚠️ Firebase not configured. User management requires Firebase.")
            
    except ImportError:
        st.warning("⚠️ Firebase module not available. Install with: pip install firebase-admin")
    except Exception as e:
        st.error(f"❌ Error loading users: {str(e)}")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'UserRole',
    'RoleManager',
    'SessionManager',
    'SimpleUserManager',
    'ROLE_PERMISSIONS',
    'TAB_ACCESS',
    'check_tab_access',
    'require_permission',
    'require_role',
    'render_login',
    'render_user_menu',
    'render_admin_panel',
    'get_auth_manager',
]
