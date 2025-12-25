"""
AWS Connector Module - Enhanced with AssumeRole Support
Handles AWS authentication, session management, and role assumption
Version: 4.0.0 - Enterprise AssumeRole Edition

Copied from working WAF Scanner application
"""

import streamlit as st
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass
import os
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AWSCredentials:
    """AWS Credentials container"""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    source: str = "manual"

@dataclass
class AssumedRoleCredentials:
    """Temporary credentials from AssumeRole"""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: str
    assumed_role_arn: str
    region: str = "us-east-1"

# ============================================================================
# CREDENTIAL HELPERS
# ============================================================================

def get_aws_credentials_from_secrets() -> Tuple[Optional[AWSCredentials], str]:
    """
    Get AWS credentials from Streamlit secrets.
    Returns tuple of (credentials, debug_info)
    """
    debug_info = []
    
    try:
        if hasattr(st, 'secrets'):
            debug_info.append(f"Secrets keys: {list(st.secrets.keys())}")
            
            # FORMAT 1: [aws] section
            if 'aws' in st.secrets:
                aws_secrets = dict(st.secrets['aws'])
                debug_info.append(f"[aws] keys: {list(aws_secrets.keys())}")
                
                access_key = (
                    aws_secrets.get('access_key_id') or 
                    aws_secrets.get('ACCESS_KEY_ID') or
                    aws_secrets.get('aws_access_key_id') or
                    aws_secrets.get('AWS_ACCESS_KEY_ID') or
                    aws_secrets.get('management_access_key_id') or
                    aws_secrets.get('MANAGEMENT_ACCESS_KEY_ID')
                )
                secret_key = (
                    aws_secrets.get('secret_access_key') or 
                    aws_secrets.get('SECRET_ACCESS_KEY') or
                    aws_secrets.get('aws_secret_access_key') or
                    aws_secrets.get('AWS_SECRET_ACCESS_KEY') or
                    aws_secrets.get('management_secret_access_key') or
                    aws_secrets.get('MANAGEMENT_SECRET_ACCESS_KEY')
                )
                region = (
                    aws_secrets.get('default_region') or 
                    aws_secrets.get('region') or 
                    aws_secrets.get('AWS_REGION') or
                    'us-east-1'
                )
                
                # Check for role assumption configuration
                role_arn = (
                    aws_secrets.get('role_arn') or
                    aws_secrets.get('ROLE_ARN') or
                    aws_secrets.get('assume_role_arn')
                )
                external_id = (
                    aws_secrets.get('external_id') or
                    aws_secrets.get('EXTERNAL_ID')
                )
                
                if access_key and secret_key:
                    debug_info.append("SUCCESS: Found credentials in [aws] section")
                    debug_info.append(f"Role ARN: {role_arn}" if role_arn else "No role ARN configured")
                    debug_info.append(f"External ID: {'configured' if external_id else 'not configured'}")
                    return AWSCredentials(
                        access_key_id=access_key.strip() if access_key else access_key,
                        secret_access_key=secret_key.strip() if secret_key else secret_key,
                        region=region.strip() if region else 'us-east-1',
                        role_arn=role_arn.strip() if role_arn else None,
                        external_id=external_id.strip() if external_id else None,
                        source="secrets"
                    ), "\n".join(debug_info)
            
            # FORMAT 2: Flat AWS_ keys
            access_key = st.secrets.get('AWS_ACCESS_KEY_ID')
            secret_key = st.secrets.get('AWS_SECRET_ACCESS_KEY')
            if access_key and secret_key:
                return AWSCredentials(
                    access_key_id=access_key.strip(),
                    secret_access_key=secret_key.strip(),
                    region=st.secrets.get('AWS_REGION', 'us-east-1'),
                    role_arn=st.secrets.get('AWS_ROLE_ARN'),
                    external_id=st.secrets.get('AWS_EXTERNAL_ID'),
                    source="secrets"
                ), "Found flat AWS_ keys"
                
    except Exception as e:
        debug_info.append(f"Error: {e}")
    
    return None, "\n".join(debug_info) if debug_info else "No secrets"

def assume_role(
    base_session,
    role_arn: str,
    external_id: Optional[str] = None,
    session_name: Optional[str] = "ComplianceCanvasSession",
    duration_seconds: int = 3600
) -> Optional[AssumedRoleCredentials]:
    """
    Assume an IAM role and return temporary credentials.
    
    Args:
        base_session: Boto3 session with base credentials
        role_arn: ARN of the role to assume
        external_id: External ID for added security (optional but recommended)
        session_name: Name for the assumed role session
        duration_seconds: Duration of temporary credentials (default 1 hour)
    
    Returns:
        AssumedRoleCredentials if successful, None otherwise
    """
    try:
        sts = base_session.client('sts')
        
        # Prepare AssumeRole request
        assume_role_params = {
            'RoleArn': role_arn,
            'RoleSessionName': session_name,
            'DurationSeconds': duration_seconds
        }
        
        # Add external ID if provided (recommended for cross-account access)
        if external_id:
            assume_role_params['ExternalId'] = external_id
        
        print(f"🔄 Assuming role: {role_arn}")
        if external_id:
            print(f"   With external ID: {external_id[:8]}...")
        
        # Assume the role
        response = sts.assume_role(**assume_role_params)
        
        # Extract temporary credentials
        credentials = response['Credentials']
        
        print(f"✅ Successfully assumed role: {role_arn}")
        
        return AssumedRoleCredentials(
            access_key_id=credentials['AccessKeyId'],
            secret_access_key=credentials['SecretAccessKey'],
            session_token=credentials['SessionToken'],
            expiration=credentials['Expiration'].isoformat(),
            assumed_role_arn=role_arn,
            region=base_session.region_name or 'us-east-1'
        )
        
    except Exception as e:
        logger.error(f"Failed to assume role {role_arn}: {e}")
        print(f"❌ Failed to assume role: {str(e)}")
        return None

def get_aws_session(credentials: Optional[AWSCredentials] = None, force_refresh: bool = False):
    """
    Create boto3 session from credentials.
    If credentials not provided, tries to get from multiple sources.
    Supports AssumeRole for enhanced security.
    
    Args:
        credentials: Optional AWSCredentials object
        force_refresh: If True, bypass any cached session
    """
    try:
        import boto3
        from botocore.config import Config
        
        # If no credentials provided, try to get them
        if credentials is None:
            # Priority order:
            # 1. Session state (from manual entry or assumed role)
            # 2. Streamlit secrets
            # 3. Environment variables
            # 4. AWS CLI config
            # 5. IAM role (for EC2/ECS/Lambda)
            
            # Check if we have assumed role credentials in session state (and not forcing refresh)
            if not force_refresh and 'assumed_role_credentials' in st.session_state:
                assumed_creds = st.session_state.assumed_role_credentials
                session = boto3.Session(
                    aws_access_key_id=assumed_creds.access_key_id,
                    aws_secret_access_key=assumed_creds.secret_access_key,
                    aws_session_token=assumed_creds.session_token,
                    region_name=assumed_creds.region
                )
                return session
            
            # Try session state first (manual entry)
            if ('aws_access_key' in st.session_state and 
                'aws_secret_key' in st.session_state):
                
                base_session = boto3.Session(
                    aws_access_key_id=st.session_state.aws_access_key,
                    aws_secret_access_key=st.session_state.aws_secret_key,
                    region_name=st.session_state.get('aws_region', 'us-east-1')
                )
                
                # Check if role assumption is configured
                if 'aws_role_arn' in st.session_state and st.session_state.aws_role_arn:
                    assumed_creds = assume_role(
                        base_session,
                        st.session_state.aws_role_arn,
                        st.session_state.get('aws_external_id'),
                        session_name="ComplianceCanvasSession"
                    )
                    if assumed_creds:
                        st.session_state.assumed_role_credentials = assumed_creds
                        session = boto3.Session(
                            aws_access_key_id=assumed_creds.access_key_id,
                            aws_secret_access_key=assumed_creds.secret_access_key,
                            aws_session_token=assumed_creds.session_token,
                            region_name=assumed_creds.region
                        )
                        return session
                
                return base_session
            
            # Try Streamlit secrets
            creds, debug = get_aws_credentials_from_secrets()
            print(f"🔍 Credential lookup:\n{debug}")
            
            if creds:
                base_session = boto3.Session(
                    aws_access_key_id=creds.access_key_id,
                    aws_secret_access_key=creds.secret_access_key,
                    aws_session_token=creds.session_token,
                    region_name=creds.region
                )
                
                # Verify base credentials first
                try:
                    sts = base_session.client('sts')
                    identity = sts.get_caller_identity()
                    print(f"✅ Base credentials valid - Account: {identity['Account']}, User: {identity['Arn'].split('/')[-1]}")
                except Exception as e:
                    print(f"❌ Base credentials invalid: {e}")
                    return None
                
                # Check if role assumption is configured in secrets
                if creds.role_arn:
                    assumed_creds = assume_role(
                        base_session,
                        creds.role_arn,
                        creds.external_id,
                        session_name="ComplianceCanvasSession"
                    )
                    if assumed_creds:
                        st.session_state.assumed_role_credentials = assumed_creds
                        session = boto3.Session(
                            aws_access_key_id=assumed_creds.access_key_id,
                            aws_secret_access_key=assumed_creds.secret_access_key,
                            aws_session_token=assumed_creds.session_token,
                            region_name=assumed_creds.region
                        )
                        
                        # Verify assumed role
                        try:
                            sts = session.client('sts')
                            identity = sts.get_caller_identity()
                            print(f"✅ Assumed role identity: {identity['Arn']}")
                        except Exception as e:
                            print(f"⚠️ Could not verify assumed role: {e}")
                        
                        return session
                    else:
                        print("⚠️ Role assumption failed, using base credentials")
                
                return base_session
            
            # Try default boto3 credential chain (env vars, CLI, IAM role)
            try:
                session = boto3.Session()
                # Test if credentials are available
                sts = session.client('sts')
                sts.get_caller_identity()
                return session
            except:
                pass
            
            return None
        
        # Credentials provided, use them
        base_session = boto3.Session(
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=credentials.region
        )
        
        # Check if role assumption is requested
        if credentials.role_arn:
            assumed_creds = assume_role(
                base_session,
                credentials.role_arn,
                credentials.external_id,
                session_name="ComplianceCanvasSession"
            )
            if assumed_creds:
                session = boto3.Session(
                    aws_access_key_id=assumed_creds.access_key_id,
                    aws_secret_access_key=assumed_creds.secret_access_key,
                    aws_session_token=assumed_creds.session_token,
                    region_name=assumed_creds.region
                )
                return session
        
        return base_session
        
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        print(f"❌ Failed to create session: {e}")
        return None

@st.cache_data(ttl=60)  # Cache for 1 minute
def test_aws_connection(_session) -> Tuple[bool, str, Dict]:
    """Test AWS connection and return identity info"""
    try:
        from botocore.config import Config
        config = Config(connect_timeout=10, read_timeout=30)
        
        sts = _session.client('sts', config=config)
        identity = sts.get_caller_identity()
        
        return True, f"Connected as {identity['Arn']}", {
            'account': identity['Account'],
            'arn': identity['Arn'],
            'user_id': identity['UserId']
        }
    except Exception as e:
        return False, str(e), {}


def get_aws_client(service_name: str, session=None, region_name: str = None):
    """
    Get an AWS client for a specific service.
    Uses the session from get_aws_session() if not provided.
    """
    if session is None:
        session = get_aws_session()
    
    if session is None:
        return None
    
    try:
        if region_name:
            return session.client(service_name, region_name=region_name)
        return session.client(service_name)
    except Exception as e:
        logger.error(f"Failed to create {service_name} client: {e}")
        return None
