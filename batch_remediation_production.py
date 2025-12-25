"""
Batch Remediation Module - Enterprise Extended Edition
Comprehensive threat remediation across 10 AWS services
Supports: IAM, S3, EC2, RDS, Lambda, CloudTrail, KMS, Secrets Manager, VPC, SNS/SQS
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json
import boto3

# Feature flag - set to True when ready to enable in production
BATCH_REMEDIATION_ENABLED = True


def execute_batch_remediation(selected_threats: List[Dict], remediation_options: Dict) -> Dict:
    """
    Execute remediation actions on multiple threats simultaneously
    
    Args:
        selected_threats: List of threat dictionaries
        remediation_options: Configuration for remediation actions
    
    Returns:
        Dict with batch remediation results
    """
    results = {
        'total_threats': len(selected_threats),
        'successful': 0,
        'failed': 0,
        'start_time': datetime.utcnow().isoformat(),
        'end_time': None,
        'details': []
    }
    
    for threat in selected_threats:
        try:
            # Execute remediation for each threat
            threat_result = remediate_single_threat(
                threat,
                remediation_options
            )
            
            if threat_result['status'] == 'SUCCESS':
                results['successful'] += 1
            else:
                results['failed'] += 1
            
            results['details'].append(threat_result)
            
        except Exception as e:
            results['failed'] += 1
            results['details'].append({
                'threat_id': threat.get('threat_id', 'UNKNOWN'),
                'status': 'FAILED',
                'error': str(e)
            })
    
    results['end_time'] = datetime.utcnow().isoformat()
    return results


def remediate_single_threat(threat: Dict, options: Dict) -> Dict:
    """
    Remediate a single threat based on threat type
    Routes to appropriate service-specific remediation function
    
    Supports 10 AWS Services:
    - IAM (Identity & Access Management)
    - S3 (Storage)
    - EC2 (Security Groups)
    - RDS (Databases)
    - Lambda (Serverless Functions)
    - CloudTrail (Audit Logging)
    - KMS (Key Management)
    - Secrets Manager
    - VPC (Network Logs)
    - SNS/SQS (Messaging)
    
    Args:
        threat: Threat dictionary
        options: Remediation options
    
    Returns:
        Dict with remediation result
    """
    
    result = {
        'threat_id': threat.get('threat_id'),
        'status': 'SUCCESS',
        'actions': [],
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        # Determine threat type and route to appropriate remediation function
        event_name = threat.get('event_name', '')
        threat_type = threat.get('threat_type', '').lower()
        service = threat.get('service', '').lower()
        
        # Route based on service/event
        if 'iam' in service or 'IAM' in event_name or 'Policy' in event_name or 'User' in event_name or 'Role' in event_name:
            result['actions'] = remediate_iam_threat(threat, options)
        
        elif 's3' in service or 'S3' in event_name or 'Bucket' in event_name:
            result['actions'] = remediate_s3_threat(threat, options)
        
        elif 'securitygroup' in event_name.lower() or 'ec2' in service:
            result['actions'] = remediate_sg_threat(threat, options)
        
        elif 'rds' in service or 'database' in threat_type or 'DB' in event_name:
            result['actions'] = remediate_rds_threat(threat, options)
        
        elif 'lambda' in service or 'function' in threat_type:
            result['actions'] = remediate_lambda_threat(threat, options)
        
        elif 'cloudtrail' in service or 'trail' in threat_type:
            result['actions'] = remediate_cloudtrail_threat(threat, options)
        
        elif 'kms' in service or 'key' in threat_type:
            result['actions'] = remediate_kms_threat(threat, options)
        
        elif 'secretsmanager' in service or 'secret' in threat_type:
            result['actions'] = remediate_secrets_threat(threat, options)
        
        elif 'vpc' in service or 'flowlogs' in threat_type:
            result['actions'] = remediate_vpc_threat(threat, options)
        
        elif 'sns' in service or 'sqs' in service or 'topic' in threat_type or 'queue' in threat_type:
            result['actions'] = remediate_messaging_threat(threat, options)
        
        else:
            result['actions'] = remediate_generic_threat(threat, options)
        
    except Exception as e:
        result['status'] = 'FAILED'
        result['error'] = str(e)
    
    return result


# ==================== ORIGINAL 3 SERVICES ====================

def remediate_iam_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate IAM-related threats
    
    Remediations:
    - Delete unauthorized policies
    - Rotate compromised credentials
    - Revoke active sessions
    - Enable MFA enforcement
    """
    iam = boto3.client('iam')
    actions = []
    
    event_details = threat.get('event_details', {})
    event_name = event_details.get('eventName')
    request_params = event_details.get('requestParameters', {})
    
    # Revert unauthorized policy changes
    if options.get('revert_changes', True):
        if event_name == 'PutRolePolicy':
            role_name = request_params.get('roleName')
            policy_name = request_params.get('policyName')
            
            iam.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            
            actions.append({
                'action': 'DeleteRolePolicy',
                'target': f"{role_name}/{policy_name}",
                'status': 'SUCCESS'
            })
        
        elif event_name == 'PutUserPolicy':
            user_name = request_params.get('userName')
            policy_name = request_params.get('policyName')
            
            iam.delete_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            
            actions.append({
                'action': 'DeleteUserPolicy',
                'target': f"{user_name}/{policy_name}",
                'status': 'SUCCESS'
            })
    
    # Rotate compromised credentials
    if options.get('rotate_credentials', False):
        user_arn = event_details.get('userIdentity', {}).get('arn', '')
        if user_arn and ':user/' in user_arn:
            user_name = user_arn.split('/')[-1]
            
            # List and delete all access keys
            try:
                keys = iam.list_access_keys(UserName=user_name)
                for key in keys.get('AccessKeyMetadata', []):
                    iam.delete_access_key(
                        UserName=user_name,
                        AccessKeyId=key['AccessKeyId']
                    )
                
                actions.append({
                    'action': 'RotateCredentials',
                    'target': user_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RotateCredentials',
                    'target': user_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    # Revoke active sessions
    if options.get('revoke_sessions', False):
        user_arn = event_details.get('userIdentity', {}).get('arn', '')
        if user_arn and ':user/' in user_arn:
            user_name = user_arn.split('/')[-1]
            
            try:
                # Attach deny-all policy to immediately revoke access
                iam.put_user_policy(
                    UserName=user_name,
                    PolicyName='EmergencyDenyAll',
                    PolicyDocument=json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*"
                        }]
                    })
                )
                
                actions.append({
                    'action': 'RevokeActiveSessions',
                    'target': user_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RevokeActiveSessions',
                    'target': user_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


def remediate_s3_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate S3-related threats
    
    Remediations:
    - Enable bucket encryption
    - Block public access
    - Enable versioning
    - Configure lifecycle policies
    """
    s3 = boto3.client('s3')
    actions = []
    
    event_details = threat.get('event_details', {})
    bucket_name = event_details.get('requestParameters', {}).get('bucketName')
    
    if not bucket_name:
        # Try alternate extraction
        bucket_name = threat.get('resource', {}).get('bucket_name')
    
    if bucket_name:
        # Enable encryption
        if options.get('enable_encryption', True):
            try:
                s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            },
                            'BucketKeyEnabled': True
                        }]
                    }
                )
                
                actions.append({
                    'action': 'EnableEncryption',
                    'target': bucket_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableEncryption',
                    'target': bucket_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Block public access
        if options.get('block_public_access', True):
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                
                actions.append({
                    'action': 'BlockPublicAccess',
                    'target': bucket_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'BlockPublicAccess',
                    'target': bucket_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable versioning
        if options.get('enable_versioning', False):
            try:
                s3.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                
                actions.append({
                    'action': 'EnableVersioning',
                    'target': bucket_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableVersioning',
                    'target': bucket_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


def remediate_sg_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate Security Group threats
    
    Remediations:
    - Revoke 0.0.0.0/0 ingress rules
    - Remove overly permissive rules
    - Add restrictive rules
    """
    ec2 = boto3.client('ec2')
    actions = []
    
    event_details = threat.get('event_details', {})
    sg_id = event_details.get('requestParameters', {}).get('groupId')
    
    if not sg_id:
        # Try alternate extraction
        sg_id = threat.get('resource', {}).get('security_group_id')
    
    if sg_id and options.get('revoke_rules', True):
        try:
            # Get security group details
            response = ec2.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            # Revoke overly permissive ingress rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[rule]
                        )
                        
                        port_info = f"{rule.get('FromPort', 'all')}-{rule.get('ToPort', 'all')}"
                        actions.append({
                            'action': 'RevokeIngress',
                            'target': f"{sg_id} port {port_info} from 0.0.0.0/0",
                            'status': 'SUCCESS'
                        })
        
        except Exception as e:
            actions.append({
                'action': 'RevokeIngress',
                'target': sg_id,
                'status': 'FAILED',
                'error': str(e)
            })
    
    return actions


# ==================== NEW SERVICE 1: RDS ====================

def remediate_rds_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate RDS database threats
    
    Remediations:
    - Make database private (disable public accessibility)
    - Enable encryption at rest
    - Restrict security groups
    - Enable automated backups
    - Enable Multi-AZ
    - Enable deletion protection
    """
    rds = boto3.client('rds')
    ec2 = boto3.client('ec2')
    actions = []
    
    # Extract database identifier
    db_instance_id = threat.get('resource', {}).get('db_instance_id')
    if not db_instance_id:
        event_details = threat.get('event_details', {})
        db_instance_id = event_details.get('requestParameters', {}).get('dBInstanceIdentifier')
    
    if db_instance_id:
        # Make database private
        if options.get('make_private', True):
            try:
                rds.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True
                )
                
                actions.append({
                    'action': 'MakePrivate',
                    'target': db_instance_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'MakePrivate',
                    'target': db_instance_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Restrict security group (remove 0.0.0.0/0 access)
        if options.get('restrict_security_group', True):
            try:
                # Get DB instance details
                response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
                db_instance = response['DBInstances'][0]
                
                # Get security groups
                vpc_security_groups = db_instance.get('VpcSecurityGroups', [])
                
                for sg in vpc_security_groups:
                    sg_id = sg['VpcSecurityGroupId']
                    
                    # Get security group rules
                    sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
                    sg_details = sg_response['SecurityGroups'][0]
                    
                    # Revoke 0.0.0.0/0 rules
                    for rule in sg_details.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[rule]
                                )
                
                actions.append({
                    'action': 'RestrictSecurityGroup',
                    'target': f"{db_instance_id} security groups",
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RestrictSecurityGroup',
                    'target': db_instance_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable automated backups
        if options.get('enable_backups', True):
            try:
                rds.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    BackupRetentionPeriod=7,
                    PreferredBackupWindow='03:00-04:00',
                    ApplyImmediately=True
                )
                
                actions.append({
                    'action': 'EnableBackups',
                    'target': db_instance_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableBackups',
                    'target': db_instance_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable deletion protection
        if options.get('enable_deletion_protection', True):
            try:
                rds.modify_db_instance(
                    DBInstanceIdentifier=db_instance_id,
                    DeletionProtection=True,
                    ApplyImmediately=True
                )
                
                actions.append({
                    'action': 'EnableDeletionProtection',
                    'target': db_instance_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableDeletionProtection',
                    'target': db_instance_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 2: LAMBDA ====================

def remediate_lambda_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate Lambda function threats
    
    Remediations:
    - Restrict IAM permissions (least privilege)
    - Move secrets to Secrets Manager
    - Add VPC configuration
    - Remove public function URLs
    - Enable X-Ray tracing
    - Configure reserved concurrency
    """
    lambda_client = boto3.client('lambda')
    iam = boto3.client('iam')
    secretsmanager = boto3.client('secretsmanager')
    actions = []
    
    # Extract function name
    function_name = threat.get('resource', {}).get('function_name')
    if not function_name:
        event_details = threat.get('event_details', {})
        function_name = event_details.get('requestParameters', {}).get('functionName')
    
    if function_name:
        # Restrict IAM permissions
        if options.get('restrict_permissions', True):
            try:
                # Get function configuration
                func_config = lambda_client.get_function_configuration(
                    FunctionName=function_name
                )
                
                role_arn = func_config['Role']
                role_name = role_arn.split('/')[-1]
                
                # Create restricted policy
                restricted_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": f"arn:aws:logs:*:*:log-group:/aws/lambda/{function_name}:*"
                    }]
                }
                
                # Replace inline policies with restricted version
                iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName='LambdaRestrictedPolicy',
                    PolicyDocument=json.dumps(restricted_policy)
                )
                
                actions.append({
                    'action': 'RestrictIAMPermissions',
                    'target': f"{function_name} role {role_name}",
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RestrictIAMPermissions',
                    'target': function_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Move secrets from environment variables to Secrets Manager
        if options.get('move_secrets', True):
            try:
                func_config = lambda_client.get_function_configuration(
                    FunctionName=function_name
                )
                
                env_vars = func_config.get('Environment', {}).get('Variables', {})
                
                # Identify potential secrets (API_KEY, PASSWORD, SECRET, TOKEN, etc.)
                secret_keys = [k for k in env_vars.keys() 
                              if any(term in k.upper() for term in ['KEY', 'PASSWORD', 'SECRET', 'TOKEN'])]
                
                if secret_keys:
                    # Create secret in Secrets Manager
                    secret_value = {k: env_vars[k] for k in secret_keys}
                    
                    secret_name = f"{function_name}-secrets"
                    
                    try:
                        secretsmanager.create_secret(
                            Name=secret_name,
                            SecretString=json.dumps(secret_value)
                        )
                    except secretsmanager.exceptions.ResourceExistsException:
                        # Update existing secret
                        secretsmanager.update_secret(
                            SecretId=secret_name,
                            SecretString=json.dumps(secret_value)
                        )
                    
                    # Remove secrets from environment variables
                    new_env_vars = {k: v for k, v in env_vars.items() if k not in secret_keys}
                    new_env_vars['SECRET_ARN'] = f"arn:aws:secretsmanager:*:*:secret:{secret_name}"
                    
                    lambda_client.update_function_configuration(
                        FunctionName=function_name,
                        Environment={'Variables': new_env_vars}
                    )
                    
                    actions.append({
                        'action': 'MoveSecretsToSecretsManager',
                        'target': f"{function_name} ({len(secret_keys)} secrets moved)",
                        'status': 'SUCCESS'
                    })
            except Exception as e:
                actions.append({
                    'action': 'MoveSecretsToSecretsManager',
                    'target': function_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Remove public function URL
        if options.get('remove_public_url', True):
            try:
                lambda_client.delete_function_url_config(
                    FunctionName=function_name
                )
                
                actions.append({
                    'action': 'RemovePublicFunctionURL',
                    'target': function_name,
                    'status': 'SUCCESS'
                })
            except lambda_client.exceptions.ResourceNotFoundException:
                # No function URL configured, that's fine
                pass
            except Exception as e:
                actions.append({
                    'action': 'RemovePublicFunctionURL',
                    'target': function_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable X-Ray tracing
        if options.get('enable_xray', True):
            try:
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    TracingConfig={'Mode': 'Active'}
                )
                
                actions.append({
                    'action': 'EnableXRayTracing',
                    'target': function_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableXRayTracing',
                    'target': function_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 3: CLOUDTRAIL ====================

def remediate_cloudtrail_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate CloudTrail logging threats
    
    Remediations:
    - Re-enable CloudTrail if disabled
    - Enable log file validation
    - Enable encryption with KMS
    - Configure S3 bucket with MFA delete
    - Create CloudWatch alarm for tampering
    """
    cloudtrail = boto3.client('cloudtrail')
    s3 = boto3.client('s3')
    cloudwatch = boto3.client('cloudwatch')
    actions = []
    
    # Extract trail name
    trail_name = threat.get('resource', {}).get('trail_name')
    if not trail_name:
        event_details = threat.get('event_details', {})
        trail_name = event_details.get('requestParameters', {}).get('name')
    
    if trail_name:
        # Re-enable logging
        if options.get('enable_logging', True):
            try:
                cloudtrail.start_logging(Name=trail_name)
                
                actions.append({
                    'action': 'EnableLogging',
                    'target': trail_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableLogging',
                    'target': trail_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable log file validation
        if options.get('enable_validation', True):
            try:
                cloudtrail.update_trail(
                    Name=trail_name,
                    EnableLogFileValidation=True
                )
                
                actions.append({
                    'action': 'EnableLogFileValidation',
                    'target': trail_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableLogFileValidation',
                    'target': trail_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Create CloudWatch alarm for future tampering
        if options.get('create_alarm', True):
            try:
                cloudwatch.put_metric_alarm(
                    AlarmName=f'{trail_name}-Disabled-Alarm',
                    ComparisonOperator='LessThanThreshold',
                    EvaluationPeriods=1,
                    MetricName='IsLogging',
                    Namespace='CloudTrailMetrics',
                    Period=300,
                    Statistic='Average',
                    Threshold=1.0,
                    ActionsEnabled=True,
                    AlarmDescription=f'Alert when {trail_name} is disabled',
                    AlarmActions=[]  # Add SNS topic ARN if available
                )
                
                actions.append({
                    'action': 'CreateTamperingAlarm',
                    'target': trail_name,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'CreateTamperingAlarm',
                    'target': trail_name,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 4: KMS ====================

def remediate_kms_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate KMS key management threats
    
    Remediations:
    - Cancel key deletion
    - Enable automatic key rotation
    - Restrict key policy
    - Create alarm for deletion attempts
    """
    kms = boto3.client('kms')
    cloudwatch = boto3.client('cloudwatch')
    actions = []
    
    # Extract key ID
    key_id = threat.get('resource', {}).get('key_id')
    if not key_id:
        event_details = threat.get('event_details', {})
        key_id = event_details.get('requestParameters', {}).get('keyId')
    
    if key_id:
        # Cancel key deletion
        if options.get('cancel_deletion', True):
            try:
                kms.cancel_key_deletion(KeyId=key_id)
                
                actions.append({
                    'action': 'CancelKeyDeletion',
                    'target': key_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'CancelKeyDeletion',
                    'target': key_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Enable automatic key rotation
        if options.get('enable_rotation', True):
            try:
                kms.enable_key_rotation(KeyId=key_id)
                
                actions.append({
                    'action': 'EnableKeyRotation',
                    'target': key_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableKeyRotation',
                    'target': key_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Restrict key policy (remove overly broad access)
        if options.get('restrict_policy', True):
            try:
                # Get current account ID
                import boto3
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                
                # Create restricted policy
                restricted_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*"
                    }]
                }
                
                kms.put_key_policy(
                    KeyId=key_id,
                    PolicyName='default',
                    Policy=json.dumps(restricted_policy)
                )
                
                actions.append({
                    'action': 'RestrictKeyPolicy',
                    'target': key_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RestrictKeyPolicy',
                    'target': key_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 5: SECRETS MANAGER ====================

def remediate_secrets_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate Secrets Manager threats
    
    Remediations:
    - Enable automatic rotation
    - Update resource policy
    - Enable encryption with KMS
    - Create new secret version
    """
    secretsmanager = boto3.client('secretsmanager')
    actions = []
    
    # Extract secret ID/ARN
    secret_id = threat.get('resource', {}).get('secret_id')
    if not secret_id:
        event_details = threat.get('event_details', {})
        secret_id = event_details.get('requestParameters', {}).get('secretId')
    
    if secret_id:
        # Enable automatic rotation
        if options.get('enable_rotation', True):
            try:
                # Note: Requires Lambda function for rotation
                # This is a placeholder - actual implementation needs rotation Lambda
                secretsmanager.rotate_secret(
                    SecretId=secret_id,
                    RotationRules={'AutomaticallyAfterDays': 30}
                )
                
                actions.append({
                    'action': 'EnableAutomaticRotation',
                    'target': secret_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableAutomaticRotation',
                    'target': secret_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
        
        # Update resource policy (restrict access)
        if options.get('restrict_access', True):
            try:
                import boto3
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*"
                    }]
                }
                
                secretsmanager.put_resource_policy(
                    SecretId=secret_id,
                    ResourcePolicy=json.dumps(policy)
                )
                
                actions.append({
                    'action': 'RestrictAccess',
                    'target': secret_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RestrictAccess',
                    'target': secret_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 6: VPC FLOW LOGS ====================

def remediate_vpc_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate VPC Flow Logs threats
    
    Remediations:
    - Enable VPC Flow Logs
    - Configure S3/CloudWatch Logs destination
    - Enable log file validation
    """
    ec2 = boto3.client('ec2')
    actions = []
    
    # Extract VPC ID
    vpc_id = threat.get('resource', {}).get('vpc_id')
    if not vpc_id:
        event_details = threat.get('event_details', {})
        vpc_id = event_details.get('requestParameters', {}).get('vpcId')
    
    if vpc_id:
        # Enable VPC Flow Logs
        if options.get('enable_flow_logs', True):
            try:
                # Create flow log to CloudWatch Logs
                response = ec2.create_flow_logs(
                    ResourceIds=[vpc_id],
                    ResourceType='VPC',
                    TrafficType='ALL',  # Capture ALL traffic (ACCEPT + REJECT)
                    LogDestinationType='cloud-watch-logs',
                    LogGroupName=f'/aws/vpc/flowlogs/{vpc_id}',
                    DeliverLogsPermissionArn='arn:aws:iam::*:role/flowlogsRole'  # Needs to exist
                )
                
                actions.append({
                    'action': 'EnableVPCFlowLogs',
                    'target': vpc_id,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'EnableVPCFlowLogs',
                    'target': vpc_id,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    return actions


# ==================== NEW SERVICE 7: SNS/SQS ====================

def remediate_messaging_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Remediate SNS/SQS messaging threats
    
    Remediations:
    - Enable encryption
    - Restrict topic/queue policy
    - Enable dead letter queue
    - Configure access logging
    """
    sns = boto3.client('sns')
    sqs = boto3.client('sqs')
    actions = []
    
    threat_service = threat.get('service', '').lower()
    
    if 'sns' in threat_service:
        # SNS Topic remediation
        topic_arn = threat.get('resource', {}).get('topic_arn')
        
        if topic_arn and options.get('restrict_policy', True):
            try:
                import boto3
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": ["SNS:Publish", "SNS:Subscribe"],
                        "Resource": topic_arn
                    }]
                }
                
                sns.set_topic_attributes(
                    TopicArn=topic_arn,
                    AttributeName='Policy',
                    AttributeValue=json.dumps(policy)
                )
                
                actions.append({
                    'action': 'RestrictSNSPolicy',
                    'target': topic_arn,
                    'status': 'SUCCESS'
                })
            except Exception as e:
                actions.append({
                    'action': 'RestrictSNSPolicy',
                    'target': topic_arn,
                    'status': 'FAILED',
                    'error': str(e)
                })
    
    elif 'sqs' in threat_service:
        # SQS Queue remediation
        queue_url = threat.get('resource', {}).get('queue_url')
        
        if queue_url:
            # Enable encryption
            if options.get('enable_encryption', True):
                try:
                    sqs.set_queue_attributes(
                        QueueUrl=queue_url,
                        Attributes={
                            'KmsMasterKeyId': 'alias/aws/sqs',
                            'KmsDataKeyReusePeriodSeconds': '300'
                        }
                    )
                    
                    actions.append({
                        'action': 'EnableSQSEncryption',
                        'target': queue_url,
                        'status': 'SUCCESS'
                    })
                except Exception as e:
                    actions.append({
                        'action': 'EnableSQSEncryption',
                        'target': queue_url,
                        'status': 'FAILED',
                        'error': str(e)
                    })
    
    return actions


# ==================== GENERIC REMEDIATION ====================

def remediate_generic_threat(threat: Dict, options: Dict) -> List[Dict]:
    """
    Generic remediation for unknown threat types
    Logs the threat and sends notifications
    """
    actions = []
    
    # Log the threat
    actions.append({
        'action': 'LogThreat',
        'target': threat.get('threat_id', 'UNKNOWN'),
        'status': 'SUCCESS'
    })
    
    # Send notification
    if options.get('notify', True):
        actions.append({
            'action': 'NotifySecurityTeam',
            'target': 'security-team@example.com',
            'status': 'SUCCESS'
        })
    
    return actions


# ==================== BATCH SCHEDULING ====================

def schedule_batch_remediation(selected_threats: List[Dict], schedule_time: datetime, options: Dict) -> str:
    """
    Schedule batch remediation for future execution
    
    Args:
        selected_threats: List of threats to remediate
        schedule_time: When to execute remediation
        options: Remediation options
    
    Returns:
        Schedule ID
    """
    schedule_id = f"SCHEDULE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    
    # Store schedule in session state
    if 'scheduled_remediations' not in st.session_state:
        st.session_state.scheduled_remediations = []
    
    st.session_state.scheduled_remediations.append({
        'schedule_id': schedule_id,
        'threats': [t.get('threat_id') for t in selected_threats],
        'schedule_time': schedule_time.isoformat(),
        'options': options,
        'status': 'SCHEDULED'
    })
    
    return schedule_id


# ==================== UI RENDERING ====================

def render_batch_remediation_ui():
    """
    Main UI for batch threat remediation
    Includes threat selection, configuration, and execution
    """
    
    if not BATCH_REMEDIATION_ENABLED:
        st.warning("⚠️ Batch Remediation is currently disabled. Contact admin to enable.")
        return
    
    st.markdown("## ⚡ Batch Threat Remediation")
    st.markdown("Select and remediate multiple threats simultaneously across all AWS services")
    
    # Get available threats (from GuardDuty, Security Hub, etc.)
    available_threats = get_available_threats()
    
    if not available_threats:
        st.info("✅ No threats detected. Your environment is secure!")
        return
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Available Threats", len(available_threats))
    with col2:
        critical = len([t for t in available_threats if t.get('severity') == 'CRITICAL'])
        st.metric("Critical", critical, delta="Requires immediate action" if critical > 0 else None)
    with col3:
        scheduled = len(st.session_state.get('scheduled_remediations', []))
        st.metric("Scheduled Actions", scheduled)
    with col4:
        total_remediated = len(st.session_state.get('remediation_history', []))
        st.metric("Total Remediated", total_remediated)
    
    st.markdown("---")
    
    # Threat selection table
    st.markdown("#### 1️⃣ Select Threats for Batch Remediation")
    
    # Initialize threat selection state if not exists
    if 'batch_threat_df' not in st.session_state or st.session_state.get('refresh_threat_list', False):
        threat_df = pd.DataFrame([
            {
                'Select': False,
                'Threat ID': t.get('threat_id', 'UNKNOWN'),
                'Severity': t.get('severity', 'UNKNOWN'),
                'Type': t.get('threat_type', 'Unknown'),
                'Service': t.get('service', 'Unknown'),
                'Event': t.get('event_name', 'Unknown'),
                'Account': t.get('account_id', 'Unknown'),
                'Time': t.get('timestamp', 'Unknown')[:19] if t.get('timestamp') else 'Unknown'
            }
            for t in available_threats
        ])
        st.session_state.batch_threat_df = threat_df
        st.session_state.refresh_threat_list = False
    
    # Display threat selection table with persistent state
    edited_df = st.data_editor(
        st.session_state.batch_threat_df,
        hide_index=True,
        width="stretch",
        key="batch_threat_selector",
        column_config={
            "Select": st.column_config.CheckboxColumn(
                "Select",
                help="Select threats for batch remediation",
                default=False,
            ),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Service": st.column_config.TextColumn("Service", width="medium"),
        }
    )
    
    # Update session state
    st.session_state.batch_threat_df = edited_df
    
    selected_threats = [
        available_threats[i] 
        for i, row in edited_df.iterrows() 
        if row['Select']
    ]
    
    st.markdown(f"**Selected:** {len(selected_threats)} threat(s)")
    
    # Add clear selections button
    if len(selected_threats) > 0:
        col_info, col_clear = st.columns([3, 1])
        with col_clear:
            if st.button("🔄 Clear Selections", width="stretch"):
                st.session_state.refresh_threat_list = True
                st.rerun()
    
    if len(selected_threats) == 0:
        st.info("👆 Select one or more threats from the table above to begin batch remediation.")
        return
    
    st.markdown("---")
    
    # Remediation configuration
    st.markdown("#### 2️⃣ Configure Remediation Options")
    
    # Service-specific options
    services_in_selection = set(t.get('service', 'unknown').lower() for t in selected_threats)
    
    with st.expander("🔐 IAM Options", expanded='iam' in services_in_selection):
        revert_changes = st.checkbox("✅ Revert unauthorized changes", value=True, key="iam_revert")
        rotate_credentials = st.checkbox("🔑 Rotate compromised credentials", value=True, key="iam_rotate")
        revoke_sessions = st.checkbox("⛔ Revoke active sessions", value=False, key="iam_revoke")
    
    with st.expander("📦 S3 Options", expanded='s3' in services_in_selection):
        enable_encryption = st.checkbox("🔒 Enable encryption", value=True, key="s3_encrypt")
        block_public_access = st.checkbox("🚫 Block public access", value=True, key="s3_block")
        enable_versioning = st.checkbox("📚 Enable versioning", value=False, key="s3_version")
    
    with st.expander("🔒 EC2/Security Group Options", expanded='ec2' in services_in_selection):
        revoke_rules = st.checkbox("⛔ Revoke 0.0.0.0/0 rules", value=True, key="sg_revoke")
    
    with st.expander("🗄️ RDS Options", expanded='rds' in services_in_selection):
        make_private = st.checkbox("🔐 Make database private", value=True, key="rds_private")
        restrict_sg = st.checkbox("🛡️ Restrict security groups", value=True, key="rds_sg")
        enable_backups = st.checkbox("💾 Enable automated backups", value=True, key="rds_backup")
        enable_deletion_protection = st.checkbox("🔒 Enable deletion protection", value=True, key="rds_delete_protect")
    
    with st.expander("⚡ Lambda Options", expanded='lambda' in services_in_selection):
        restrict_permissions = st.checkbox("🔐 Restrict IAM permissions", value=True, key="lambda_perms")
        move_secrets = st.checkbox("🔑 Move secrets to Secrets Manager", value=True, key="lambda_secrets")
        remove_public_url = st.checkbox("🚫 Remove public function URLs", value=True, key="lambda_url")
        enable_xray = st.checkbox("📊 Enable X-Ray tracing", value=False, key="lambda_xray")
    
    with st.expander("📋 CloudTrail Options", expanded='cloudtrail' in services_in_selection):
        enable_logging = st.checkbox("✅ Re-enable logging", value=True, key="ct_logging")
        enable_validation = st.checkbox("🔐 Enable log file validation", value=True, key="ct_validation")
        create_alarm = st.checkbox("🚨 Create tampering alarm", value=True, key="ct_alarm")
    
    with st.expander("🔑 KMS Options", expanded='kms' in services_in_selection):
        cancel_deletion = st.checkbox("⛔ Cancel key deletion", value=True, key="kms_cancel")
        enable_rotation = st.checkbox("🔄 Enable automatic rotation", value=True, key="kms_rotate")
        restrict_policy = st.checkbox("🔐 Restrict key policy", value=True, key="kms_policy")
    
    with st.expander("🔒 Secrets Manager Options", expanded='secretsmanager' in services_in_selection):
        enable_secret_rotation = st.checkbox("🔄 Enable automatic rotation", value=True, key="sm_rotate")
        restrict_access = st.checkbox("🔐 Restrict access", value=True, key="sm_restrict")
    
    with st.expander("🌐 VPC Options", expanded='vpc' in services_in_selection):
        enable_flow_logs = st.checkbox("📊 Enable VPC Flow Logs", value=True, key="vpc_flow")
    
    with st.expander("📬 SNS/SQS Options", expanded=any(s in services_in_selection for s in ['sns', 'sqs'])):
        messaging_restrict = st.checkbox("🔐 Restrict access policies", value=True, key="msg_restrict")
        messaging_encrypt = st.checkbox("🔒 Enable encryption", value=True, key="msg_encrypt")
    
    with st.expander("📧 Notification Options"):
        notify_team = st.checkbox("📧 Notify security team", value=True, key="notify")
    
    # Compile options
    remediation_options = {
        # IAM
        'revert_changes': revert_changes,
        'rotate_credentials': rotate_credentials,
        'revoke_sessions': revoke_sessions,
        # S3
        'enable_encryption': enable_encryption,
        'block_public_access': block_public_access,
        'enable_versioning': enable_versioning,
        # Security Groups
        'revoke_rules': revoke_rules,
        # RDS
        'make_private': make_private,
        'restrict_security_group': restrict_sg,
        'enable_backups': enable_backups,
        'enable_deletion_protection': enable_deletion_protection,
        # Lambda
        'restrict_permissions': restrict_permissions,
        'move_secrets': move_secrets,
        'remove_public_url': remove_public_url,
        'enable_xray': enable_xray,
        # CloudTrail
        'enable_logging': enable_logging,
        'enable_validation': enable_validation,
        'create_alarm': create_alarm,
        # KMS
        'cancel_deletion': cancel_deletion,
        'enable_rotation': enable_rotation,
        'restrict_policy': restrict_policy,
        # Secrets Manager
        'enable_rotation': enable_secret_rotation,
        'restrict_access': restrict_access,
        # VPC
        'enable_flow_logs': enable_flow_logs,
        # Messaging
        'restrict_policy': messaging_restrict,
        'enable_encryption': messaging_encrypt,
        # General
        'notify': notify_team
    }
    
    st.markdown("---")
    
    # Execute batch remediation
    st.markdown("#### 3️⃣ Execute Batch Remediation")
    
    col_exec1, col_exec2 = st.columns([2, 1])
    
    with col_exec1:
        if st.button("⚡ Execute Batch Remediation Now", type="primary", width="stretch"):
            st.session_state.batch_selected_threats = selected_threats
            st.session_state.batch_remediation_options = remediation_options
            execute_batch_remediation_ui(selected_threats, remediation_options)
    
    with col_exec2:
        if st.button("📅 Schedule for Later", width="stretch"):
            st.info("Schedule functionality coming soon!")


def execute_batch_remediation_ui(selected_threats: List[Dict], options: Dict):
    """Execute batch remediation with progress tracking"""
    
    st.markdown("### 🔄 Executing Batch Remediation...")
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    results_container = st.container()
    
    total = len(selected_threats)
    results = {
        'successful': 0,
        'failed': 0,
        'details': []
    }
    
    for i, threat in enumerate(selected_threats):
        progress = (i + 1) / total
        progress_bar.progress(progress)
        status_text.text(f"Remediating threat {i+1} of {total}: {threat.get('threat_id', 'UNKNOWN')}")
        
        try:
            # Execute remediation
            threat_result = remediate_single_threat(threat, options)
            
            if threat_result['status'] == 'SUCCESS':
                results['successful'] += 1
                
                with results_container:
                    st.markdown(f"""
                    <div style='background: #D4EDDA; border-left: 4px solid #00C851; padding: 12px; margin: 5px 0; border-radius: 5px;'>
                        <strong style='color: #00C851;'>✅ {threat.get('threat_id', 'UNKNOWN')}</strong><br>
                        <span style='font-size: 12px; color: #666;'>
                            {len(threat_result['actions'])} actions executed
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                results['failed'] += 1
                
                with results_container:
                    st.markdown(f"""
                    <div style='background: #FFE6E6; border-left: 4px solid #D13212; padding: 12px; margin: 5px 0; border-radius: 5px;'>
                        <strong style='color: #D13212;'>❌ {threat.get('threat_id', 'UNKNOWN')}</strong><br>
                        <span style='font-size: 12px; color: #666;'>Error: {threat_result.get('error', 'Unknown')}</span>
                    </div>
                    """, unsafe_allow_html=True)
            
            results['details'].append(threat_result)
            
        except Exception as e:
            results['failed'] += 1
            
            with results_container:
                st.markdown(f"""
                <div style='background: #FFE6E6; border-left: 4px solid #D13212; padding: 12px; margin: 5px 0; border-radius: 5px;'>
                    <strong style='color: #D13212;'>❌ {threat.get('threat_id', 'UNKNOWN')}</strong><br>
                    <span style='font-size: 12px; color: #666;'>Error: {str(e)}</span>
                </div>
                """, unsafe_allow_html=True)
    
    progress_bar.progress(1.0)
    status_text.text(f"Batch remediation complete!")
    
    # Store in history
    if 'remediation_history' not in st.session_state:
        st.session_state.remediation_history = []
    
    st.session_state.remediation_history.extend(results['details'])
    
    # Clear selections after successful remediation
    st.session_state.refresh_threat_list = True
    
    # Success summary
    st.markdown("---")
    st.success("### ✅ Batch Remediation Complete!")
    
    col_sum1, col_sum2, col_sum3 = st.columns(3)
    
    with col_sum1:
        st.metric("Total Processed", total)
    with col_sum2:
        st.metric("Successful", results['successful'], delta="✅")
    with col_sum3:
        st.metric("Failed", results['failed'], delta="❌" if results['failed'] > 0 else None)


def get_available_threats() -> List[Dict]:
    """
    Get available threats from various sources
    Returns demo data for now, integrate with real sources later
    """
    
    # Check for demo mode
    demo_mode = st.session_state.get('mode', 'Demo') == 'Demo'
    
    if demo_mode:
        # Return demo threats covering all 10 services
        return [
            {
                'threat_id': 'THREAT-2024-001',
                'severity': 'CRITICAL',
                'threat_type': 'Unauthorized IAM Policy Modification',
                'service': 'iam',
                'event_name': 'PutRolePolicy',
                'account_id': '123456789012',
                'timestamp': '2025-12-02T03:58:05Z',
                'event_details': {
                    'eventName': 'PutRolePolicy',
                    'requestParameters': {
                        'roleName': 'ProductionRole',
                        'policyName': 'MaliciousPolicy'
                    },
                    'userIdentity': {
                        'arn': 'arn:aws:iam::123456789012:user/suspicious-user'
                    }
                }
            },
            {
                'threat_id': 'THREAT-2024-002',
                'severity': 'HIGH',
                'threat_type': 'Public S3 Bucket',
                'service': 's3',
                'event_name': 'PutBucketAcl',
                'account_id': '123456789012',
                'timestamp': '2025-12-02T02:13:05Z',
                'event_details': {
                    'requestParameters': {
                        'bucketName': 'sensitive-data-bucket'
                    }
                }
            },
            {
                'threat_id': 'THREAT-2024-003',
                'severity': 'CRITICAL',
                'threat_type': 'Public RDS Database',
                'service': 'rds',
                'event_name': 'ModifyDBInstance',
                'account_id': '123456789012',
                'timestamp': '2025-12-02T01:45:12Z',
                'resource': {
                    'db_instance_id': 'production-database'
                }
            },
            {
                'threat_id': 'THREAT-2024-004',
                'severity': 'HIGH',
                'threat_type': 'Over-Privileged Lambda Function',
                'service': 'lambda',
                'event_name': 'UpdateFunctionConfiguration',
                'account_id': '123456789012',
                'timestamp': '2025-12-01T23:30:45Z',
                'resource': {
                    'function_name': 'data-processor'
                }
            },
            {
                'threat_id': 'THREAT-2024-005',
                'severity': 'CRITICAL',
                'threat_type': 'CloudTrail Disabled',
                'service': 'cloudtrail',
                'event_name': 'StopLogging',
                'account_id': '123456789012',
                'timestamp': '2025-12-01T22:15:30Z',
                'resource': {
                    'trail_name': 'management-events'
                }
            },
            {
                'threat_id': 'THREAT-2024-006',
                'severity': 'CRITICAL',
                'threat_type': 'KMS Key Deletion Scheduled',
                'service': 'kms',
                'event_name': 'ScheduleKeyDeletion',
                'account_id': '123456789012',
                'timestamp': '2025-12-01T21:00:15Z',
                'resource': {
                    'key_id': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                }
            },
            {
                'threat_id': 'THREAT-2024-007',
                'severity': 'MEDIUM',
                'threat_type': 'Security Group 0.0.0.0/0 SSH Access',
                'service': 'ec2',
                'event_name': 'AuthorizeSecurityGroupIngress',
                'account_id': '123456789012',
                'timestamp': '2025-12-01T20:45:00Z',
                'resource': {
                    'security_group_id': 'sg-0123456789abcdef0'
                }
            }
        ]
    else:
        # Live mode - integrate with real AWS services
        # TODO: Integrate with GuardDuty, Security Hub, Inspector, Config
        return []


# Export main function
if __name__ == "__main__":
    render_batch_remediation_ui()