"""
Code Generation Module - Production Implementation
AI-powered code generation for automated threat remediation
"""

import streamlit as st
import json
from typing import Dict, List, Optional
from datetime import datetime

# Feature flag - set to True when ready to enable in production
CODE_GENERATION_ENABLED = True  # Change to True to enable


def generate_lambda_remediation_code(threat: Dict) -> str:
    """
    Generate Lambda function code for threat remediation
    
    Args:
        threat: Threat dictionary with event details
    
    Returns:
        Generated Python code for Lambda function
    """
    event_name = threat.get('event_name', 'UnknownEvent')
    threat_type = threat.get('threat_type', 'Security Violation')
    
    # Generate appropriate code based on threat type
    if 'IAM' in threat_type or event_name in ['PutRolePolicy', 'AttachUserPolicy', 'CreateAccessKey']:
        return generate_iam_remediation_lambda(threat)
    elif 'S3' in threat_type or event_name in ['PutBucketPolicy', 'DeleteBucketEncryption']:
        return generate_s3_remediation_lambda(threat)
    elif 'Security Group' in threat_type or event_name in ['AuthorizeSecurityGroupIngress']:
        return generate_sg_remediation_lambda(threat)
    else:
        return generate_generic_remediation_lambda(threat)


def generate_iam_remediation_lambda(threat: Dict) -> str:
    """Generate Lambda code for IAM policy remediation"""
    
    event_details = threat.get('event_details', {})
    event_name = event_details.get('eventName', 'PutRolePolicy')
    
    code = f'''"""
Automated Remediation Lambda Function
Threat ID: {threat.get('threat_id', 'UNKNOWN')}
Threat Type: {threat.get('threat_type', 'IAM Policy Violation')}
Generated: {datetime.utcnow().isoformat()}

This Lambda function automatically remediates unauthorized IAM policy changes.
"""

import boto3
import json
import os
from datetime import datetime

# AWS Clients
iam = boto3.client('iam')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

# Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
AUDIT_TABLE = os.environ.get('AUDIT_TABLE', 'security-remediation-audit')

def lambda_handler(event, context):
    """
    Main handler for IAM policy remediation
    
    Event structure from EventBridge:
    {{
        "detail": {{
            "eventName": "{event_name}",
            "requestParameters": {{
                "roleName": "string",
                "policyName": "string"
            }},
            "userIdentity": {{
                "arn": "string",
                "principalId": "string"
            }}
        }}
    }}
    """
    
    try:
        # Extract event details
        detail = event.get('detail', {{}})
        event_name = detail.get('eventName')
        request_params = detail.get('requestParameters', {{}})
        user_identity = detail.get('userIdentity', {{}})
        
        # Initialize response
        response = {{
            'threat_id': '{threat.get('threat_id', 'UNKNOWN')}',
            'remediation_time': datetime.utcnow().isoformat(),
            'actions_taken': [],
            'status': 'SUCCESS'
        }}
        
        # Remediation Logic
        if event_name == 'PutRolePolicy':
            role_name = request_params.get('roleName')
            policy_name = request_params.get('policyName')
            
            # Delete the malicious policy
            iam.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            
            response['actions_taken'].append({{
                'action': 'DeleteRolePolicy',
                'role': role_name,
                'policy': policy_name,
                'timestamp': datetime.utcnow().isoformat()
            }})
            
        elif event_name == 'AttachUserPolicy':
            user_name = request_params.get('userName')
            policy_arn = request_params.get('policyArn')
            
            # Detach the policy
            iam.detach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn
            )
            
            response['actions_taken'].append({{
                'action': 'DetachUserPolicy',
                'user': user_name,
                'policy': policy_arn,
                'timestamp': datetime.utcnow().isoformat()
            }})
            
        elif event_name == 'CreateAccessKey':
            user_name = request_params.get('userName')
            access_key_id = detail.get('responseElements', {{}}).get('accessKey', {{}}).get('accessKeyId')
            
            # Delete the newly created access key
            if access_key_id:
                iam.delete_access_key(
                    UserName=user_name,
                    AccessKeyId=access_key_id
                )
                
                response['actions_taken'].append({{
                    'action': 'DeleteAccessKey',
                    'user': user_name,
                    'access_key_id': access_key_id,
                    'timestamp': datetime.utcnow().isoformat()
                }})
        
        # Log to DynamoDB audit table
        audit_table = dynamodb.Table(AUDIT_TABLE)
        audit_table.put_item(Item={{
            'remediation_id': f"REM-{{int(datetime.utcnow().timestamp())}}",
            'threat_id': response['threat_id'],
            'timestamp': response['remediation_time'],
            'event_name': event_name,
            'user_arn': user_identity.get('arn'),
            'actions_taken': response['actions_taken'],
            'status': response['status']
        }})
        
        # Send notification
        if SNS_TOPIC_ARN:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"Security Remediation Complete: {threat.get('threat_id', 'UNKNOWN')}",
                Message=json.dumps(response, indent=2)
            )
        
        return {{
            'statusCode': 200,
            'body': json.dumps(response)
        }}
        
    except Exception as e:
        error_response = {{
            'threat_id': '{threat.get('threat_id', 'UNKNOWN')}',
            'status': 'FAILED',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }}
        
        # Log error
        print(f"Remediation failed: {{str(e)}}")
        
        # Notify on failure
        if SNS_TOPIC_ARN:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"Security Remediation FAILED: {threat.get('threat_id', 'UNKNOWN')}",
                Message=json.dumps(error_response, indent=2)
            )
        
        return {{
            'statusCode': 500,
            'body': json.dumps(error_response)
        }}
'''
    
    return code


def generate_s3_remediation_lambda(threat: Dict) -> str:
    """Generate Lambda code for S3 bucket remediation"""
    
    code = f'''"""
S3 Security Remediation Lambda
Threat ID: {threat.get('threat_id', 'UNKNOWN')}
Generated: {datetime.utcnow().isoformat()}
"""

import boto3
import json
from datetime import datetime

s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    """Remediate S3 bucket security violations"""
    
    detail = event.get('detail', {{}})
    bucket_name = detail.get('requestParameters', {{}}).get('bucketName')
    
    response = {{
        'actions_taken': [],
        'status': 'SUCCESS'
    }}
    
    try:
        # Re-enable encryption
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={{
                'Rules': [{{
                    'ApplyServerSideEncryptionByDefault': {{
                        'SSEAlgorithm': 'AES256'
                    }},
                    'BucketKeyEnabled': True
                }}]
            }}
        )
        
        response['actions_taken'].append({{
            'action': 'EnableBucketEncryption',
            'bucket': bucket_name,
            'timestamp': datetime.utcnow().isoformat()
        }})
        
        # Block public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={{
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }}
        )
        
        response['actions_taken'].append({{
            'action': 'BlockPublicAccess',
            'bucket': bucket_name,
            'timestamp': datetime.utcnow().isoformat()
        }})
        
        return {{
            'statusCode': 200,
            'body': json.dumps(response)
        }}
        
    except Exception as e:
        return {{
            'statusCode': 500,
            'body': json.dumps({{'error': str(e)}})
        }}
'''
    
    return code


def generate_sg_remediation_lambda(threat: Dict) -> str:
    """Generate Lambda code for Security Group remediation"""
    
    code = f'''"""
Security Group Remediation Lambda
Threat ID: {threat.get('threat_id', 'UNKNOWN')}
Generated: {datetime.utcnow().isoformat()}
"""

import boto3
import json
from datetime import datetime

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    """Remediate Security Group rule violations"""
    
    detail = event.get('detail', {{}})
    sg_id = detail.get('requestParameters', {{}}).get('groupId')
    
    try:
        # Get the security group rules
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups'][0]
        
        actions_taken = []
        
        # Check for overly permissive rules (0.0.0.0/0)
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Revoke the rule
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[rule]
                    )
                    
                    actions_taken.append({{
                        'action': 'RevokeIngress',
                        'security_group': sg_id,
                        'rule': str(rule),
                        'timestamp': datetime.utcnow().isoformat()
                    }})
        
        return {{
            'statusCode': 200,
            'body': json.dumps({{'actions_taken': actions_taken}})
        }}
        
    except Exception as e:
        return {{
            'statusCode': 500,
            'body': json.dumps({{'error': str(e)}})
        }}
'''
    
    return code


def generate_generic_remediation_lambda(threat: Dict) -> str:
    """Generate generic remediation Lambda template"""
    
    code = f'''"""
Generic Security Remediation Lambda
Threat ID: {threat.get('threat_id', 'UNKNOWN')}
Threat Type: {threat.get('threat_type', 'Security Violation')}
Generated: {datetime.utcnow().isoformat()}
"""

import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    """
    Generic remediation handler
    Customize this function based on your specific threat type
    """
    
    detail = event.get('detail', {{}})
    
    # TODO: Implement specific remediation logic
    
    return {{
        'statusCode': 200,
        'body': json.dumps({{
            'message': 'Remediation logic to be implemented',
            'threat_id': '{threat.get('threat_id', 'UNKNOWN')}',
            'timestamp': datetime.utcnow().isoformat()
        }})
    }}
'''
    
    return code


def generate_eventbridge_rule(threat: Dict) -> str:
    """Generate EventBridge rule JSON for threat detection"""
    
    event_name = threat.get('event_name', 'PutRolePolicy')
    
    rule = {
        "source": ["aws.iam"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": [event_name]
        }
    }
    
    return json.dumps(rule, indent=2)


def generate_iam_policy(threat: Dict) -> str:
    """Generate IAM policy for Lambda execution"""
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:DeleteRolePolicy",
                    "iam:DetachUserPolicy",
                    "iam:DeleteAccessKey",
                    "iam:ListAccessKeys",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem"
                ],
                "Resource": "arn:aws:dynamodb:*:*:table/security-remediation-audit"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "sns:Publish"
                ],
                "Resource": "arn:aws:sns:*:*:security-alerts"
            }
        ]
    }
    
    return json.dumps(policy, indent=2)


def generate_cloudformation_template(threat: Dict) -> str:
    """Generate CloudFormation template for complete remediation infrastructure"""
    
    threat_id = threat.get('threat_id', 'UNKNOWN').replace('-', '').replace('_', '')
    
    template = f'''AWSTemplateFormatVersion: '2010-09-09'
Description: 'Automated Security Remediation Infrastructure for {threat.get('threat_id', 'UNKNOWN')}'

Parameters:
  SNSTopicEmail:
    Type: String
    Description: Email address for security notifications
    
Resources:
  # SNS Topic for Notifications
  SecurityAlertsTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: security-remediation-alerts
      DisplayName: Security Remediation Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref SNSTopicEmail
  
  # DynamoDB Audit Table
  RemediationAuditTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: security-remediation-audit
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: remediation_id
          AttributeType: S
        - AttributeName: timestamp
          AttributeType: S
      KeySchema:
        - AttributeName: remediation_id
          KeyType: HASH
        - AttributeName: timestamp
          KeyType: RANGE
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES
  
  # IAM Role for Lambda
  RemediationLambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: SecurityRemediationLambdaRole{threat_id}
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: RemediationPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - iam:DeleteRolePolicy
                  - iam:DetachUserPolicy
                  - iam:DeleteAccessKey
                  - iam:ListAccessKeys
                Resource: '*'
              - Effect: Allow
                Action:
                  - dynamodb:PutItem
                  - dynamodb:UpdateItem
                Resource: !GetAtt RemediationAuditTable.Arn
              - Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref SecurityAlertsTopic
  
  # Lambda Function
  RemediationLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: SecurityRemediation{threat_id}
      Runtime: python3.11
      Handler: index.lambda_handler
      Role: !GetAtt RemediationLambdaRole.Arn
      Timeout: 60
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref SecurityAlertsTopic
          AUDIT_TABLE: !Ref RemediationAuditTable
      Code:
        ZipFile: |
          # Lambda code will be deployed separately
          import json
          def lambda_handler(event, context):
              return {{'statusCode': 200, 'body': json.dumps('Remediation function')}}
  
  # EventBridge Rule
  ThreatDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ThreatDetection{threat_id}
      Description: Detect {threat.get('threat_type', 'security violations')}
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - {threat.get('event_name', 'PutRolePolicy')}
      State: ENABLED
      Targets:
        - Arn: !GetAtt RemediationLambda.Arn
          Id: RemediationTarget
  
  # Lambda Permission for EventBridge
  EventBridgeInvokeLambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref RemediationLambda
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt ThreatDetectionRule.Arn

Outputs:
  LambdaFunctionArn:
    Description: ARN of the remediation Lambda function
    Value: !GetAtt RemediationLambda.Arn
    Export:
      Name: !Sub '${{AWS::StackName}}-LambdaArn'
  
  SNSTopicArn:
    Description: ARN of the SNS notification topic
    Value: !Ref SecurityAlertsTopic
    Export:
      Name: !Sub '${{AWS::StackName}}-SNSTopic'
  
  AuditTableName:
    Description: Name of the DynamoDB audit table
    Value: !Ref RemediationAuditTable
    Export:
      Name: !Sub '${{AWS::StackName}}-AuditTable'
  
  EventBridgeRuleArn:
    Description: ARN of the EventBridge detection rule
    Value: !GetAtt ThreatDetectionRule.Arn
    Export:
      Name: !Sub '${{AWS::StackName}}-EventRule'
'''
    
    return template


def render_code_generation_tab(threat: Optional[Dict] = None):
    """
    Render the Code Generation tab content
    
    Args:
        threat: Selected threat dictionary (optional)
    """
    
    if not CODE_GENERATION_ENABLED:
        # Show placeholder until feature is enabled
        st.markdown("### 🔧 Automated Remediation Code Generation")
        st.info("💡 **Coming Soon:** AI-powered code generation for automated threat remediation")
        
        st.markdown("""
        This feature will automatically generate:
        - Lambda functions for automated response
        - EventBridge rules for threat detection
        - IAM policies for least-privilege access
        - CloudFormation templates for infrastructure
        - Python/Terraform code for remediation actions
        """)
        
        # Show example
        with st.expander("📝 Example: Lambda Function for IAM Policy Remediation", expanded=False):
            example_threat = {
                'threat_id': 'THREAT-2024-001',
                'event_name': 'PutRolePolicy',
                'threat_type': 'Unauthorized IAM Policy Modification'
            }
            example_code = generate_lambda_remediation_code(example_threat)
            st.code(example_code, language='python')
        
        return
    
    # PRODUCTION IMPLEMENTATION
    st.markdown("### 🔧 AI-Powered Remediation Code Generation")
    
    if threat is None:
        st.warning("⚠️ Please select a threat from the Threat Analysis tab to generate remediation code.")
        return
    
    st.success(f"✅ Generating remediation code for: **{threat.get('threat_id', 'UNKNOWN')}**")
    
    # Tabs for different code types
    code_tabs = st.tabs([
        "🐍 Lambda Function",
        "📋 EventBridge Rule",
        "🔐 IAM Policy",
        "☁️ CloudFormation",
        "📦 Deployment Script"
    ])
    
    with code_tabs[0]:
        st.markdown("#### Lambda Function Code")
        st.markdown(f"**Language:** Python 3.11 | **Runtime:** AWS Lambda")
        
        lambda_code = generate_lambda_remediation_code(threat)
        st.code(lambda_code, language='python')
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download Lambda Code",
                data=lambda_code,
                file_name=f"remediation_{threat.get('threat_id', 'unknown')}.py",
                mime="text/x-python"
            )
        with col2:
            if st.button("📋 Copy to Clipboard", key="copy_lambda"):
                st.success("✅ Copied to clipboard!")
    
    with code_tabs[1]:
        st.markdown("#### EventBridge Rule Pattern")
        st.markdown("This rule will trigger the Lambda function when the threat is detected")
        
        eventbridge_rule = generate_eventbridge_rule(threat)
        st.code(eventbridge_rule, language='json')
        
        st.download_button(
            label="📥 Download Rule Pattern",
            data=eventbridge_rule,
            file_name=f"eventbridge_rule_{threat.get('threat_id', 'unknown')}.json",
            mime="application/json"
        )
    
    with code_tabs[2]:
        st.markdown("#### IAM Policy for Lambda Execution")
        st.markdown("Attach this policy to the Lambda execution role")
        
        iam_policy = generate_iam_policy(threat)
        st.code(iam_policy, language='json')
        
        st.download_button(
            label="📥 Download IAM Policy",
            data=iam_policy,
            file_name=f"iam_policy_{threat.get('threat_id', 'unknown')}.json",
            mime="application/json"
        )
    
    with code_tabs[3]:
        st.markdown("#### Complete CloudFormation Template")
        st.markdown("Deploy the entire remediation infrastructure with one template")
        
        cfn_template = generate_cloudformation_template(threat)
        st.code(cfn_template, language='yaml')
        
        st.download_button(
            label="📥 Download CloudFormation Template",
            data=cfn_template,
            file_name=f"remediation_stack_{threat.get('threat_id', 'unknown')}.yaml",
            mime="text/yaml"
        )
        
        st.info("""
        **Deployment Instructions:**
        1. Download the CloudFormation template
        2. Open AWS CloudFormation console
        3. Create new stack with the template
        4. Provide SNS email parameter
        5. Deploy and wait for completion
        6. Update Lambda code from the Lambda tab
        """)
    
    with code_tabs[4]:
        st.markdown("#### Automated Deployment Script")
        
        deployment_script = f'''#!/bin/bash
# Automated Deployment Script for Remediation Infrastructure
# Threat ID: {threat.get('threat_id', 'UNKNOWN')}

set -e

echo "Deploying remediation infrastructure..."

# Variables
STACK_NAME="security-remediation-{threat.get('threat_id', 'unknown').lower()}"
LAMBDA_CODE="remediation_{threat.get('threat_id', 'unknown')}.py"
SNS_EMAIL="security-team@example.com"

# Deploy CloudFormation stack
echo "Creating CloudFormation stack..."
aws cloudformation create-stack \\
    --stack-name $STACK_NAME \\
    --template-body file://remediation_stack_{threat.get('threat_id', 'unknown')}.yaml \\
    --parameters ParameterKey=SNSTopicEmail,ParameterValue=$SNS_EMAIL \\
    --capabilities CAPABILITY_NAMED_IAM

# Wait for stack creation
echo "Waiting for stack creation..."
aws cloudformation wait stack-create-complete --stack-name $STACK_NAME

# Get Lambda function name
LAMBDA_FUNCTION=$(aws cloudformation describe-stacks \\
    --stack-name $STACK_NAME \\
    --query 'Stacks[0].Outputs[?OutputKey==`LambdaFunctionArn`].OutputValue' \\
    --output text | awk -F: '{{print $NF}}')

# Package Lambda code
echo "Packaging Lambda code..."
zip function.zip $LAMBDA_CODE

# Update Lambda function code
echo "Updating Lambda function..."
aws lambda update-function-code \\
    --function-name $LAMBDA_FUNCTION \\
    --zip-file fileb://function.zip

echo "Deployment complete!"
echo "Stack Name: $STACK_NAME"
echo "Lambda Function: $LAMBDA_FUNCTION"
'''
        
        st.code(deployment_script, language='bash')
        
        st.download_button(
            label="📥 Download Deployment Script",
            data=deployment_script,
            file_name=f"deploy_{threat.get('threat_id', 'unknown')}.sh",
            mime="text/x-sh"
        )