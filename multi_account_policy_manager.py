"""
Multi-Account Policy Manager
============================

Integrates with Policy as Code Platform to deploy and manage policies
across AWS Organizations.

Features:
- Organization-wide Config Rule deployment via StackSets
- Central compliance aggregation
- Cross-account scanning
- SCP management
- Security Hub integration

Author: Cloud Compliance Canvas
Version: 1.0.0
"""

import streamlit as st
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Optional AWS imports
try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# ============================================================================
# AWS ORGANIZATIONS INTEGRATION
# ============================================================================

class AWSOrganizationsManager:
    """Manage AWS Organizations for multi-account deployment"""
    
    def __init__(self):
        self.org_client = None
        self.cfn_client = None
        self.config_client = None
        self.securityhub_client = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize AWS clients from session state (pre-initialized by main app)"""
        if not BOTO3_AVAILABLE:
            return
        
        # Get pre-initialized clients from session state
        clients = st.session_state.get('aws_clients', {})
        
        # Use pre-initialized clients if available
        self.org_client = clients.get('organizations')
        self.cfn_client = clients.get('cloudformation')
        self.config_client = clients.get('config')
        self.securityhub_client = clients.get('securityhub')
        
        # Fallback: try to create from boto3_session
        session = st.session_state.get('boto3_session')
        if session:
            try:
                if not self.org_client:
                    self.org_client = session.client('organizations', region_name='us-east-1')
                if not self.cfn_client:
                    self.cfn_client = session.client('cloudformation')
                if not self.config_client:
                    self.config_client = session.client('config')
                if not self.securityhub_client:
                    self.securityhub_client = session.client('securityhub')
            except Exception as e:
                st.warning(f"AWS client initialization: {e}")
    
    def get_organization_info(self) -> Dict:
        """Get organization details"""
        if not self.org_client:
            return self._get_demo_org_info()
        
        try:
            org = self.org_client.describe_organization()
            return {
                'id': org['Organization']['Id'],
                'arn': org['Organization']['Arn'],
                'master_account_id': org['Organization']['MasterAccountId'],
                'master_account_email': org['Organization'].get('MasterAccountEmail', 'N/A'),
                'feature_set': org['Organization']['FeatureSet']
            }
        except Exception as e:
            st.error(f"Error getting organization: {e}")
            return self._get_demo_org_info()
    
    def list_accounts(self) -> List[Dict]:
        """List all accounts in organization"""
        if not self.org_client:
            return self._get_demo_accounts()
        
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account['Email'],
                        'status': account['Status'],
                        'joined': account.get('JoinedTimestamp', '').isoformat() if account.get('JoinedTimestamp') else 'N/A'
                    })
            
            return accounts
        except Exception as e:
            st.error(f"Error listing accounts: {e}")
            return self._get_demo_accounts()
    
    def list_organizational_units(self) -> List[Dict]:
        """List all OUs in organization"""
        if not self.org_client:
            return self._get_demo_ous()
        
        try:
            # Get root
            roots = self.org_client.list_roots()
            root_id = roots['Roots'][0]['Id']
            
            # Get OUs under root
            ous = []
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=root_id):
                for ou in page['OrganizationalUnits']:
                    ous.append({
                        'id': ou['Id'],
                        'name': ou['Name'],
                        'arn': ou['Arn']
                    })
            
            # Add root as an option
            ous.insert(0, {
                'id': root_id,
                'name': 'Root (All Accounts)',
                'arn': roots['Roots'][0]['Arn']
            })
            
            return ous
        except Exception as e:
            return self._get_demo_ous()
    
    def list_stack_sets(self) -> List[Dict]:
        """List CloudFormation StackSets"""
        if not self.cfn_client:
            return self._get_demo_stacksets()
        
        try:
            stacksets = []
            paginator = self.cfn_client.get_paginator('list_stack_sets')
            
            for page in paginator.paginate(Status='ACTIVE'):
                for ss in page['Summaries']:
                    stacksets.append({
                        'name': ss['StackSetName'],
                        'status': ss['Status'],
                        'description': ss.get('Description', 'N/A'),
                        'drift_status': ss.get('DriftStatus', 'NOT_CHECKED')
                    })
            
            return stacksets
        except Exception as e:
            return self._get_demo_stacksets()
    
    def get_stackset_instances(self, stackset_name: str) -> List[Dict]:
        """Get stack instances for a StackSet"""
        if not self.cfn_client:
            return self._get_demo_instances()
        
        try:
            instances = []
            paginator = self.cfn_client.get_paginator('list_stack_instances')
            
            for page in paginator.paginate(StackSetName=stackset_name):
                for instance in page['Summaries']:
                    instances.append({
                        'account': instance['Account'],
                        'region': instance['Region'],
                        'status': instance['Status'],
                        'status_reason': instance.get('StatusReason', '')
                    })
            
            return instances
        except Exception as e:
            return self._get_demo_instances()
    
    def create_stackset(self, name: str, template: str, description: str = "") -> Dict:
        """Create a new StackSet"""
        if not self.cfn_client:
            return {'status': 'demo', 'message': 'Demo mode - StackSet would be created'}
        
        try:
            response = self.cfn_client.create_stack_set(
                StackSetName=name,
                Description=description,
                TemplateBody=template,
                PermissionModel='SERVICE_MANAGED',
                AutoDeployment={
                    'Enabled': True,
                    'RetainStacksOnAccountRemoval': False
                },
                Capabilities=['CAPABILITY_NAMED_IAM']
            )
            return {'status': 'success', 'stackset_id': response['StackSetId']}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def deploy_to_ous(self, stackset_name: str, ou_ids: List[str], regions: List[str]) -> Dict:
        """Deploy StackSet to organizational units"""
        if not self.cfn_client:
            return {'status': 'demo', 'message': f'Would deploy to {len(ou_ids)} OUs in {len(regions)} regions'}
        
        try:
            response = self.cfn_client.create_stack_instances(
                StackSetName=stackset_name,
                DeploymentTargets={'OrganizationalUnitIds': ou_ids},
                Regions=regions,
                OperationPreferences={
                    'FailureToleranceCount': 0,
                    'MaxConcurrentCount': 10
                }
            )
            return {'status': 'success', 'operation_id': response['OperationId']}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    # Demo data methods
    def _get_demo_org_info(self) -> Dict:
        return {
            'id': 'o-demo12345',
            'arn': 'arn:aws:organizations::123456789012:organization/o-demo12345',
            'master_account_id': '123456789012',
            'master_account_email': 'master@company.com',
            'feature_set': 'ALL'
        }
    
    def _get_demo_accounts(self) -> List[Dict]:
        return [
            {'id': '123456789012', 'name': 'Management', 'email': 'master@company.com', 'status': 'ACTIVE', 'joined': '2023-01-15'},
            {'id': '234567890123', 'name': 'Production', 'email': 'prod@company.com', 'status': 'ACTIVE', 'joined': '2023-02-20'},
            {'id': '345678901234', 'name': 'Development', 'email': 'dev@company.com', 'status': 'ACTIVE', 'joined': '2023-03-10'},
            {'id': '456789012345', 'name': 'Staging', 'email': 'staging@company.com', 'status': 'ACTIVE', 'joined': '2023-04-05'},
            {'id': '567890123456', 'name': 'Sandbox', 'email': 'sandbox@company.com', 'status': 'ACTIVE', 'joined': '2023-05-15'},
        ]
    
    def _get_demo_ous(self) -> List[Dict]:
        return [
            {'id': 'r-demo', 'name': 'Root (All Accounts)', 'arn': 'arn:aws:organizations::123456789012:root/o-demo/r-demo'},
            {'id': 'ou-prod-123', 'name': 'Production', 'arn': 'arn:aws:organizations::123456789012:ou/o-demo/ou-prod-123'},
            {'id': 'ou-dev-456', 'name': 'Development', 'arn': 'arn:aws:organizations::123456789012:ou/o-demo/ou-dev-456'},
            {'id': 'ou-sandbox-789', 'name': 'Sandbox', 'arn': 'arn:aws:organizations::123456789012:ou/o-demo/ou-sandbox-789'},
        ]
    
    def _get_demo_stacksets(self) -> List[Dict]:
        return [
            {'name': 'org-config-rules', 'status': 'ACTIVE', 'description': 'Organization-wide Config Rules', 'drift_status': 'NOT_CHECKED'},
            {'name': 'security-baseline', 'status': 'ACTIVE', 'description': 'Security baseline controls', 'drift_status': 'IN_SYNC'},
        ]
    
    def _get_demo_instances(self) -> List[Dict]:
        return [
            {'account': '234567890123', 'region': 'us-east-1', 'status': 'CURRENT', 'status_reason': ''},
            {'account': '345678901234', 'region': 'us-east-1', 'status': 'CURRENT', 'status_reason': ''},
            {'account': '456789012345', 'region': 'us-east-1', 'status': 'OUTDATED', 'status_reason': 'Update pending'},
            {'account': '567890123456', 'region': 'us-east-1', 'status': 'CURRENT', 'status_reason': ''},
        ]


# ============================================================================
# CONFIG AGGREGATOR
# ============================================================================

class ConfigAggregatorManager:
    """Manage AWS Config Aggregator for cross-account compliance"""
    
    def __init__(self):
        self.config_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        if not BOTO3_AVAILABLE:
            return
        
        # Get from pre-initialized clients
        clients = st.session_state.get('aws_clients', {})
        self.config_client = clients.get('config')
        
        # Fallback: try boto3_session
        if not self.config_client:
            session = st.session_state.get('boto3_session')
            if session:
                try:
                    self.config_client = session.client('config')
                except Exception:
                    pass
    
    def get_aggregator_compliance(self, aggregator_name: str = "organization-aggregator") -> Dict:
        """Get compliance summary from aggregator"""
        if not self.config_client:
            return self._get_demo_compliance()
        
        try:
            # Get compliance by rule
            rule_response = self.config_client.describe_aggregate_compliance_by_config_rules(
                ConfigurationAggregatorName=aggregator_name
            )
            
            # Get compliance by account
            account_response = self.config_client.get_aggregate_config_rule_compliance_summary(
                ConfigurationAggregatorName=aggregator_name,
                GroupByKey='ACCOUNT_ID'
            )
            
            return {
                'by_rule': rule_response.get('AggregateComplianceByConfigRules', []),
                'by_account': account_response.get('GroupByKeyResults', []),
                'status': 'success'
            }
        except Exception as e:
            return self._get_demo_compliance()
    
    def get_non_compliant_resources(self, aggregator_name: str, rule_name: str) -> List[Dict]:
        """Get non-compliant resources for a specific rule"""
        if not self.config_client:
            return self._get_demo_non_compliant()
        
        try:
            response = self.config_client.get_aggregate_compliance_details_by_config_rule(
                ConfigurationAggregatorName=aggregator_name,
                ConfigRuleName=rule_name,
                ComplianceType='NON_COMPLIANT'
            )
            
            resources = []
            for result in response.get('AggregateEvaluationResults', []):
                # Safely access nested keys
                eval_id = result.get('EvaluationResultIdentifier', {})
                qualifier = eval_id.get('EvaluationResultQualifier', {})
                
                resources.append({
                    'account_id': result.get('AccountId'),
                    'region': result.get('AwsRegion'),
                    'resource_type': qualifier.get('ResourceType', 'Unknown'),
                    'resource_id': qualifier.get('ResourceId', 'Unknown'),
                    'compliance': result.get('ComplianceType')
                })
            
            return resources
        except Exception as e:
            return self._get_demo_non_compliant()
    
    def _get_demo_compliance(self) -> Dict:
        return {
            'by_rule': [
                {'ConfigRuleName': 's3-bucket-encryption-enabled', 'Compliance': {'ComplianceType': 'NON_COMPLIANT', 'ComplianceContributorCount': {'CappedCount': 3}}},
                {'ConfigRuleName': 'restricted-ssh', 'Compliance': {'ComplianceType': 'COMPLIANT', 'ComplianceContributorCount': {'CappedCount': 0}}},
                {'ConfigRuleName': 'rds-storage-encrypted', 'Compliance': {'ComplianceType': 'NON_COMPLIANT', 'ComplianceContributorCount': {'CappedCount': 2}}},
                {'ConfigRuleName': 'root-account-mfa-enabled', 'Compliance': {'ComplianceType': 'COMPLIANT', 'ComplianceContributorCount': {'CappedCount': 0}}},
                {'ConfigRuleName': 'ec2-imdsv2-check', 'Compliance': {'ComplianceType': 'NON_COMPLIANT', 'ComplianceContributorCount': {'CappedCount': 5}}},
            ],
            'by_account': [
                {'GroupName': '234567890123', 'ComplianceSummary': {'CompliantResourceCount': {'CappedCount': 45}, 'NonCompliantResourceCount': {'CappedCount': 3}}},
                {'GroupName': '345678901234', 'ComplianceSummary': {'CompliantResourceCount': {'CappedCount': 38}, 'NonCompliantResourceCount': {'CappedCount': 5}}},
                {'GroupName': '456789012345', 'ComplianceSummary': {'CompliantResourceCount': {'CappedCount': 22}, 'NonCompliantResourceCount': {'CappedCount': 2}}},
                {'GroupName': '567890123456', 'ComplianceSummary': {'CompliantResourceCount': {'CappedCount': 15}, 'NonCompliantResourceCount': {'CappedCount': 0}}},
            ],
            'status': 'demo'
        }
    
    def _get_demo_non_compliant(self) -> List[Dict]:
        return [
            {'account_id': '234567890123', 'region': 'us-east-1', 'resource_type': 'AWS::S3::Bucket', 'resource_id': 'app-data-bucket', 'compliance': 'NON_COMPLIANT'},
            {'account_id': '345678901234', 'region': 'us-east-1', 'resource_type': 'AWS::S3::Bucket', 'resource_id': 'logs-bucket', 'compliance': 'NON_COMPLIANT'},
            {'account_id': '456789012345', 'region': 'us-west-2', 'resource_type': 'AWS::S3::Bucket', 'resource_id': 'backup-bucket', 'compliance': 'NON_COMPLIANT'},
        ]


# ============================================================================
# CONFIG RULES TEMPLATES
# ============================================================================

CONFIG_RULES_STACKSET_TEMPLATE = '''AWSTemplateFormatVersion: '2010-09-09'
Description: Organization-wide Config Rules for Policy as Code

Resources:
  S3BucketEncryptionRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-encryption-enabled
      Description: Checks if S3 buckets have server-side encryption enabled
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
      Scope:
        ComplianceResourceTypes:
          - AWS::S3::Bucket

  S3BucketPublicReadProhibitedRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-read-prohibited
      Description: Checks if S3 buckets do not allow public read access
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED
      Scope:
        ComplianceResourceTypes:
          - AWS::S3::Bucket

  RestrictedSSHRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: restricted-ssh
      Description: Checks if security groups allow unrestricted SSH access
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED
      Scope:
        ComplianceResourceTypes:
          - AWS::EC2::SecurityGroup

  RDSEncryptionRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rds-storage-encrypted
      Description: Checks if RDS instances have encryption enabled
      Source:
        Owner: AWS
        SourceIdentifier: RDS_STORAGE_ENCRYPTED
      Scope:
        ComplianceResourceTypes:
          - AWS::RDS::DBInstance

  RDSPublicAccessRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rds-instance-public-access-check
      Description: Checks if RDS instances are publicly accessible
      Source:
        Owner: AWS
        SourceIdentifier: RDS_INSTANCE_PUBLIC_ACCESS_CHECK
      Scope:
        ComplianceResourceTypes:
          - AWS::RDS::DBInstance

  IAMRootMFARule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: root-account-mfa-enabled
      Description: Checks if root account has MFA enabled
      Source:
        Owner: AWS
        SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED

  EC2IMDSv2Rule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: ec2-imdsv2-check
      Description: Checks if EC2 instances use IMDSv2
      Source:
        Owner: AWS
        SourceIdentifier: EC2_IMDSV2_CHECK
      Scope:
        ComplianceResourceTypes:
          - AWS::EC2::Instance

  EBSEncryptionRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: ec2-ebs-encryption-by-default
      Description: Checks if EBS encryption by default is enabled
      Source:
        Owner: AWS
        SourceIdentifier: EC2_EBS_ENCRYPTION_BY_DEFAULT

  CloudTrailEnabledRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloudtrail-enabled
      Description: Checks if CloudTrail is enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENABLED

Outputs:
  RulesDeployed:
    Description: Number of Config Rules deployed
    Value: "9"
'''


# ============================================================================
# SESSION STATE
# ============================================================================

def init_multi_account_state():
    """Initialize session state for multi-account management"""
    if 'multi_account' not in st.session_state:
        st.session_state.multi_account = {
            'org_info': None,
            'accounts': [],
            'ous': [],
            'stacksets': [],
            'compliance': {},
            'selected_accounts': [],
            'selected_ous': [],
            'deployment_history': []
        }


# ============================================================================
# UI COMPONENTS
# ============================================================================

def render_organization_overview():
    """Render organization overview tab"""
    st.markdown("### 🏢 Organization Overview")
    
    org_manager = AWSOrganizationsManager()
    
    # Get org info
    org_info = org_manager.get_organization_info()
    accounts = org_manager.list_accounts()
    ous = org_manager.list_organizational_units()
    
    # Store in session
    st.session_state.multi_account['org_info'] = org_info
    st.session_state.multi_account['accounts'] = accounts
    st.session_state.multi_account['ous'] = ous
    
    # Display org info
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Organization ID", org_info['id'][:15] + "...")
    col2.metric("Total Accounts", len(accounts))
    col3.metric("Organizational Units", len(ous))
    col4.metric("Feature Set", org_info['feature_set'])
    
    st.markdown("---")
    
    # Accounts table
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 📋 Accounts")
        if accounts:
            df = pd.DataFrame(accounts)
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("#### 📁 Organizational Units")
        for ou in ous:
            icon = "🏠" if "Root" in ou['name'] else "📁"
            st.markdown(f"{icon} **{ou['name']}**")
            st.caption(f"`{ou['id']}`")


def render_stackset_deployment():
    """Render StackSet deployment tab"""
    st.markdown("### 🚀 Deploy Config Rules")
    
    org_manager = AWSOrganizationsManager()
    ous = org_manager.list_organizational_units()
    
    # Deployment form
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Target Selection")
        
        # OU selection
        ou_options = {ou['name']: ou['id'] for ou in ous}
        selected_ou_names = st.multiselect(
            "Select Organizational Units",
            options=list(ou_options.keys()),
            default=["Root (All Accounts)"] if "Root (All Accounts)" in ou_options else []
        )
        selected_ous = [ou_options[name] for name in selected_ou_names]
        
        # Region selection
        regions = st.multiselect(
            "Select Regions",
            options=['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'],
            default=['us-east-1']
        )
    
    with col2:
        st.markdown("#### StackSet Configuration")
        
        stackset_name = st.text_input("StackSet Name", value="org-config-rules")
        description = st.text_input("Description", value="Organization-wide Config Rules for Policy as Code")
        
        # Rule selection
        st.markdown("**Config Rules to Deploy:**")
        rules = {
            's3-bucket-encryption-enabled': st.checkbox("S3 Encryption", value=True),
            's3-bucket-public-read-prohibited': st.checkbox("S3 No Public Read", value=True),
            'restricted-ssh': st.checkbox("Restricted SSH", value=True),
            'rds-storage-encrypted': st.checkbox("RDS Encryption", value=True),
            'root-account-mfa-enabled': st.checkbox("Root MFA", value=True),
            'ec2-imdsv2-check': st.checkbox("EC2 IMDSv2", value=True),
        }
    
    st.markdown("---")
    
    # Preview
    with st.expander("📄 Preview CloudFormation Template"):
        st.code(CONFIG_RULES_STACKSET_TEMPLATE, language='yaml')
    
    # Deploy button
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("🚀 Deploy StackSet", type="primary", disabled=not selected_ous or not regions):
            with st.spinner("Creating StackSet..."):
                # Create StackSet
                result = org_manager.create_stackset(
                    name=stackset_name,
                    template=CONFIG_RULES_STACKSET_TEMPLATE,
                    description=description
                )
                
                if result['status'] in ['success', 'demo']:
                    st.success(f"✅ StackSet created: {stackset_name}")
                    
                    # Deploy to OUs
                    deploy_result = org_manager.deploy_to_ous(stackset_name, selected_ous, regions)
                    
                    if deploy_result['status'] in ['success', 'demo']:
                        st.success(f"✅ Deployment initiated to {len(selected_ous)} OUs in {len(regions)} regions")
                        
                        # Log deployment
                        st.session_state.multi_account['deployment_history'].append({
                            'timestamp': datetime.now().isoformat(),
                            'stackset': stackset_name,
                            'ous': selected_ou_names,
                            'regions': regions,
                            'status': 'Initiated'
                        })
                    else:
                        st.error(f"❌ Deployment failed: {deploy_result.get('message')}")
                else:
                    st.error(f"❌ StackSet creation failed: {result.get('message')}")
    
    with col2:
        if st.button("📋 Check Status"):
            stacksets = org_manager.list_stack_sets()
            if stacksets:
                st.markdown("#### Active StackSets")
                for ss in stacksets:
                    status_color = "green" if ss['status'] == 'ACTIVE' else "orange"
                    st.markdown(f"- **{ss['name']}**: :{status_color}[{ss['status']}]")
            else:
                st.info("No StackSets found")


def render_compliance_dashboard():
    """Render cross-account compliance dashboard"""
    st.markdown("### 📊 Organization Compliance Dashboard")
    
    aggregator = ConfigAggregatorManager()
    compliance = aggregator.get_aggregator_compliance()
    
    if compliance.get('status') == 'demo':
        st.info("🔄 Demo Mode - Connect AWS for real compliance data")
    
    # Summary metrics
    by_rule = compliance.get('by_rule', [])
    by_account = compliance.get('by_account', [])
    
    # Safely count compliant rules
    compliant_rules = len([r for r in by_rule if r.get('Compliance', {}).get('ComplianceType') == 'COMPLIANT'])
    total_rules = len(by_rule)
    
    # Safely sum compliant/non-compliant counts
    total_compliant = sum([
        a.get('ComplianceSummary', {}).get('CompliantResourceCount', {}).get('CappedCount', 0) 
        for a in by_account
    ])
    total_non_compliant = sum([
        a.get('ComplianceSummary', {}).get('NonCompliantResourceCount', {}).get('CappedCount', 0) 
        for a in by_account
    ])
    total_resources = total_compliant + total_non_compliant
    
    compliance_score = (total_compliant / total_resources * 100) if total_resources > 0 else 100
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Compliance Score", f"{compliance_score:.1f}%", delta=f"{compliant_rules}/{total_rules} rules passing")
    col2.metric("Compliant Resources", total_compliant)
    col3.metric("Non-Compliant", total_non_compliant, delta_color="inverse")
    col4.metric("Accounts Monitored", len(by_account))
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Compliance by Rule")
        
        rule_data = []
        for rule in by_rule:
            # Safely access nested keys
            compliance = rule.get('Compliance', {})
            contributor_count = compliance.get('ComplianceContributorCount', {})
            
            rule_data.append({
                'Rule': rule.get('ConfigRuleName', 'Unknown').replace('-', ' ').title()[:25],
                'Status': compliance.get('ComplianceType', 'UNKNOWN'),
                'Non-Compliant': contributor_count.get('CappedCount', 0)
            })
        
        if rule_data:
            df_rules = pd.DataFrame(rule_data)
            
            fig = px.bar(
                df_rules,
                x='Rule',
                y='Non-Compliant',
                color='Status',
                color_discrete_map={'COMPLIANT': '#10b981', 'NON_COMPLIANT': '#ef4444', 'UNKNOWN': '#6b7280'},
                title=''
            )
            fig.update_layout(height=300, showlegend=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No rule compliance data available")
    
    with col2:
        st.markdown("#### Compliance by Account")
        
        account_data = []
        for account in by_account:
            # Safely access nested keys
            summary = account.get('ComplianceSummary', {})
            compliant_count = summary.get('CompliantResourceCount', {})
            non_compliant_count = summary.get('NonCompliantResourceCount', {})
            
            compliant = compliant_count.get('CappedCount', 0)
            non_compliant = non_compliant_count.get('CappedCount', 0)
            total = compliant + non_compliant
            score = (compliant / total * 100) if total > 0 else 100
            
            account_data.append({
                'Account': account.get('GroupName', 'Unknown')[-6:],  # Last 6 digits
                'Compliant': compliant,
                'Non-Compliant': non_compliant,
                'Score': f"{score:.0f}%"
            })
        
        if account_data:
            df_accounts = pd.DataFrame(account_data)
            st.dataframe(df_accounts, use_container_width=True, hide_index=True)
        else:
            st.info("No account compliance data available")
    
    # Non-compliant resources detail
    st.markdown("---")
    st.markdown("#### 🔍 Non-Compliant Resources")
    
    rule_names = [r.get('ConfigRuleName', '') for r in by_rule 
                  if r.get('Compliance', {}).get('ComplianceType') == 'NON_COMPLIANT']
    
    if rule_names:
        selected_rule = st.selectbox("Select Rule to View Details", rule_names)
        
        if selected_rule:
            resources = aggregator.get_non_compliant_resources("organization-aggregator", selected_rule)
            
            if resources:
                df_resources = pd.DataFrame(resources)
                st.dataframe(df_resources, use_container_width=True, hide_index=True)
            else:
                st.success("No non-compliant resources found")
    else:
        st.success("✅ All rules are compliant!")


def render_deployment_history():
    """Render deployment history tab"""
    st.markdown("### 📜 Deployment History")
    
    history = st.session_state.multi_account.get('deployment_history', [])
    
    if not history:
        # Add sample history
        history = [
            {'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(), 'stackset': 'org-config-rules', 'ous': ['Production'], 'regions': ['us-east-1'], 'status': 'Completed'},
            {'timestamp': (datetime.now() - timedelta(days=1)).isoformat(), 'stackset': 'security-baseline', 'ous': ['Root'], 'regions': ['us-east-1', 'us-west-2'], 'status': 'Completed'},
            {'timestamp': (datetime.now() - timedelta(days=3)).isoformat(), 'stackset': 'org-config-rules', 'ous': ['Development'], 'regions': ['us-east-1'], 'status': 'Completed'},
        ]
    
    if history:
        df = pd.DataFrame(history)
        df['ous'] = df['ous'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
        df['regions'] = df['regions'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No deployment history yet. Deploy Config Rules to see history.")


def render_cli_commands():
    """Render CLI commands for reference"""
    st.markdown("### 💻 CLI Commands")
    
    st.markdown("Use these PowerShell/AWS CLI commands to manage deployments:")
    
    with st.expander("📦 Create StackSet"):
        st.code('''aws cloudformation create-stack-set --stack-set-name org-config-rules --template-body file://stackset-config-rules.yaml --permission-model SERVICE_MANAGED --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false --capabilities CAPABILITY_NAMED_IAM --region us-east-1''', language='bash')
    
    with st.expander("🚀 Deploy to All Accounts"):
        st.code('''# Get root OU ID
$rootId = aws organizations list-roots --query "Roots[0].Id" --output text

# Deploy to all accounts
aws cloudformation create-stack-instances --stack-set-name org-config-rules --deployment-targets OrganizationalUnitIds=$rootId --regions us-east-1 --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=10''', language='powershell')
    
    with st.expander("📊 Check Compliance"):
        st.code('''# View compliance by account
aws configservice get-aggregate-config-rule-compliance-summary --configuration-aggregator-name organization-aggregator --group-by-key ACCOUNT_ID --output table

# View non-compliant resources
aws configservice get-aggregate-compliance-details-by-config-rule --configuration-aggregator-name organization-aggregator --config-rule-name s3-bucket-encryption-enabled --compliance-type NON_COMPLIANT --output table''', language='powershell')
    
    with st.expander("🔄 Update StackSet"):
        st.code('''aws cloudformation update-stack-set --stack-set-name org-config-rules --template-body file://stackset-config-rules.yaml --capabilities CAPABILITY_NAMED_IAM''', language='bash')
    
    with st.expander("❌ Delete StackSet"):
        st.code('''# Delete stack instances first
aws cloudformation delete-stack-instances --stack-set-name org-config-rules --deployment-targets OrganizationalUnitIds=$rootId --regions us-east-1 --no-retain-stacks

# Wait, then delete StackSet
aws cloudformation delete-stack-set --stack-set-name org-config-rules''', language='powershell')


# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

def render_multi_account_manager():
    """Main entry point for Multi-Account Policy Manager"""
    
    # Initialize state
    init_multi_account_state()
    
    # Header
    st.markdown("""
    <div style='background: linear-gradient(135deg, #1e40af 0%, #3b82f6 50%, #60a5fa 100%); 
                padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>🌐 Multi-Account Policy Manager</h2>
        <p style='color: #bfdbfe; margin: 0.5rem 0 0 0;'>
            Deploy and manage policies across AWS Organizations
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Connection status - check session state (where main app stores credentials)
    aws_connected = st.session_state.get('aws_connected', False)
    aws_account_id = st.session_state.get('aws_account_id')
    demo_mode = st.session_state.get('demo_mode', False)
    
    if aws_connected and aws_account_id and not demo_mode:
        st.success(f"✅ Connected to AWS Account: {aws_account_id}")
    elif demo_mode:
        st.info("📋 Demo Mode - showing sample data")
    else:
        # Try to check via session state clients
        clients = st.session_state.get('aws_clients', {})
        if clients.get('organizations') or clients.get('sts'):
            st.success("✅ AWS credentials available via session")
        else:
            st.warning("⚠️ AWS credentials not detected - connect via sidebar")
    
    # Main tabs
    tabs = st.tabs([
        "🏢 Organization",
        "🚀 Deploy Rules",
        "📊 Compliance",
        "📜 History",
        "💻 CLI Commands"
    ])
    
    with tabs[0]:
        render_organization_overview()
    
    with tabs[1]:
        render_stackset_deployment()
    
    with tabs[2]:
        render_compliance_dashboard()
    
    with tabs[3]:
        render_deployment_history()
    
    with tabs[4]:
        render_cli_commands()


# ============================================================================
# EXPORT
# ============================================================================

__all__ = ['render_multi_account_manager']


# For testing
if __name__ == "__main__":
    st.set_page_config(page_title="Multi-Account Manager", layout="wide")
    render_multi_account_manager()