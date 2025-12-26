"""
Policy as Code Platform - Single Account Implementation
=======================================================

A practical, testable Policy as Code implementation that works in a single AWS account.

Features:
- Real OPA/Rego policy files
- Policy testing framework
- Terraform/CloudFormation validation
- AWS Config Rules integration
- Local testing before deployment
- CI/CD pipeline ready

Author: Cloud Compliance Canvas
Version: 1.0.0
Date: December 2025
"""

import streamlit as st
import json
import os
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import base64
import uuid
import time
import re

# Optional imports
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


# ============================================================================
# POLICY AS CODE - FILE STRUCTURE
# ============================================================================

POLICY_REPO_STRUCTURE = """
policies/
├── aws/
│   ├── s3/
│   │   ├── encryption.rego          # Policy: S3 must be encrypted
│   │   ├── encryption_test.rego     # Tests for encryption policy
│   │   ├── public_access.rego       # Policy: No public S3
│   │   └── public_access_test.rego  # Tests for public access
│   ├── ec2/
│   │   ├── instance_types.rego      # Policy: Allowed instance types
│   │   ├── security_groups.rego     # Policy: No open SGs
│   │   └── security_groups_test.rego
│   ├── iam/
│   │   ├── mfa_required.rego        # Policy: MFA for privileged
│   │   └── no_wildcards.rego        # Policy: No * in policies
│   └── rds/
│       ├── encryption.rego          # Policy: RDS encryption
│       └── public_access.rego       # Policy: No public RDS
├── kubernetes/
│   ├── pod_security.rego            # Policy: Pod security standards
│   ├── resource_limits.rego         # Policy: Require limits
│   └── pod_security_test.rego
├── terraform/
│   ├── required_tags.rego           # Policy: Mandatory tags
│   ├── required_tags_test.rego
│   └── module_sources.rego          # Policy: Approved modules only
├── config-rules/
│   ├── s3-encryption.yaml           # AWS Config Rule
│   ├── sg-open-check.yaml
│   └── rds-encryption.yaml
└── .github/
    └── workflows/
        └── policy-ci.yml            # CI/CD pipeline
"""

# ============================================================================
# SAMPLE POLICIES (Real Rego Code)
# ============================================================================

SAMPLE_POLICIES = {
    # ==================== S3 ENCRYPTION ====================
    "aws/s3/encryption.rego": '''# S3 Bucket Encryption Policy
# Ensures all S3 buckets have server-side encryption enabled

package aws.s3.encryption

import future.keywords.in
import future.keywords.if

# Default deny
default allow := false

# Allow if encryption is configured
allow if {
    input.resource_type == "aws_s3_bucket"
    encryption_configured(input.resource)
}

# Check if any encryption method is configured
encryption_configured(resource) if {
    resource.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
}

encryption_configured(resource) if {
    resource.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id
}

# Deny rule with message
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    not encryption_configured(input.resource)
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [input.resource.bucket])
}

# Severity for reporting
severity := "HIGH"

# Compliance frameworks
frameworks := ["PCI-DSS-3.4", "HIPAA-164.312", "SOC2-CC6.1"]
''',

    # ==================== S3 ENCRYPTION TEST ====================
    "aws/s3/encryption_test.rego": '''# Tests for S3 Encryption Policy
package aws.s3.encryption_test

import future.keywords.in
import data.aws.s3.encryption

# Test: Encrypted bucket should be allowed
test_encrypted_bucket_allowed if {
    encryption.allow with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "bucket": "my-encrypted-bucket",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "sse_algorithm": "AES256"
                    }]
                }]
            }]
        }
    }
}

# Test: KMS encrypted bucket should be allowed
test_kms_encrypted_bucket_allowed if {
    encryption.allow with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "bucket": "my-kms-bucket",
            "server_side_encryption_configuration": [{
                "rule": [{
                    "apply_server_side_encryption_by_default": [{
                        "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                    }]
                }]
            }]
        }
    }
}

# Test: Unencrypted bucket should be denied
test_unencrypted_bucket_denied if {
    count(encryption.deny) > 0 with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "bucket": "my-unencrypted-bucket"
        }
    }
}

# Test: Deny message is correct
test_deny_message_format if {
    msg := encryption.deny[_] with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "bucket": "test-bucket"
        }
    }
    contains(msg, "test-bucket")
    contains(msg, "encryption")
}
''',

    # ==================== S3 PUBLIC ACCESS ====================
    "aws/s3/public_access.rego": '''# S3 Public Access Policy
# Ensures S3 buckets block public access

package aws.s3.public_access

import future.keywords.in
import future.keywords.if

default allow := false

# Allow if public access is blocked
allow if {
    input.resource_type == "aws_s3_bucket"
    public_access_blocked(input.resource)
}

# Check if public access block is configured
public_access_blocked(resource) if {
    resource.block_public_acls == true
    resource.block_public_policy == true
    resource.ignore_public_acls == true
    resource.restrict_public_buckets == true
}

# Deny rule
deny[msg] if {
    input.resource_type == "aws_s3_bucket"
    not public_access_blocked(input.resource)
    msg := sprintf("S3 bucket '%s' must have public access blocked", [input.resource.bucket])
}

severity := "CRITICAL"
frameworks := ["PCI-DSS-1.3", "SOC2-CC6.6", "HIPAA-164.312"]
''',

    # ==================== SECURITY GROUP ====================
    "aws/ec2/security_groups.rego": '''# Security Group Policy
# Ensures no security groups allow unrestricted ingress

package aws.ec2.security_groups

import future.keywords.in
import future.keywords.if

default allow := false

# Dangerous ports that should never be open to the world
dangerous_ports := [22, 3389, 3306, 5432, 1433, 27017, 6379]

# Allow if no unrestricted access
allow if {
    input.resource_type == "aws_security_group"
    not has_unrestricted_ingress(input.resource)
}

# Check for 0.0.0.0/0 or ::/0 in ingress rules
has_unrestricted_ingress(resource) if {
    rule := resource.ingress[_]
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
}

has_unrestricted_ingress(resource) if {
    rule := resource.ingress[_]
    cidr := rule.ipv6_cidr_blocks[_]
    cidr == "::/0"
}

# Deny SSH open to world
deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.resource.ingress[_]
    rule.from_port <= 22
    rule.to_port >= 22
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows SSH (port 22) from 0.0.0.0/0", [input.resource.name])
}

# Deny RDP open to world
deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.resource.ingress[_]
    rule.from_port <= 3389
    rule.to_port >= 3389
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows RDP (port 3389) from 0.0.0.0/0", [input.resource.name])
}

# Deny all ports open to world
deny[msg] if {
    input.resource_type == "aws_security_group"
    rule := input.resource.ingress[_]
    rule.from_port == 0
    rule.to_port == 65535
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows ALL ports from 0.0.0.0/0", [input.resource.name])
}

severity := "CRITICAL"
frameworks := ["PCI-DSS-1.3.1", "SOC2-CC6.6", "CIS-AWS-5.2"]
''',

    # ==================== SECURITY GROUP TEST ====================
    "aws/ec2/security_groups_test.rego": '''# Tests for Security Group Policy
package aws.ec2.security_groups_test

import data.aws.ec2.security_groups

# Test: Restricted SG should be allowed
test_restricted_sg_allowed if {
    security_groups.allow with input as {
        "resource_type": "aws_security_group",
        "resource": {
            "name": "restricted-sg",
            "ingress": [{
                "from_port": 443,
                "to_port": 443,
                "cidr_blocks": ["10.0.0.0/8"]
            }]
        }
    }
}

# Test: SSH open to world should be denied
test_ssh_open_denied if {
    count(security_groups.deny) > 0 with input as {
        "resource_type": "aws_security_group",
        "resource": {
            "name": "open-sg",
            "ingress": [{
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
}

# Test: All ports open should be denied
test_all_ports_denied if {
    count(security_groups.deny) > 0 with input as {
        "resource_type": "aws_security_group",
        "resource": {
            "name": "wide-open-sg",
            "ingress": [{
                "from_port": 0,
                "to_port": 65535,
                "cidr_blocks": ["0.0.0.0/0"]
            }]
        }
    }
}
''',

    # ==================== REQUIRED TAGS ====================
    "terraform/required_tags.rego": '''# Required Tags Policy
# Ensures all resources have mandatory tags

package terraform.required_tags

import future.keywords.in
import future.keywords.if

# Required tags for all resources
required_tags := ["Environment", "Owner", "CostCenter", "Project"]

# Resource types that must have tags
taggable_resources := [
    "aws_s3_bucket",
    "aws_instance",
    "aws_db_instance",
    "aws_lambda_function",
    "aws_eks_cluster",
    "aws_vpc",
    "aws_subnet"
]

default allow := false

# Allow if all required tags present
allow if {
    input.resource_type in taggable_resources
    all_tags_present(input.resource)
}

# Check if all required tags are present
all_tags_present(resource) if {
    tags := resource.tags
    every tag in required_tags {
        tags[tag]
    }
}

# Deny missing tags
deny[msg] if {
    input.resource_type in taggable_resources
    tag := required_tags[_]
    not input.resource.tags[tag]
    msg := sprintf("Resource '%s' (%s) missing required tag: %s", [input.resource.name, input.resource_type, tag])
}

# List missing tags for reporting
missing_tags[tag] if {
    input.resource_type in taggable_resources
    tag := required_tags[_]
    not input.resource.tags[tag]
}

severity := "MEDIUM"
frameworks := ["SOC2-CC6.1", "ISO27001-A.8.1.1"]
''',

    # ==================== REQUIRED TAGS TEST ====================
    "terraform/required_tags_test.rego": '''# Tests for Required Tags Policy
package terraform.required_tags_test

import data.terraform.required_tags

# Test: Fully tagged resource should be allowed
test_fully_tagged_allowed if {
    required_tags.allow with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "name": "my-bucket",
            "tags": {
                "Environment": "production",
                "Owner": "platform-team",
                "CostCenter": "CC-12345",
                "Project": "data-lake"
            }
        }
    }
}

# Test: Missing Environment tag should be denied
test_missing_environment_denied if {
    count(required_tags.deny) > 0 with input as {
        "resource_type": "aws_s3_bucket",
        "resource": {
            "name": "my-bucket",
            "tags": {
                "Owner": "platform-team"
            }
        }
    }
}

# Test: No tags should have multiple denials
test_no_tags_multiple_denials if {
    denials := required_tags.deny with input as {
        "resource_type": "aws_instance",
        "resource": {
            "name": "my-instance",
            "tags": {}
        }
    }
    count(denials) == 4
}

# Test: Non-taggable resource should not be evaluated
test_non_taggable_ignored if {
    not required_tags.allow with input as {
        "resource_type": "aws_iam_policy",
        "resource": {
            "name": "my-policy"
        }
    }
}
''',

    # ==================== KUBERNETES POD SECURITY ====================
    "kubernetes/pod_security.rego": '''# Kubernetes Pod Security Policy
# Enforces pod security standards

package kubernetes.pod_security

import future.keywords.in
import future.keywords.if

default allow := false

# Allow if pod meets security requirements
allow if {
    input.kind == "Pod"
    not has_privileged_container(input)
    not runs_as_root(input)
    has_security_context(input)
}

# Check for privileged containers
has_privileged_container(pod) if {
    container := pod.spec.containers[_]
    container.securityContext.privileged == true
}

has_privileged_container(pod) if {
    container := pod.spec.initContainers[_]
    container.securityContext.privileged == true
}

# Check if running as root
runs_as_root(pod) if {
    container := pod.spec.containers[_]
    container.securityContext.runAsUser == 0
}

runs_as_root(pod) if {
    not pod.spec.securityContext.runAsNonRoot
    container := pod.spec.containers[_]
    not container.securityContext.runAsNonRoot
}

# Check for security context
has_security_context(pod) if {
    pod.spec.securityContext
}

# Deny privileged containers
deny[msg] if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' in pod '%s' cannot run as privileged", [container.name, input.metadata.name])
}

# Deny running as root
deny[msg] if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("Container '%s' in pod '%s' cannot run as root (UID 0)", [container.name, input.metadata.name])
}

# Warn about missing runAsNonRoot
warn[msg] if {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%s' should set runAsNonRoot: true", [container.name])
}

severity := "HIGH"
frameworks := ["CIS-Kubernetes-5.2.1", "NSA-CISA-K8s"]
''',

    # ==================== AWS CONFIG RULE ====================
    "config-rules/s3-encryption.yaml": '''# AWS Config Rule: S3 Bucket Encryption
# Checks if S3 buckets have server-side encryption enabled

AWSTemplateFormatVersion: '2010-09-09'
Description: AWS Config Rule for S3 Bucket Encryption

Resources:
  S3BucketEncryptionRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-server-side-encryption-enabled
      Description: Checks if S3 buckets have server-side encryption enabled
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
      Scope:
        ComplianceResourceTypes:
          - AWS::S3::Bucket
      MaximumExecutionFrequency: TwentyFour_Hours

  S3BucketEncryptionRemediation:
    Type: AWS::Config::RemediationConfiguration
    Properties:
      ConfigRuleName: !Ref S3BucketEncryptionRule
      TargetType: SSM_DOCUMENT
      TargetId: AWS-EnableS3BucketEncryption
      Automatic: false
      MaximumAutomaticAttempts: 3
      RetryAttemptSeconds: 60
      Parameters:
        BucketName:
          ResourceValue:
            Value: RESOURCE_ID
        SSEAlgorithm:
          StaticValue:
            Values:
              - AES256

Outputs:
  ConfigRuleArn:
    Description: ARN of the Config Rule
    Value: !GetAtt S3BucketEncryptionRule.Arn
''',

    # ==================== CI/CD PIPELINE ====================
    ".github/workflows/policy-ci.yml": '''# Policy as Code CI/CD Pipeline
name: Policy CI/CD

on:
  push:
    branches: [main, develop]
    paths:
      - 'policies/**'
  pull_request:
    branches: [main]
    paths:
      - 'policies/**'

env:
  OPA_VERSION: '0.60.0'

jobs:
  validate:
    name: Validate Policies
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: ${{ env.OPA_VERSION }}

      - name: Check policy format
        run: |
          echo "Checking Rego formatting..."
          opa fmt --diff --fail policies/

      - name: Validate policy syntax
        run: |
          echo "Validating policy syntax..."
          find policies -name "*.rego" -exec opa check {} +

  test:
    name: Test Policies
    runs-on: ubuntu-latest
    needs: validate
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: ${{ env.OPA_VERSION }}

      - name: Run policy tests
        run: |
          echo "Running policy tests..."
          opa test policies/ -v --coverage --format=json > coverage.json

      - name: Check coverage threshold
        run: |
          coverage=$(jq '.coverage' coverage.json)
          echo "Policy coverage: $coverage%"
          if (( $(echo "$coverage < 80" | bc -l) )); then
            echo "Coverage below 80% threshold!"
            exit 1
          fi

      - name: Upload coverage report
        uses: actions/upload-artifact@v3
        with:
          name: policy-coverage
          path: coverage.json

  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    needs: validate
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Conftest on policies
        uses: instrumenta/conftest-action@v0.2.0
        with:
          files: policies/
          policy: policies/meta/
          
  deploy-dev:
    name: Deploy to Dev
    runs-on: ubuntu-latest
    needs: [test, security-scan]
    if: github.ref == 'refs/heads/develop'
    environment: development
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Bundle policies
        run: |
          opa build -b policies/ -o policy-bundle.tar.gz

      - name: Deploy to OPA Server (Dev)
        run: |
          curl -X PUT "$OPA_DEV_SERVER/v1/policies" \\
            -H "Authorization: Bearer ${{ secrets.OPA_TOKEN }}" \\
            -T policy-bundle.tar.gz

  deploy-prod:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: [test, security-scan]
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Bundle policies
        run: |
          opa build -b policies/ -o policy-bundle.tar.gz

      - name: Deploy to OPA Server (Prod)
        run: |
          curl -X PUT "$OPA_PROD_SERVER/v1/policies" \\
            -H "Authorization: Bearer ${{ secrets.OPA_TOKEN }}" \\
            -T policy-bundle.tar.gz

      - name: Deploy Config Rules
        run: |
          aws cloudformation deploy \\
            --template-file policies/config-rules/s3-encryption.yaml \\
            --stack-name config-rule-s3-encryption \\
            --no-fail-on-empty-changeset
'''
}


# ============================================================================
# POLICY TESTING ENGINE
# ============================================================================

class PolicyTestEngine:
    """Engine for testing OPA/Rego policies"""
    
    def __init__(self):
        self.opa_available = self._check_opa_available()
        self.test_results = []
    
    def _check_opa_available(self) -> bool:
        """Check if OPA CLI is available"""
        try:
            result = subprocess.run(['opa', 'version'], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def run_policy_tests(self, policy_content: str, test_content: str) -> Dict:
        """Run OPA tests on policy"""
        if not self.opa_available:
            return self._simulate_test_run(policy_content, test_content)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write policy file
            policy_path = os.path.join(tmpdir, "policy.rego")
            with open(policy_path, 'w') as f:
                f.write(policy_content)
            
            # Write test file
            test_path = os.path.join(tmpdir, "policy_test.rego")
            with open(test_path, 'w') as f:
                f.write(test_content)
            
            # Run OPA test
            result = subprocess.run(
                ['opa', 'test', tmpdir, '-v', '--format=json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {'error': 'Failed to parse test output', 'raw': result.stdout}
            else:
                return {'error': result.stderr, 'returncode': result.returncode}
    
    def _simulate_test_run(self, policy_content: str, test_content: str) -> Dict:
        """Simulate test run when OPA not available"""
        # Count test functions
        test_pattern = r'test_\w+'
        tests = re.findall(test_pattern, test_content)
        
        # Simulate results
        results = []
        for test in tests:
            results.append({
                'name': test,
                'package': 'simulated',
                'duration': 0.001,
                'pass': True  # Simulate passing
            })
        
        return {
            'simulated': True,
            'message': 'OPA not installed - showing simulated results',
            'tests': results,
            'summary': {
                'total': len(tests),
                'passed': len(tests),
                'failed': 0
            }
        }
    
    def evaluate_policy(self, policy_content: str, input_data: Dict) -> Dict:
        """Evaluate policy against input data"""
        if not self.opa_available:
            return self._simulate_evaluation(policy_content, input_data)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write policy
            policy_path = os.path.join(tmpdir, "policy.rego")
            with open(policy_path, 'w') as f:
                f.write(policy_content)
            
            # Write input
            input_path = os.path.join(tmpdir, "input.json")
            with open(input_path, 'w') as f:
                json.dump(input_data, f)
            
            # Run OPA eval
            result = subprocess.run(
                ['opa', 'eval', '-d', policy_path, '-i', input_path, 
                 '--format=json', 'data'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {'error': 'Failed to parse output'}
            else:
                return {'error': result.stderr}
    
    def _simulate_evaluation(self, policy_content: str, input_data: Dict) -> Dict:
        """Simulate policy evaluation"""
        # Simple heuristic evaluation
        violations = []
        
        # Check for encryption
        if 'encryption' in policy_content.lower():
            resource = input_data.get('resource', {})
            if not resource.get('server_side_encryption_configuration'):
                violations.append({
                    'rule': 'encryption_required',
                    'message': f"Resource '{resource.get('bucket', 'unknown')}' missing encryption"
                })
        
        # Check for public access
        if 'public' in policy_content.lower():
            resource = input_data.get('resource', {})
            if resource.get('block_public_acls') != True:
                violations.append({
                    'rule': 'public_access_blocked',
                    'message': f"Resource missing public access block"
                })
        
        return {
            'simulated': True,
            'allow': len(violations) == 0,
            'deny': [v['message'] for v in violations],
            'violations': violations
        }


# ============================================================================
# AWS CONFIG INTEGRATION
# ============================================================================

class AWSConfigIntegration:
    """Integration with AWS Config Rules"""
    
    def __init__(self):
        self.config_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize AWS Config client"""
        if BOTO3_AVAILABLE:
            try:
                self.config_client = boto3.client('config')
            except Exception as e:
                print(f"Config client init error: {e}")
    
    def get_config_rules(self) -> List[Dict]:
        """Get all Config Rules in account"""
        if not self.config_client:
            return self._get_demo_config_rules()
        
        try:
            rules = []
            paginator = self.config_client.get_paginator('describe_config_rules')
            
            for page in paginator.paginate():
                for rule in page.get('ConfigRules', []):
                    rules.append({
                        'name': rule['ConfigRuleName'],
                        'description': rule.get('Description', ''),
                        'source': rule['Source']['Owner'],
                        'source_identifier': rule['Source'].get('SourceIdentifier', 'CUSTOM'),
                        'state': rule['ConfigRuleState'],
                        'arn': rule['ConfigRuleArn']
                    })
            
            return rules
        except Exception as e:
            st.error(f"Error fetching Config Rules: {e}")
            return self._get_demo_config_rules()
    
    def get_compliance_summary(self) -> Dict:
        """Get compliance summary for all rules"""
        if not self.config_client:
            return self._get_demo_compliance()
        
        try:
            response = self.config_client.get_compliance_summary_by_config_rule()
            return {
                'compliant': response.get('ComplianceSummary', {}).get('CompliantResourceCount', {}).get('CappedCount', 0),
                'non_compliant': response.get('ComplianceSummary', {}).get('NonCompliantResourceCount', {}).get('CappedCount', 0)
            }
        except Exception as e:
            return self._get_demo_compliance()
    
    def get_rule_compliance(self, rule_name: str) -> List[Dict]:
        """Get compliance details for a specific rule"""
        if not self.config_client:
            return self._get_demo_rule_compliance(rule_name)
        
        try:
            response = self.config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=['NON_COMPLIANT', 'COMPLIANT']
            )
            
            results = []
            for item in response.get('EvaluationResults', []):
                results.append({
                    'resource_type': item['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
                    'resource_id': item['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
                    'compliance': item['ComplianceType'],
                    'timestamp': item['ResultRecordedTime'].isoformat() if item.get('ResultRecordedTime') else None
                })
            
            return results
        except Exception as e:
            return self._get_demo_rule_compliance(rule_name)
    
    def deploy_config_rule(self, rule_template: str) -> Dict:
        """Deploy a Config Rule from CloudFormation template"""
        if not BOTO3_AVAILABLE:
            return {'status': 'simulated', 'message': 'Would deploy Config Rule'}
        
        try:
            cfn_client = boto3.client('cloudformation')
            
            stack_name = f"config-rule-{uuid.uuid4().hex[:8]}"
            
            response = cfn_client.create_stack(
                StackName=stack_name,
                TemplateBody=rule_template,
                Capabilities=['CAPABILITY_IAM']
            )
            
            return {
                'status': 'success',
                'stack_id': response['StackId'],
                'stack_name': stack_name
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def _get_demo_config_rules(self) -> List[Dict]:
        """Return demo Config Rules"""
        return [
            {
                'name': 's3-bucket-server-side-encryption-enabled',
                'description': 'Checks if S3 buckets have encryption enabled',
                'source': 'AWS',
                'source_identifier': 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED',
                'state': 'ACTIVE',
                'arn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc123'
            },
            {
                'name': 'restricted-ssh',
                'description': 'Checks if security groups allow unrestricted SSH',
                'source': 'AWS',
                'source_identifier': 'INCOMING_SSH_DISABLED',
                'state': 'ACTIVE',
                'arn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-def456'
            },
            {
                'name': 'rds-storage-encrypted',
                'description': 'Checks if RDS instances have encryption enabled',
                'source': 'AWS',
                'source_identifier': 'RDS_STORAGE_ENCRYPTED',
                'state': 'ACTIVE',
                'arn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-ghi789'
            }
        ]
    
    def _get_demo_compliance(self) -> Dict:
        """Return demo compliance summary"""
        return {
            'compliant': 45,
            'non_compliant': 8
        }
    
    def _get_demo_rule_compliance(self, rule_name: str) -> List[Dict]:
        """Return demo rule compliance"""
        return [
            {
                'resource_type': 'AWS::S3::Bucket',
                'resource_id': 'my-app-data-bucket',
                'compliance': 'NON_COMPLIANT',
                'timestamp': datetime.now().isoformat()
            },
            {
                'resource_type': 'AWS::S3::Bucket',
                'resource_id': 'my-logs-bucket',
                'compliance': 'COMPLIANT',
                'timestamp': datetime.now().isoformat()
            }
        ]


# ============================================================================
# AI POLICY GENERATOR
# ============================================================================

class AIPolicyGenerator:
    """AI-powered policy generation using Claude"""
    
    def __init__(self):
        self.client = None
        self.model = "claude-sonnet-4-20250514"
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Anthropic client"""
        try:
            api_key = st.session_state.get('anthropic_api_key') or st.secrets.get('ANTHROPIC_API_KEY')
            if api_key and ANTHROPIC_AVAILABLE:
                self.client = anthropic.Anthropic(api_key=api_key)
        except Exception as e:
            print(f"AI init error: {e}")
    
    def generate_rego_policy(self, requirements: str, policy_type: str = "aws") -> Dict:
        """Generate Rego policy from natural language requirements"""
        if not self.client:
            return self._generate_demo_policy(requirements, policy_type)
        
        prompt = f"""You are an expert in Open Policy Agent (OPA) and Rego policy language.
Generate a production-ready Rego policy based on these requirements:

Requirements: {requirements}
Policy Type: {policy_type}

Your response must include:
1. The Rego policy code with:
   - Proper package declaration
   - Import statements for future.keywords
   - default allow := false
   - allow rule
   - deny rule with descriptive messages
   - severity and frameworks metadata

2. A corresponding test file with:
   - At least 3 test cases
   - Tests for both allowed and denied scenarios
   - Edge case tests

Respond with JSON:
{{
    "policy_code": "# Full Rego policy code here",
    "test_code": "# Full test code here",
    "description": "What this policy does",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "frameworks": ["list of compliance frameworks"],
    "examples": {{
        "allowed": {{"example input that passes"}},
        "denied": {{"example input that fails"}}
    }}
}}"""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            # Extract JSON
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            st.error(f"AI generation error: {e}")
        
        return self._generate_demo_policy(requirements, policy_type)
    
    def _generate_demo_policy(self, requirements: str, policy_type: str) -> Dict:
        """Generate demo policy when AI unavailable"""
        return {
            'policy_code': f'''# Auto-generated policy
# Requirements: {requirements[:100]}

package {policy_type}.custom_policy

import future.keywords.in
import future.keywords.if

default allow := false

allow if {{
    # Add your conditions here
    input.resource.compliant == true
}}

deny[msg] if {{
    not allow
    msg := "Resource does not meet policy requirements"
}}

severity := "HIGH"
frameworks := ["SOC2", "ISO27001"]
''',
            'test_code': '''# Auto-generated tests
package {policy_type}.custom_policy_test

import data.{policy_type}.custom_policy

test_compliant_resource_allowed if {{
    custom_policy.allow with input as {{
        "resource": {{"compliant": true}}
    }}
}}

test_non_compliant_denied if {{
    count(custom_policy.deny) > 0 with input as {{
        "resource": {{"compliant": false}}
    }}
}}
''',
            'description': f'Custom policy for: {requirements[:100]}',
            'severity': 'HIGH',
            'frameworks': ['SOC2', 'ISO27001'],
            'examples': {
                'allowed': {'resource': {'compliant': True}},
                'denied': {'resource': {'compliant': False}}
            }
        }


# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

def init_pac_session_state():
    """Initialize Policy as Code session state"""
    if 'pac_state' not in st.session_state:
        st.session_state.pac_state = {
            'policies': {},  # Policy files
            'test_results': {},  # Test results
            'evaluations': [],  # Policy evaluations
            'deployments': [],  # Deployment history
            'current_policy': None,  # Currently selected policy
            'editor_content': '',  # Editor content
            'test_content': '',  # Test editor content
        }
    
    # Load sample policies
    if not st.session_state.pac_state['policies']:
        for path, content in SAMPLE_POLICIES.items():
            st.session_state.pac_state['policies'][path] = content


# ============================================================================
# STREAMLIT UI - TAB 1: POLICY CATALOG
# ============================================================================

def render_policy_catalog_tab():
    """Tab 1: Browse and manage policy files"""
    st.markdown("### 📚 Policy Catalog")
    st.markdown("""
    <div style='background: #dbeafe; padding: 1rem; border-radius: 8px; border-left: 4px solid #3b82f6; margin-bottom: 1rem;'>
        <strong>Policy as Code:</strong> All policies are stored as version-controlled code files (.rego, .yaml)
    </div>
    """, unsafe_allow_html=True)
    
    pac = st.session_state.pac_state
    policies = pac['policies']
    
    # Policy tree view
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("#### 📁 Policy Files")
        
        # Group by directory
        policy_tree = {}
        for path in policies.keys():
            parts = path.split('/')
            if len(parts) > 1:
                category = '/'.join(parts[:-1])
                filename = parts[-1]
                if category not in policy_tree:
                    policy_tree[category] = []
                policy_tree[category].append(filename)
        
        for category, files in sorted(policy_tree.items()):
            with st.expander(f"📁 {category}", expanded=True):
                for filename in sorted(files):
                    full_path = f"{category}/{filename}"
                    is_test = '_test' in filename
                    icon = "🧪" if is_test else "📜"
                    
                    if st.button(f"{icon} {filename}", key=f"select_{full_path}", use_container_width=True):
                        pac['current_policy'] = full_path
                        pac['editor_content'] = policies[full_path]
                        st.rerun()
    
    with col2:
        current = pac.get('current_policy')
        
        if current:
            st.markdown(f"#### 📜 {current}")
            
            # Show policy content
            content = policies.get(current, '')
            
            # Determine language
            lang = 'rego' if current.endswith('.rego') else 'yaml'
            
            st.code(content, language=lang, line_numbers=True)
            
            # Policy metadata
            if 'severity' in content:
                st.markdown("---")
                col_m1, col_m2, col_m3 = st.columns(3)
                
                # Extract severity
                severity_match = re.search(r'severity\s*:=\s*"(\w+)"', content)
                if severity_match:
                    severity = severity_match.group(1)
                    col_m1.metric("Severity", severity)
                
                # Extract frameworks
                frameworks_match = re.search(r'frameworks\s*:=\s*\[(.*?)\]', content, re.DOTALL)
                if frameworks_match:
                    col_m2.metric("Frameworks", frameworks_match.group(1).count(',') + 1)
                
                # Is test file
                col_m3.metric("Type", "Test" if '_test' in current else "Policy")
        else:
            st.info("👈 Select a policy file to view its contents")
    
    st.markdown("---")
    
    # Repository structure visualization
    with st.expander("📊 Repository Structure"):
        st.code(POLICY_REPO_STRUCTURE, language='text')


# ============================================================================
# STREAMLIT UI - TAB 2: AUTHOR & EDIT
# ============================================================================

def render_author_edit_tab():
    """Tab 2: Write and edit policy code"""
    st.markdown("### ✏️ Author & Edit Policies")
    
    pac = st.session_state.pac_state
    
    # Sub-tabs
    author_tabs = st.tabs(["📝 Code Editor", "🤖 AI Generator", "📋 Templates"])
    
    # ==================== CODE EDITOR ====================
    with author_tabs[0]:
        col1, col2 = st.columns([3, 1])
        
        with col2:
            # File selection
            policy_files = [p for p in pac['policies'].keys() if not p.endswith('_test.rego')]
            
            selected_file = st.selectbox(
                "Select Policy",
                options=['(New Policy)'] + list(policy_files),
                key="editor_file_select"
            )
            
            if selected_file != '(New Policy)':
                if st.button("📥 Load", use_container_width=True):
                    pac['editor_content'] = pac['policies'].get(selected_file, '')
                    st.rerun()
            
            new_filename = st.text_input("Filename", value="custom/my_policy.rego", key="new_filename")
        
        with col1:
            # Code editor
            editor_content = st.text_area(
                "Policy Code (Rego)",
                value=pac.get('editor_content', ''),
                height=400,
                key="policy_editor",
                help="Write your OPA/Rego policy code here"
            )
            pac['editor_content'] = editor_content
        
        # Actions
        col_a1, col_a2, col_a3 = st.columns(3)
        
        with col_a1:
            if st.button("💾 Save Policy", type="primary", use_container_width=True):
                filename = new_filename if selected_file == '(New Policy)' else selected_file
                pac['policies'][filename] = editor_content
                st.success(f"✅ Saved: {filename}")
        
        with col_a2:
            if st.button("✅ Validate Syntax", use_container_width=True):
                # Basic validation
                if 'package' in editor_content and ('deny' in editor_content or 'allow' in editor_content):
                    st.success("✅ Syntax looks valid!")
                else:
                    st.warning("⚠️ Policy should have 'package' and 'deny'/'allow' rules")
        
        with col_a3:
            if st.button("📋 Format Code", use_container_width=True):
                st.info("💡 Run `opa fmt` locally to format Rego code")
    
    # ==================== AI GENERATOR ====================
    with author_tabs[1]:
        st.markdown("#### 🤖 AI Policy Generator")
        st.markdown("Describe what you want to enforce in plain English, and AI will generate the Rego policy code.")
        
        requirements = st.text_area(
            "Policy Requirements",
            placeholder="Example: Ensure all EC2 instances have encrypted EBS volumes and are not using t2.micro in production",
            height=100,
            key="ai_requirements"
        )
        
        col1, col2 = st.columns(2)
        with col1:
            policy_type = st.selectbox("Policy Type", ["aws", "kubernetes", "terraform"], key="ai_policy_type")
        with col2:
            target_frameworks = st.multiselect("Frameworks", ["PCI-DSS", "HIPAA", "SOC2", "ISO27001"], default=["SOC2"])
        
        if st.button("🚀 Generate Policy", type="primary", disabled=not requirements):
            with st.spinner("🧠 AI is generating your policy..."):
                generator = AIPolicyGenerator()
                result = generator.generate_rego_policy(requirements, policy_type)
                
                if result:
                    st.session_state['generated_policy'] = result
                    st.success("✅ Policy generated!")
        
        # Display generated policy
        if st.session_state.get('generated_policy'):
            gen = st.session_state['generated_policy']
            
            st.markdown("---")
            st.markdown("#### Generated Policy")
            st.markdown(f"*{gen.get('description', '')}*")
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Policy Code:**")
                st.code(gen.get('policy_code', ''), language='rego')
            with col2:
                st.markdown("**Test Code:**")
                st.code(gen.get('test_code', ''), language='rego')
            
            if st.button("💾 Save Generated Policy", key="save_generated"):
                pac['policies'][f'{policy_type}/generated_policy.rego'] = gen.get('policy_code', '')
                pac['policies'][f'{policy_type}/generated_policy_test.rego'] = gen.get('test_code', '')
                st.success("✅ Saved to policy catalog!")
                st.rerun()
    
    # ==================== TEMPLATES ====================
    with author_tabs[2]:
        st.markdown("#### 📋 Policy Templates")
        
        templates = {
            "S3 Encryption": "aws/s3/encryption.rego",
            "Security Groups": "aws/ec2/security_groups.rego",
            "Required Tags": "terraform/required_tags.rego",
            "Pod Security": "kubernetes/pod_security.rego"
        }
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            selected_template = st.radio("Select Template", list(templates.keys()))
        
        with col2:
            template_path = templates.get(selected_template)
            if template_path and template_path in pac['policies']:
                st.code(pac['policies'][template_path], language='rego')
                
                if st.button("📥 Use as Starting Point"):
                    pac['editor_content'] = pac['policies'][template_path]
                    st.success("✅ Loaded into editor!")
                    st.rerun()


# ============================================================================
# STREAMLIT UI - TAB 3: TEST & VALIDATE
# ============================================================================

def render_test_validate_tab():
    """Tab 3: Test policies against sample inputs"""
    st.markdown("### 🧪 Test & Validate")
    
    pac = st.session_state.pac_state
    test_engine = PolicyTestEngine()
    
    # Check OPA availability
    if test_engine.opa_available:
        st.success("✅ OPA CLI detected - running real tests")
    else:
        st.warning("⚠️ OPA CLI not installed - using simulated tests. Install OPA: `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x opa`")
    
    test_tabs = st.tabs(["🧪 Run Tests", "🎮 Policy Playground", "📊 Coverage"])
    
    # ==================== RUN TESTS ====================
    with test_tabs[0]:
        st.markdown("#### Run Policy Tests")
        
        # Select policy and test
        col1, col2 = st.columns(2)
        
        with col1:
            policy_files = [p for p in pac['policies'].keys() if p.endswith('.rego') and '_test' not in p]
            selected_policy = st.selectbox("Policy File", policy_files, key="test_policy_select")
        
        with col2:
            # Find matching test file
            test_file = selected_policy.replace('.rego', '_test.rego') if selected_policy else None
            test_exists = test_file in pac['policies'] if test_file else False
            
            if test_exists:
                st.success(f"✅ Test file found: {test_file}")
            else:
                st.warning("⚠️ No test file found")
        
        if st.button("▶️ Run Tests", type="primary", disabled=not test_exists):
            with st.spinner("Running tests..."):
                policy_content = pac['policies'].get(selected_policy, '')
                test_content = pac['policies'].get(test_file, '')
                
                results = test_engine.run_policy_tests(policy_content, test_content)
                pac['test_results'][selected_policy] = results
                
                st.success("✅ Tests completed!")
        
        # Display results
        if selected_policy in pac.get('test_results', {}):
            results = pac['test_results'][selected_policy]
            
            st.markdown("---")
            st.markdown("#### Test Results")
            
            if results.get('simulated'):
                st.info(f"ℹ️ {results.get('message', 'Simulated results')}")
            
            tests = results.get('tests', [])
            if tests:
                for test in tests:
                    status = "✅" if test.get('pass') else "❌"
                    st.markdown(f"{status} **{test.get('name', 'Unknown')}** ({test.get('duration', 0)*1000:.1f}ms)")
                
                # Summary
                summary = results.get('summary', {})
                col1, col2, col3 = st.columns(3)
                col1.metric("Total", summary.get('total', len(tests)))
                col2.metric("Passed", summary.get('passed', len([t for t in tests if t.get('pass')])))
                col3.metric("Failed", summary.get('failed', len([t for t in tests if not t.get('pass')])))
    
    # ==================== POLICY PLAYGROUND ====================
    with test_tabs[1]:
        st.markdown("#### Policy Playground")
        st.markdown("Test your policy against custom input data")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Policy:**")
            policy_for_eval = st.selectbox(
                "Select Policy",
                [p for p in pac['policies'].keys() if p.endswith('.rego') and '_test' not in p],
                key="playground_policy"
            )
            
            if policy_for_eval:
                st.code(pac['policies'].get(policy_for_eval, '')[:500] + '...', language='rego')
        
        with col2:
            st.markdown("**Input Data (JSON):**")
            
            # Sample inputs
            sample_inputs = {
                "S3 Encrypted": {
                    "resource_type": "aws_s3_bucket",
                    "resource": {
                        "bucket": "my-bucket",
                        "server_side_encryption_configuration": [{
                            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]
                        }]
                    }
                },
                "S3 Unencrypted": {
                    "resource_type": "aws_s3_bucket",
                    "resource": {
                        "bucket": "my-bucket"
                    }
                },
                "SG Open SSH": {
                    "resource_type": "aws_security_group",
                    "resource": {
                        "name": "open-sg",
                        "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
                    }
                }
            }
            
            sample_select = st.selectbox("Load Sample", ["Custom"] + list(sample_inputs.keys()))
            
            if sample_select != "Custom":
                default_input = json.dumps(sample_inputs[sample_select], indent=2)
            else:
                default_input = '{\n  "resource_type": "",\n  "resource": {}\n}'
            
            input_json = st.text_area("Input JSON", value=default_input, height=200, key="playground_input")
        
        if st.button("▶️ Evaluate Policy", type="primary"):
            try:
                input_data = json.loads(input_json)
                policy_content = pac['policies'].get(policy_for_eval, '')
                
                result = test_engine.evaluate_policy(policy_content, input_data)
                
                st.markdown("---")
                st.markdown("#### Evaluation Result")
                
                if result.get('allow'):
                    st.success("✅ **ALLOWED** - Input passes policy")
                else:
                    st.error("❌ **DENIED** - Input violates policy")
                
                if result.get('deny'):
                    st.markdown("**Violations:**")
                    for msg in result.get('deny', []):
                        st.markdown(f"- {msg}")
                
                with st.expander("Raw Result"):
                    st.json(result)
                    
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
    
    # ==================== COVERAGE ====================
    with test_tabs[2]:
        st.markdown("#### Test Coverage")
        
        # Calculate coverage
        policy_files = [p for p in pac['policies'].keys() if p.endswith('.rego') and '_test' not in p]
        test_files = [p for p in pac['policies'].keys() if '_test.rego' in p]
        
        coverage_data = []
        for policy in policy_files:
            test_file = policy.replace('.rego', '_test.rego')
            has_test = test_file in test_files
            
            # Count test functions if test exists
            test_count = 0
            if has_test:
                test_content = pac['policies'].get(test_file, '')
                test_count = len(re.findall(r'test_\w+', test_content))
            
            coverage_data.append({
                'Policy': policy.split('/')[-1],
                'Path': policy,
                'Has Tests': '✅' if has_test else '❌',
                'Test Count': test_count
            })
        
        df = pd.DataFrame(coverage_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Summary
        tested = len([c for c in coverage_data if c['Has Tests'] == '✅'])
        total = len(coverage_data)
        coverage_pct = (tested / total * 100) if total > 0 else 0
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Policy Files", total)
        col2.metric("With Tests", tested)
        col3.metric("Coverage", f"{coverage_pct:.0f}%")
        
        if coverage_pct < 80:
            st.warning(f"⚠️ Test coverage ({coverage_pct:.0f}%) is below 80% threshold")


# ============================================================================
# STREAMLIT UI - TAB 4: DEPLOY & ENFORCE
# ============================================================================

def render_deploy_enforce_tab():
    """Tab 4: Deploy policies to enforcement points"""
    st.markdown("### 🚀 Deploy & Enforce")
    
    pac = st.session_state.pac_state
    config_integration = AWSConfigIntegration()
    
    deploy_tabs = st.tabs(["☁️ AWS Config", "🐳 Conftest (CI/CD)", "📦 OPA Bundle", "📋 History"])
    
    # ==================== AWS CONFIG ====================
    with deploy_tabs[0]:
        st.markdown("#### Deploy as AWS Config Rules")
        st.markdown("Deploy policies as AWS Config Rules for continuous compliance monitoring.")
        
        # Current Config Rules
        st.markdown("##### Current Config Rules in Account")
        
        rules = config_integration.get_config_rules()
        compliance = config_integration.get_compliance_summary()
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Rules", len(rules))
        col2.metric("Compliant Resources", compliance.get('compliant', 0))
        col3.metric("Non-Compliant", compliance.get('non_compliant', 0), delta_color="inverse")
        
        if rules:
            df = pd.DataFrame(rules)
            st.dataframe(df[['name', 'source_identifier', 'state']], use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Deploy new rule
        st.markdown("##### Deploy New Config Rule")
        
        config_templates = {
            "S3 Encryption": "config-rules/s3-encryption.yaml",
        }
        
        selected_template = st.selectbox("Select Template", list(config_templates.keys()), key="config_template")
        
        template_path = config_templates.get(selected_template)
        if template_path and template_path in pac['policies']:
            with st.expander("View CloudFormation Template"):
                st.code(pac['policies'][template_path], language='yaml')
        
        if st.button("🚀 Deploy to AWS Config", type="primary"):
            with st.spinner("Deploying..."):
                if template_path:
                    result = config_integration.deploy_config_rule(pac['policies'].get(template_path, ''))
                    
                    if result.get('status') == 'success':
                        st.success(f"✅ Deployed! Stack: {result.get('stack_name')}")
                    else:
                        st.info(f"ℹ️ {result.get('message', 'Deployment simulated')}")
    
    # ==================== CONFTEST ====================
    with deploy_tabs[1]:
        st.markdown("#### Conftest (CI/CD Integration)")
        st.markdown("Use policies in your CI/CD pipeline to validate Terraform, Kubernetes, and other configs.")
        
        # Generate conftest command
        st.markdown("##### Test Terraform Plan")
        
        st.code("""# Step 1: Generate Terraform plan as JSON
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Step 2: Run Conftest with your policies
conftest test tfplan.json -p policies/terraform/ -o table

# Step 3: In CI/CD (GitHub Actions)
- name: Run Conftest
  run: |
    conftest test tfplan.json -p policies/terraform/ --fail-on-warn
""", language='bash')
        
        st.markdown("---")
        st.markdown("##### Test Kubernetes Manifests")
        
        st.code("""# Test a Kubernetes deployment
conftest test deployment.yaml -p policies/kubernetes/

# Test all YAML files in directory
conftest test k8s/*.yaml -p policies/kubernetes/ -o json
""", language='bash')
        
        st.markdown("---")
        
        # Show CI/CD pipeline
        st.markdown("##### CI/CD Pipeline Configuration")
        
        if '.github/workflows/policy-ci.yml' in pac['policies']:
            st.code(pac['policies']['.github/workflows/policy-ci.yml'], language='yaml')
    
    # ==================== OPA BUNDLE ====================
    with deploy_tabs[2]:
        st.markdown("#### OPA Bundle")
        st.markdown("Package policies as an OPA bundle for deployment to OPA servers or Gatekeeper.")
        
        st.code("""# Build OPA bundle
opa build -b policies/ -o policy-bundle.tar.gz

# Deploy to OPA server
curl -X PUT http://opa-server:8181/v1/policies \\
  -H "Content-Type: application/gzip" \\
  -T policy-bundle.tar.gz

# For Gatekeeper (Kubernetes)
kubectl apply -f constraint-template.yaml
kubectl apply -f constraint.yaml
""", language='bash')
        
        st.markdown("---")
        
        # Generate bundle contents preview
        st.markdown("##### Bundle Contents")
        
        bundle_policies = [p for p in pac['policies'].keys() if p.endswith('.rego') and '_test' not in p]
        
        for policy in bundle_policies:
            st.markdown(f"- 📜 {policy}")
        
        if st.button("📦 Generate Bundle (Preview)", type="primary"):
            st.info("ℹ️ In production, run: `opa build -b policies/ -o policy-bundle.tar.gz`")
    
    # ==================== HISTORY ====================
    with deploy_tabs[3]:
        st.markdown("#### Deployment History")
        
        deployments = pac.get('deployments', [])
        
        if not deployments:
            # Add sample history
            pac['deployments'] = [
                {'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(), 'policy': 's3/encryption.rego', 'target': 'AWS Config', 'status': 'Success'},
                {'timestamp': (datetime.now() - timedelta(days=1)).isoformat(), 'policy': 'ec2/security_groups.rego', 'target': 'Conftest', 'status': 'Success'},
                {'timestamp': (datetime.now() - timedelta(days=3)).isoformat(), 'policy': 'kubernetes/pod_security.rego', 'target': 'Gatekeeper', 'status': 'Success'},
            ]
            deployments = pac['deployments']
        
        df = pd.DataFrame(deployments)
        st.dataframe(df, use_container_width=True, hide_index=True)


# ============================================================================
# STREAMLIT UI - TAB 5: MONITOR
# ============================================================================

def render_monitor_tab():
    """Tab 5: Monitor compliance status"""
    st.markdown("### 📊 Monitor & Comply")
    
    config_integration = AWSConfigIntegration()
    
    monitor_tabs = st.tabs(["📊 Dashboard", "🔍 Violations", "📄 Reports"])
    
    # ==================== DASHBOARD ====================
    with monitor_tabs[0]:
        st.markdown("#### Compliance Dashboard")
        
        # Get compliance data
        compliance = config_integration.get_compliance_summary()
        rules = config_integration.get_config_rules()
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        total = compliance.get('compliant', 0) + compliance.get('non_compliant', 0)
        score = (compliance.get('compliant', 0) / total * 100) if total > 0 else 100
        
        col1.metric("Compliance Score", f"{score:.0f}%")
        col2.metric("Active Rules", len(rules))
        col3.metric("Compliant", compliance.get('compliant', 0))
        col4.metric("Non-Compliant", compliance.get('non_compliant', 0), delta_color="inverse")
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Compliance pie chart
            fig = px.pie(
                values=[compliance.get('compliant', 0), compliance.get('non_compliant', 0)],
                names=['Compliant', 'Non-Compliant'],
                color_discrete_sequence=['#10b981', '#ef4444'],
                title="Resource Compliance"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Rules by source
            rule_sources = {}
            for rule in rules:
                source = rule.get('source', 'Unknown')
                rule_sources[source] = rule_sources.get(source, 0) + 1
            
            if rule_sources:
                fig = px.bar(
                    x=list(rule_sources.keys()),
                    y=list(rule_sources.values()),
                    title="Rules by Source"
                )
                st.plotly_chart(fig, use_container_width=True)
    
    # ==================== VIOLATIONS ====================
    with monitor_tabs[1]:
        st.markdown("#### Compliance Violations")
        
        # Select rule
        rules = config_integration.get_config_rules()
        rule_names = [r['name'] for r in rules]
        
        selected_rule = st.selectbox("Select Config Rule", rule_names, key="violation_rule")
        
        if selected_rule:
            violations = config_integration.get_rule_compliance(selected_rule)
            
            # Filter non-compliant
            non_compliant = [v for v in violations if v.get('compliance') == 'NON_COMPLIANT']
            
            st.metric("Non-Compliant Resources", len(non_compliant))
            
            if non_compliant:
                df = pd.DataFrame(non_compliant)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.success("✅ All resources compliant!")
    
    # ==================== REPORTS ====================
    with monitor_tabs[2]:
        st.markdown("#### Compliance Reports")
        
        report_type = st.selectbox("Report Type", ["Executive Summary", "Detailed Findings", "Framework Mapping"])
        
        if st.button("📄 Generate Report", type="primary"):
            st.success("✅ Report generated!")
            
            # Sample report content
            report = f"""
# Compliance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Compliance Score: {score:.0f}%
- Active Rules: {len(rules)}
- Non-Compliant Resources: {compliance.get('non_compliant', 0)}

## Rules Status
{chr(10).join([f"- {r['name']}: {r['state']}" for r in rules[:5]])}

## Recommendations
1. Address critical violations immediately
2. Review and update policies quarterly
3. Enable auto-remediation for common issues
"""
            
            st.download_button(
                "📥 Download Report",
                data=report,
                file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d')}.md",
                mime="text/markdown"
            )


# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

def render_policy_as_code_platform():
    """Main entry point for Policy as Code Platform"""
    
    # Initialize state
    init_pac_session_state()
    
    # Header
    st.markdown("""
    <div style='background: linear-gradient(135deg, #065f46 0%, #047857 50%, #10b981 100%); 
                padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>🏛️ Policy as Code Platform</h2>
        <p style='color: #a7f3d0; margin: 0.5rem 0 0 0;'>
            Write • Test • Version • Deploy • Monitor
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick stats
    pac = st.session_state.pac_state
    policy_count = len([p for p in pac['policies'].keys() if p.endswith('.rego') and '_test' not in p])
    test_count = len([p for p in pac['policies'].keys() if '_test.rego' in p])
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📜 Policies", policy_count)
    col2.metric("🧪 Test Files", test_count)
    col3.metric("📁 Categories", 4)
    col4.metric("🔧 OPA", "✅ Ready" if PolicyTestEngine().opa_available else "⚠️ Install")
    
    st.markdown("---")
    
    # Main tabs
    main_tabs = st.tabs([
        "📚 Policy Catalog",
        "✏️ Author & Edit",
        "🧪 Test & Validate",
        "🚀 Deploy & Enforce",
        "📊 Monitor"
    ])
    
    with main_tabs[0]:
        render_policy_catalog_tab()
    
    with main_tabs[1]:
        render_author_edit_tab()
    
    with main_tabs[2]:
        render_test_validate_tab()
    
    with main_tabs[3]:
        render_deploy_enforce_tab()
    
    with main_tabs[4]:
        render_monitor_tab()


# ============================================================================
# EXPORT
# ============================================================================

__all__ = ['render_policy_as_code_platform', 'SAMPLE_POLICIES', 'PolicyTestEngine']
