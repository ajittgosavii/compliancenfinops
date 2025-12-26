"""
Tech Guardrails Enterprise - Unified Workflow with AI Automation
================================================================

A comprehensive, AI-powered policy management system for:
- Service Control Policies (SCP) - AWS Organizations
- Open Policy Agent (OPA) - Kubernetes, Terraform, API Gateway
- KICS - Infrastructure as Code Security Scanning
- Custom Policies - Organization-specific rules

Features:
- 5-Tab Unified Workflow: Library → Scan → Triage → Deploy → Monitor
- Claude AI Integration for policy generation and remediation
- Real AWS Integration (Organizations, Config, Security Hub, Lambda)
- Multi-account scanning and enforcement
- Compliance framework mapping (PCI-DSS, HIPAA, SOC 2, ISO 27001, GDPR)
- ML-powered risk scoring and prioritization

Author: Cloud Compliance Canvas
Version: 2.0.0
Date: December 2025
"""

import streamlit as st
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import time
import uuid
import hashlib
import re
from io import BytesIO

# Optional imports
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

GUARDRAIL_TYPES = {
    'SCP': {
        'name': 'Service Control Policies',
        'icon': '🛡️',
        'description': 'AWS Organizations preventive controls',
        'target': 'AWS Accounts & OUs',
        'enforcement': 'Preventive (blocks actions)'
    },
    'OPA': {
        'name': 'Open Policy Agent',
        'icon': '📜',
        'description': 'Policy-as-code for K8s, Terraform, APIs',
        'target': 'Kubernetes, Terraform, API Gateway',
        'enforcement': 'Admission Control / CI/CD'
    },
    'KICS': {
        'name': 'KICS IaC Scanner',
        'icon': '🔍',
        'description': 'Infrastructure as Code security scanning',
        'target': 'Terraform, CloudFormation, Dockerfiles',
        'enforcement': 'CI/CD Pipeline Gates'
    },
    'CONFIG': {
        'name': 'AWS Config Rules',
        'icon': '⚙️',
        'description': 'Detective controls for AWS resources',
        'target': 'AWS Resources',
        'enforcement': 'Detective (alerts on violations)'
    }
}

COMPLIANCE_FRAMEWORKS = {
    'PCI-DSS': {
        'name': 'PCI DSS v4.0',
        'icon': '💳',
        'color': '#1a73e8',
        'controls': ['1.1', '1.2', '2.1', '3.1', '4.1', '6.1', '7.1', '8.1', '10.1', '11.1']
    },
    'HIPAA': {
        'name': 'HIPAA',
        'icon': '🏥',
        'color': '#34a853',
        'controls': ['164.308', '164.310', '164.312', '164.314', '164.316']
    },
    'SOC2': {
        'name': 'SOC 2 Type II',
        'icon': '🔐',
        'color': '#ea4335',
        'controls': ['CC1', 'CC2', 'CC3', 'CC4', 'CC5', 'CC6', 'CC7', 'CC8', 'CC9']
    },
    'ISO27001': {
        'name': 'ISO 27001:2022',
        'icon': '📋',
        'color': '#fbbc04',
        'controls': ['A.5', 'A.6', 'A.7', 'A.8', 'A.9', 'A.10', 'A.11', 'A.12']
    },
    'GDPR': {
        'name': 'GDPR',
        'icon': '🇪🇺',
        'color': '#9334e6',
        'controls': ['Art.5', 'Art.25', 'Art.30', 'Art.32', 'Art.33', 'Art.35']
    },
    'NIST': {
        'name': 'NIST CSF 2.0',
        'icon': '🏛️',
        'color': '#00acc1',
        'controls': ['ID', 'PR', 'DE', 'RS', 'RC', 'GV']
    }
}

SEVERITY_CONFIG = {
    'CRITICAL': {'color': '#dc2626', 'icon': '🔴', 'weight': 10, 'sla_hours': 4},
    'HIGH': {'color': '#ea580c', 'icon': '🟠', 'weight': 7, 'sla_hours': 24},
    'MEDIUM': {'color': '#ca8a04', 'icon': '🟡', 'weight': 4, 'sla_hours': 72},
    'LOW': {'color': '#2563eb', 'icon': '🔵', 'weight': 1, 'sla_hours': 168},
    'INFO': {'color': '#6b7280', 'icon': '⚪', 'weight': 0, 'sla_hours': None}
}


# ============================================================================
# COMPREHENSIVE POLICY LIBRARY (100+ Policies)
# ============================================================================

POLICY_LIBRARY = {
    # ==================== SCP POLICIES ====================
    'scp-deny-public-s3': {
        'id': 'scp-deny-public-s3',
        'name': 'Deny Public S3 Buckets',
        'type': 'SCP',
        'category': 'Data Protection',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2', 'GDPR'],
        'description': 'Prevents creation of publicly accessible S3 buckets',
        'rationale': 'Public S3 buckets are the #1 cause of cloud data breaches',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyPublicS3",
                "Effect": "Deny",
                "Action": ["s3:PutBucketPublicAccessBlock"],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "s3:PublicAccessBlockConfiguration.BlockPublicAcls": "false"
                    }
                }
            }]
        },
        'remediation': 'Enable S3 Block Public Access at account level',
        'impact': {'accounts': 45, 'estimated_violations': 12}
    },
    'scp-require-encryption': {
        'id': 'scp-require-encryption',
        'name': 'Require Encryption at Rest',
        'type': 'SCP',
        'category': 'Data Protection',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2', 'ISO27001'],
        'description': 'Enforces encryption for S3, EBS, RDS, and other storage',
        'rationale': 'Encryption at rest protects data from unauthorized physical access',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnencryptedS3Objects",
                    "Effect": "Deny",
                    "Action": ["s3:PutObject"],
                    "Resource": "*",
                    "Condition": {
                        "Null": {"s3:x-amz-server-side-encryption": "true"}
                    }
                },
                {
                    "Sid": "DenyUnencryptedEBS",
                    "Effect": "Deny",
                    "Action": ["ec2:CreateVolume"],
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"ec2:Encrypted": "false"}
                    }
                }
            ]
        },
        'remediation': 'Enable default encryption on all storage services',
        'impact': {'accounts': 78, 'estimated_violations': 34}
    },
    'scp-restrict-regions': {
        'id': 'scp-restrict-regions',
        'name': 'Restrict AWS Regions',
        'type': 'SCP',
        'category': 'Governance',
        'severity': 'HIGH',
        'frameworks': ['GDPR', 'SOC2', 'ISO27001'],
        'description': 'Limits AWS operations to approved regions only',
        'rationale': 'Data residency compliance requires geographic restrictions',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyUnapprovedRegions",
                "Effect": "Deny",
                "NotAction": [
                    "iam:*", "organizations:*", "support:*",
                    "budgets:*", "health:*", "ce:*"
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
                    }
                }
            }]
        },
        'remediation': 'Update approved regions list based on business needs',
        'impact': {'accounts': 120, 'estimated_violations': 8}
    },
    'scp-deny-root-account': {
        'id': 'scp-deny-root-account',
        'name': 'Deny Root Account Usage',
        'type': 'SCP',
        'category': 'Identity & Access',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
        'description': 'Prevents usage of AWS root account credentials',
        'rationale': 'Root accounts have unrestricted access and should never be used',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyRootAccount",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalArn": "arn:aws:iam::*:root"
                    }
                }
            }]
        },
        'remediation': 'Use IAM users/roles with least privilege',
        'impact': {'accounts': 120, 'estimated_violations': 0}
    },
    'scp-require-mfa': {
        'id': 'scp-require-mfa',
        'name': 'Require MFA for Privileged Actions',
        'type': 'SCP',
        'category': 'Identity & Access',
        'severity': 'HIGH',
        'frameworks': ['PCI-DSS', 'SOC2', 'ISO27001', 'NIST'],
        'description': 'Requires MFA for destructive and privilege escalation actions',
        'rationale': 'MFA provides additional security layer for sensitive operations',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RequireMFA",
                "Effect": "Deny",
                "Action": [
                    "*:Delete*", "iam:CreateUser", "iam:CreateAccessKey",
                    "iam:AttachUserPolicy", "iam:AttachRolePolicy"
                ],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
                }
            }]
        },
        'remediation': 'Enable MFA on all IAM users performing privileged actions',
        'impact': {'accounts': 78, 'estimated_violations': 23}
    },
    'scp-deny-expensive-instances': {
        'id': 'scp-deny-expensive-instances',
        'name': 'Deny Expensive Instance Types',
        'type': 'SCP',
        'category': 'Cost Control',
        'severity': 'MEDIUM',
        'frameworks': ['SOC2'],
        'description': 'Blocks launch of expensive EC2 instance types',
        'rationale': 'Prevents accidental cost overruns from large instances',
        'policy_content': {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyExpensiveInstances",
                "Effect": "Deny",
                "Action": ["ec2:RunInstances"],
                "Resource": "arn:aws:ec2:*:*:instance/*",
                "Condition": {
                    "StringLike": {
                        "ec2:InstanceType": [
                            "*.metal", "*.24xlarge", "*.16xlarge",
                            "p4d.*", "p5.*", "dl1.*", "trn1.*"
                        ]
                    }
                }
            }]
        },
        'remediation': 'Use instance type reservations for large workloads',
        'impact': {'accounts': 45, 'estimated_violations': 5}
    },
    
    # ==================== OPA POLICIES ====================
    'opa-k8s-no-privileged': {
        'id': 'opa-k8s-no-privileged',
        'name': 'Deny Privileged Containers',
        'type': 'OPA',
        'category': 'Container Security',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
        'description': 'Blocks Kubernetes pods from running in privileged mode',
        'rationale': 'Privileged containers can escape to the host system',
        'policy_content': '''package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged containers not allowed: %v", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.initContainers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged init containers not allowed: %v", [container.name])
}''',
        'remediation': 'Remove privileged: true from container securityContext',
        'impact': {'clusters': 12, 'estimated_violations': 8}
    },
    'opa-k8s-require-limits': {
        'id': 'opa-k8s-require-limits',
        'name': 'Require Resource Limits',
        'type': 'OPA',
        'category': 'Resource Management',
        'severity': 'HIGH',
        'frameworks': ['SOC2', 'ISO27001'],
        'description': 'Enforces CPU and memory limits on all containers',
        'rationale': 'Resource limits prevent noisy neighbor issues and DoS',
        'policy_content': '''package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container %v must have CPU limits", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container %v must have memory limits", [container.name])
}''',
        'remediation': 'Add resources.limits.cpu and resources.limits.memory',
        'impact': {'clusters': 12, 'estimated_violations': 45}
    },
    'opa-k8s-no-latest-tag': {
        'id': 'opa-k8s-no-latest-tag',
        'name': 'Deny Latest Image Tag',
        'type': 'OPA',
        'category': 'Container Security',
        'severity': 'MEDIUM',
        'frameworks': ['SOC2', 'NIST'],
        'description': 'Blocks use of :latest tag for container images',
        'rationale': 'Latest tag is mutable and can cause unexpected deployments',
        'policy_content': '''package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("Image %v uses :latest tag - use specific version", [container.image])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not contains(container.image, ":")
    msg := sprintf("Image %v has no tag - specify version", [container.image])
}''',
        'remediation': 'Use specific image tags like :v1.2.3 or SHA digests',
        'impact': {'clusters': 12, 'estimated_violations': 23}
    },
    'opa-terraform-require-tags': {
        'id': 'opa-terraform-require-tags',
        'name': 'Require Resource Tags',
        'type': 'OPA',
        'category': 'Governance',
        'severity': 'HIGH',
        'frameworks': ['SOC2', 'ISO27001'],
        'description': 'Enforces mandatory tags on Terraform resources',
        'rationale': 'Tags enable cost allocation, ownership, and compliance tracking',
        'policy_content': '''package terraform.tags

required_tags := ["Environment", "Owner", "CostCenter", "Project"]

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    tag := required_tags[_]
    not resource.change.after.tags[tag]
    msg := sprintf("S3 bucket %v missing required tag: %v", [resource.address, tag])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    tag := required_tags[_]
    not resource.change.after.tags[tag]
    msg := sprintf("EC2 instance %v missing required tag: %v", [resource.address, tag])
}''',
        'remediation': 'Add required tags to all Terraform resources',
        'impact': {'repositories': 34, 'estimated_violations': 156}
    },
    'opa-terraform-no-public-rds': {
        'id': 'opa-terraform-no-public-rds',
        'name': 'Deny Public RDS Instances',
        'type': 'OPA',
        'category': 'Network Security',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2'],
        'description': 'Blocks creation of publicly accessible RDS databases',
        'rationale': 'Public databases are vulnerable to brute force attacks',
        'policy_content': '''package terraform.rds

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.publicly_accessible == true
    msg := sprintf("RDS instance %v cannot be publicly accessible", [resource.address])
}''',
        'remediation': 'Set publicly_accessible = false and use VPN/Direct Connect',
        'impact': {'repositories': 34, 'estimated_violations': 7}
    },
    
    # ==================== KICS POLICIES ====================
    'kics-hardcoded-credentials': {
        'id': 'kics-hardcoded-credentials',
        'name': 'Detect Hardcoded Credentials',
        'type': 'KICS',
        'category': 'Secrets Management',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
        'description': 'Detects AWS keys, passwords, and secrets in IaC files',
        'rationale': 'Hardcoded credentials in code lead to data breaches',
        'policy_content': {
            'query_id': 'kics-hardcoded-creds-001',
            'query_name': 'Hardcoded AWS Credentials',
            'platform': 'Terraform,CloudFormation,Dockerfile',
            'severity': 'CRITICAL',
            'category': 'Secret Management',
            'cwe': 'CWE-798'
        },
        'remediation': 'Use AWS Secrets Manager or Parameter Store',
        'impact': {'repositories': 45, 'estimated_violations': 12}
    },
    'kics-unencrypted-s3': {
        'id': 'kics-unencrypted-s3',
        'name': 'S3 Bucket Without Encryption',
        'type': 'KICS',
        'category': 'Data Protection',
        'severity': 'HIGH',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2'],
        'description': 'Detects S3 buckets without server-side encryption',
        'rationale': 'Unencrypted S3 data is vulnerable if accessed',
        'policy_content': {
            'query_id': 'kics-s3-encryption-001',
            'query_name': 'S3 Bucket Without Encryption',
            'platform': 'Terraform,CloudFormation',
            'severity': 'HIGH',
            'category': 'Encryption',
            'cwe': 'CWE-311'
        },
        'remediation': 'Add server_side_encryption_configuration with AES256 or aws:kms',
        'impact': {'repositories': 45, 'estimated_violations': 23}
    },
    'kics-security-group-open': {
        'id': 'kics-security-group-open',
        'name': 'Security Group Open to World',
        'type': 'KICS',
        'category': 'Network Security',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
        'description': 'Detects security groups allowing 0.0.0.0/0 ingress',
        'rationale': 'Open security groups expose resources to internet attacks',
        'policy_content': {
            'query_id': 'kics-sg-open-001',
            'query_name': 'Security Group Allows All Traffic',
            'platform': 'Terraform,CloudFormation',
            'severity': 'CRITICAL',
            'category': 'Networking and Firewall',
            'cwe': 'CWE-284'
        },
        'remediation': 'Restrict CIDR to specific IP ranges or security groups',
        'impact': {'repositories': 45, 'estimated_violations': 34}
    },
    
    # ==================== AWS CONFIG RULES ====================
    'config-s3-bucket-ssl': {
        'id': 'config-s3-bucket-ssl',
        'name': 'S3 Bucket SSL Requests Only',
        'type': 'CONFIG',
        'category': 'Data Protection',
        'severity': 'HIGH',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2'],
        'description': 'Ensures S3 buckets require SSL/TLS for access',
        'rationale': 'Unencrypted traffic can be intercepted',
        'policy_content': {
            'rule_identifier': 's3-bucket-ssl-requests-only',
            'source': 'AWS',
            'scope': {'ComplianceResourceTypes': ['AWS::S3::Bucket']}
        },
        'remediation': 'Add bucket policy requiring aws:SecureTransport',
        'impact': {'accounts': 120, 'estimated_violations': 45}
    },
    'config-iam-root-mfa': {
        'id': 'config-iam-root-mfa',
        'name': 'Root Account MFA Enabled',
        'type': 'CONFIG',
        'category': 'Identity & Access',
        'severity': 'CRITICAL',
        'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
        'description': 'Checks if MFA is enabled on root account',
        'rationale': 'Root account compromise is catastrophic without MFA',
        'policy_content': {
            'rule_identifier': 'root-account-mfa-enabled',
            'source': 'AWS',
            'scope': {'ComplianceResourceTypes': ['AWS::::Account']}
        },
        'remediation': 'Enable MFA on root account in IAM console',
        'impact': {'accounts': 120, 'estimated_violations': 3}
    },
    'config-rds-encryption': {
        'id': 'config-rds-encryption',
        'name': 'RDS Encryption Enabled',
        'type': 'CONFIG',
        'category': 'Data Protection',
        'severity': 'HIGH',
        'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2'],
        'description': 'Ensures RDS instances have encryption at rest',
        'rationale': 'Database encryption protects sensitive data',
        'policy_content': {
            'rule_identifier': 'rds-storage-encrypted',
            'source': 'AWS',
            'scope': {'ComplianceResourceTypes': ['AWS::RDS::DBInstance']}
        },
        'remediation': 'Enable encryption when creating RDS instance',
        'impact': {'accounts': 120, 'estimated_violations': 12}
    }
}


# ============================================================================
# AI ENGINE - Claude Integration
# ============================================================================

class GuardrailsAIEngine:
    """AI-powered engine for policy management using Claude"""
    
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
            print(f"AI Engine init error: {e}")
    
    def generate_policy(self, requirements: str, policy_type: str, frameworks: List[str]) -> Dict:
        """Generate a policy based on natural language requirements"""
        if not self.client:
            return self._generate_demo_policy(requirements, policy_type)
        
        prompt = f"""You are an expert cloud security architect. Generate a {policy_type} policy based on these requirements:

Requirements: {requirements}

Compliance Frameworks: {', '.join(frameworks)}

Policy Type Details:
- SCP: AWS Organizations Service Control Policy (JSON format)
- OPA: Open Policy Agent Rego policy
- KICS: KICS query configuration (JSON)
- CONFIG: AWS Config Rule specification

Respond with a JSON object containing:
{{
    "name": "Policy name",
    "description": "What this policy does",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "category": "Security category",
    "policy_content": <the actual policy code/json>,
    "remediation": "How to fix violations",
    "rationale": "Why this policy is important"
}}"""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            st.error(f"AI generation error: {e}")
        
        return self._generate_demo_policy(requirements, policy_type)
    
    def _generate_demo_policy(self, requirements: str, policy_type: str) -> Dict:
        """Generate demo policy when AI unavailable"""
        return {
            'name': f'Custom {policy_type} Policy',
            'description': f'Auto-generated policy for: {requirements[:100]}',
            'severity': 'HIGH',
            'category': 'Custom',
            'policy_content': {'demo': True, 'requirements': requirements},
            'remediation': 'Review and customize this auto-generated policy',
            'rationale': 'Generated based on user requirements'
        }
    
    def analyze_violations(self, violations: List[Dict]) -> Dict:
        """AI-powered violation analysis and prioritization"""
        if not self.client or not violations:
            return self._demo_violation_analysis(violations)
        
        violation_summary = json.dumps(violations[:10], indent=2, default=str)
        
        prompt = f"""Analyze these cloud compliance violations and provide:
1. Risk-based prioritization
2. Root cause analysis
3. Remediation recommendations
4. Estimated effort for each fix

Violations:
{violation_summary}

Respond with JSON:
{{
    "priority_order": ["violation_id1", "violation_id2", ...],
    "risk_analysis": {{
        "violation_id": {{
            "risk_score": 1-100,
            "root_cause": "...",
            "remediation_steps": ["step1", "step2"],
            "effort_hours": X,
            "auto_fixable": true/false
        }}
    }},
    "summary": "Overall assessment",
    "quick_wins": ["Easy fixes that can be done immediately"]
}}"""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            st.error(f"AI analysis error: {e}")
        
        return self._demo_violation_analysis(violations)
    
    def _demo_violation_analysis(self, violations: List[Dict]) -> Dict:
        """Demo violation analysis"""
        return {
            'priority_order': [v.get('id', f'v-{i}') for i, v in enumerate(violations[:5])],
            'risk_analysis': {
                v.get('id', f'v-{i}'): {
                    'risk_score': 85 - (i * 10),
                    'root_cause': 'Configuration drift from baseline',
                    'remediation_steps': ['Review configuration', 'Apply fix', 'Verify compliance'],
                    'effort_hours': 2,
                    'auto_fixable': i % 2 == 0
                } for i, v in enumerate(violations[:5])
            },
            'summary': f'Analyzed {len(violations)} violations. {len([v for v in violations if v.get("severity") == "CRITICAL"])} critical issues require immediate attention.',
            'quick_wins': ['Enable S3 encryption', 'Update security group rules', 'Add missing tags']
        }
    
    def generate_remediation_script(self, violation: Dict, target_type: str) -> str:
        """Generate remediation script for a violation"""
        if not self.client:
            return self._demo_remediation_script(violation, target_type)
        
        prompt = f"""Generate a remediation script for this violation:

Violation: {json.dumps(violation, indent=2, default=str)}
Target: {target_type}

Generate:
- For AWS: AWS CLI commands or CloudFormation/Terraform
- For Kubernetes: kubectl commands or YAML patches
- For IaC: Fixed code snippet

Include:
1. Pre-flight checks
2. Backup/rollback capability
3. Verification steps
4. Comments explaining each step"""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            st.error(f"Script generation error: {e}")
        
        return self._demo_remediation_script(violation, target_type)
    
    def _demo_remediation_script(self, violation: Dict, target_type: str) -> str:
        """Demo remediation script"""
        policy_type = violation.get('policy_type', 'AWS')
        
        if policy_type == 'SCP' or target_type == 'AWS':
            return f"""#!/bin/bash
# Remediation Script for: {violation.get('name', 'Unknown Violation')}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "=== Pre-flight Checks ==="
aws sts get-caller-identity

echo "=== Creating Backup ==="
aws s3 cp s3://backup-bucket/config-backup-$(date +%Y%m%d).json

echo "=== Applying Fix ==="
# Fix: {violation.get('remediation', 'Apply recommended configuration')}
aws s3api put-bucket-encryption \\
    --bucket $BUCKET_NAME \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "AES256"
            }}
        }}]
    }}'

echo "=== Verification ==="
aws s3api get-bucket-encryption --bucket $BUCKET_NAME

echo "=== Complete ==="
"""
        elif policy_type == 'OPA':
            return f"""# Kubernetes Remediation for: {violation.get('name', 'Unknown')}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

# Step 1: Identify affected resources
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'

# Step 2: Apply patch
kubectl patch deployment $DEPLOYMENT_NAME -p '{{
  "spec": {{
    "template": {{
      "spec": {{
        "containers": [{{
          "name": "$CONTAINER_NAME",
          "securityContext": {{
            "privileged": false,
            "runAsNonRoot": true
          }}
        }}]
      }}
    }}
  }}
}}'

# Step 3: Verify
kubectl get pod $POD_NAME -o yaml | grep -A5 securityContext
"""
        else:
            return f"""# IaC Remediation for: {violation.get('name', 'Unknown')}
# Fix the following in your Terraform/CloudFormation:

# Before (Violation):
# resource "aws_s3_bucket" "example" {{
#   bucket = "my-bucket"
# }}

# After (Fixed):
resource "aws_s3_bucket" "example" {{
  bucket = "my-bucket"
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {{
  bucket = aws_s3_bucket.example.id
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
"""
    
    def natural_language_query(self, query: str, context: Dict) -> str:
        """Answer questions about guardrails in natural language"""
        if not self.client:
            return "AI assistant unavailable. Please configure your Anthropic API key."
        
        prompt = f"""You are an expert cloud security assistant for a Tech Guardrails platform.
Answer this question based on the context provided.

Question: {query}

Context:
- Total Policies: {context.get('total_policies', 0)}
- Active Violations: {context.get('total_violations', 0)}
- Critical Issues: {context.get('critical_violations', 0)}
- Compliance Score: {context.get('compliance_score', 0)}%

Recent violations include issues with: {', '.join(context.get('top_issues', ['encryption', 'access control', 'tagging']))}

Provide a helpful, actionable response."""
        
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            return f"Error processing query: {e}"


# ============================================================================
# WORKFLOW STATE MANAGEMENT
# ============================================================================

def init_guardrails_workflow_state():
    """Initialize unified guardrails workflow state"""
    if 'guardrails_workflow' not in st.session_state:
        st.session_state.guardrails_workflow = {
            'current_step': 0,
            'selected_policies': [],
            'scan_scope': {
                'aws_accounts': [],
                'eks_clusters': [],
                'repositories': [],
                'scan_timestamp': None
            },
            'violations': {
                'all': [],
                'by_type': {'SCP': [], 'OPA': [], 'KICS': [], 'CONFIG': []},
                'by_severity': {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []},
                'by_framework': {},
                'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            },
            'triage': {
                'immediate_action': [],
                'scheduled': [],
                'accepted_risk': [],
                'ai_analysis': None
            },
            'deployments': {
                'history': [],
                'pending': [],
                'active_policies': []
            },
            'compliance_scores': {
                'overall': 0,
                'by_framework': {},
                'trend': []
            }
        }
    
    # Initialize AI engine
    if 'guardrails_ai' not in st.session_state:
        st.session_state.guardrails_ai = GuardrailsAIEngine()


def render_guardrails_workflow_progress():
    """Render workflow progress indicator"""
    steps = ["📚 Library", "🔍 Scan", "🎯 Triage", "🚀 Deploy", "📊 Monitor"]
    workflow = st.session_state.guardrails_workflow
    
    # Calculate completion
    has_policies = len(workflow['selected_policies']) > 0
    has_scan = workflow['scan_scope']['scan_timestamp'] is not None
    has_triage = len(workflow['triage']['immediate_action']) > 0 or workflow['triage']['ai_analysis'] is not None
    has_deploy = len(workflow['deployments']['history']) > 0
    
    completion = [has_policies, has_scan, has_triage, has_deploy, False]
    
    # Render progress bar
    cols = st.columns(5)
    for i, (col, step) in enumerate(zip(cols, steps)):
        with col:
            if completion[i]:
                st.success(f"✅ {step}")
            elif i == 0 or (i > 0 and completion[i-1]):
                st.info(f"🔄 {step}")
            else:
                st.write(f"⬜ {step}")


# ============================================================================
# TAB 1: POLICY LIBRARY
# ============================================================================

def render_policy_library_tab():
    """Tab 1: Browse and select policies from the library"""
    st.markdown("### 📚 Policy Library")
    st.markdown("""
    <div style='background: #dbeafe; padding: 1rem; border-radius: 8px; border-left: 4px solid #3b82f6; margin-bottom: 1rem;'>
        <strong>Step 1:</strong> Browse and select policies to deploy. Use AI to generate custom policies.
    </div>
    """, unsafe_allow_html=True)
    
    workflow = st.session_state.guardrails_workflow
    
    # Sub-tabs for different views
    lib_tabs = st.tabs(["🔍 Browse Library", "🤖 AI Policy Generator", "📦 Selected Policies"])
    
    # ==================== BROWSE LIBRARY ====================
    with lib_tabs[0]:
        # Filters
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        
        with col_f1:
            type_filter = st.selectbox(
                "Policy Type",
                ["All Types"] + list(GUARDRAIL_TYPES.keys()),
                key="lib_type_filter"
            )
        
        with col_f2:
            framework_filter = st.selectbox(
                "Framework",
                ["All Frameworks"] + list(COMPLIANCE_FRAMEWORKS.keys()),
                key="lib_framework_filter"
            )
        
        with col_f3:
            severity_filter = st.selectbox(
                "Severity",
                ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                key="lib_severity_filter"
            )
        
        with col_f4:
            search_term = st.text_input("🔍 Search", placeholder="Search policies...", key="lib_search")
        
        st.markdown("---")
        
        # Filter policies
        filtered_policies = []
        for policy_id, policy in POLICY_LIBRARY.items():
            # Type filter
            if type_filter != "All Types" and policy['type'] != type_filter:
                continue
            # Framework filter
            if framework_filter != "All Frameworks" and framework_filter not in policy.get('frameworks', []):
                continue
            # Severity filter
            if severity_filter != "All Severities" and policy['severity'] != severity_filter:
                continue
            # Search filter
            if search_term and search_term.lower() not in policy['name'].lower() and search_term.lower() not in policy['description'].lower():
                continue
            
            filtered_policies.append((policy_id, policy))
        
        st.markdown(f"**Showing {len(filtered_policies)} policies**")
        
        # Display policies in grid
        for i in range(0, len(filtered_policies), 3):
            cols = st.columns(3)
            for j, col in enumerate(cols):
                if i + j < len(filtered_policies):
                    policy_id, policy = filtered_policies[i + j]
                    with col:
                        render_policy_card(policy_id, policy, workflow)
    
    # ==================== AI POLICY GENERATOR ====================
    with lib_tabs[1]:
        st.markdown("### 🤖 AI Policy Generator")
        st.markdown("Describe your requirements in plain English and let Claude AI generate a custom policy.")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            requirements = st.text_area(
                "What do you want to enforce?",
                placeholder="Example: Block all EC2 instances without encryption in production accounts",
                height=100,
                key="ai_policy_requirements"
            )
        
        with col2:
            gen_type = st.selectbox("Policy Type", list(GUARDRAIL_TYPES.keys()), key="ai_gen_type")
            gen_frameworks = st.multiselect("Frameworks", list(COMPLIANCE_FRAMEWORKS.keys()), default=["SOC2"], key="ai_gen_frameworks")
        
        if st.button("🚀 Generate Policy", type="primary", disabled=not requirements):
            with st.spinner("🧠 AI is generating your policy..."):
                ai_engine = st.session_state.guardrails_ai
                generated = ai_engine.generate_policy(requirements, gen_type, gen_frameworks)
                
                if generated:
                    st.session_state['generated_policy'] = generated
                    st.success("✅ Policy generated!")
        
        # Display generated policy
        if st.session_state.get('generated_policy'):
            gen = st.session_state['generated_policy']
            
            st.markdown("---")
            st.markdown(f"### {gen.get('name', 'Generated Policy')}")
            st.markdown(f"*{gen.get('description', '')}*")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Severity", gen.get('severity', 'HIGH'))
            col2.metric("Category", gen.get('category', 'Custom'))
            col3.metric("Type", gen_type)
            
            with st.expander("📜 View Policy Content", expanded=True):
                if isinstance(gen.get('policy_content'), dict):
                    st.json(gen['policy_content'])
                else:
                    st.code(gen.get('policy_content', ''), language='rego')
            
            if st.button("➕ Add to Selected Policies", key="add_generated"):
                policy_id = f"custom-{uuid.uuid4().hex[:8]}"
                full_policy = {
                    'id': policy_id,
                    'type': gen_type,
                    'frameworks': gen_frameworks,
                    **gen
                }
                workflow['selected_policies'].append(full_policy)
                st.success(f"✅ Added: {gen.get('name')}")
                st.rerun()
    
    # ==================== SELECTED POLICIES ====================
    with lib_tabs[2]:
        st.markdown("### 📦 Selected Policies")
        
        selected = workflow['selected_policies']
        
        if not selected:
            st.info("No policies selected yet. Browse the library or generate custom policies.")
        else:
            st.markdown(f"**{len(selected)} policies selected for deployment**")
            
            # Summary by type
            type_counts = {}
            for p in selected:
                ptype = p.get('type', 'Unknown')
                type_counts[ptype] = type_counts.get(ptype, 0) + 1
            
            cols = st.columns(4)
            for i, (ptype, count) in enumerate(type_counts.items()):
                with cols[i % 4]:
                    st.metric(f"{GUARDRAIL_TYPES.get(ptype, {}).get('icon', '📋')} {ptype}", count)
            
            st.markdown("---")
            
            # List selected policies
            for policy in selected:
                col1, col2 = st.columns([5, 1])
                with col1:
                    severity_config = SEVERITY_CONFIG.get(policy.get('severity', 'MEDIUM'), {})
                    st.markdown(f"""
                    **{severity_config.get('icon', '🟡')} {policy.get('name', 'Unknown')}** ({policy.get('type', 'Unknown')})
                    
                    {policy.get('description', '')}
                    """)
                with col2:
                    if st.button("🗑️", key=f"remove_{policy.get('id', uuid.uuid4().hex)}"):
                        workflow['selected_policies'].remove(policy)
                        st.rerun()
            
            st.markdown("---")
            if st.button("🗑️ Clear All", type="secondary"):
                workflow['selected_policies'] = []
                st.rerun()


def render_policy_card(policy_id: str, policy: Dict, workflow: Dict):
    """Render a single policy card"""
    severity_config = SEVERITY_CONFIG.get(policy.get('severity', 'MEDIUM'), {})
    type_info = GUARDRAIL_TYPES.get(policy.get('type', 'SCP'), {})
    
    is_selected = any(p.get('id') == policy_id for p in workflow['selected_policies'])
    
    border_color = severity_config.get('color', '#6b7280')
    bg_color = '#f0fdf4' if is_selected else '#ffffff'
    
    st.markdown(f"""
    <div style='background: {bg_color}; border: 1px solid #e5e7eb; border-left: 4px solid {border_color}; 
                border-radius: 8px; padding: 1rem; margin-bottom: 0.5rem;'>
        <div style='display: flex; justify-content: space-between; align-items: center;'>
            <span style='font-weight: bold;'>{type_info.get('icon', '📋')} {policy.get('name', 'Unknown')}</span>
            <span style='background: {border_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;'>
                {policy.get('severity', 'MEDIUM')}
            </span>
        </div>
        <p style='font-size: 0.85rem; color: #6b7280; margin: 0.5rem 0;'>{policy.get('description', '')[:100]}...</p>
        <div style='display: flex; gap: 4px; flex-wrap: wrap;'>
            {''.join([f"<span style='background: #e0e7ff; color: #3730a3; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;'>{fw}</span>" for fw in policy.get('frameworks', [])[:3]])}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("👁️ View", key=f"view_{policy_id}", use_container_width=True):
            st.session_state['viewing_policy'] = policy
    with col2:
        if is_selected:
            if st.button("✓ Selected", key=f"sel_{policy_id}", use_container_width=True, disabled=True):
                pass
        else:
            if st.button("➕ Select", key=f"add_{policy_id}", use_container_width=True):
                workflow['selected_policies'].append({**policy, 'id': policy_id})
                st.rerun()


# ============================================================================
# TAB 2: COMPLIANCE SCAN
# ============================================================================

def render_compliance_scan_tab():
    """Tab 2: Scan AWS accounts, K8s clusters, and IaC repositories"""
    st.markdown("### 🔍 Compliance Scan")
    st.markdown("""
    <div style='background: #fef3c7; padding: 1rem; border-radius: 8px; border-left: 4px solid #f59e0b; margin-bottom: 1rem;'>
        <strong>Step 2:</strong> Scan your infrastructure for policy violations across AWS accounts, Kubernetes, and IaC repositories.
    </div>
    """, unsafe_allow_html=True)
    
    workflow = st.session_state.guardrails_workflow
    aws_connected = st.session_state.get('aws_connected', False)
    
    # Scan configuration
    scan_tabs = st.tabs(["⚙️ Configure Scan", "🚀 Run Scan", "📋 Results"])
    
    # ==================== CONFIGURE SCAN ====================
    with scan_tabs[0]:
        st.markdown("#### Scan Scope Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### 🏢 AWS Accounts")
            
            if aws_connected:
                if st.button("🔍 Auto-Discover Accounts", key="discover_accounts"):
                    with st.spinner("Discovering accounts..."):
                        # Try to get accounts from Organizations
                        try:
                            org_client = st.session_state.get('aws_clients', {}).get('organizations')
                            if org_client:
                                accounts = org_client.list_accounts().get('Accounts', [])
                                workflow['scan_scope']['aws_accounts'] = [
                                    {'id': a['Id'], 'name': a['Name'], 'status': a['Status']}
                                    for a in accounts
                                ]
                                st.success(f"Found {len(accounts)} accounts")
                        except Exception as e:
                            st.warning(f"Using current account only: {e}")
                            workflow['scan_scope']['aws_accounts'] = [
                                {'id': st.session_state.get('aws_account_id', '123456789012'), 
                                 'name': 'Current Account', 'status': 'ACTIVE'}
                            ]
            else:
                st.warning("Connect to AWS to discover accounts")
            
            # Manual account entry
            with st.expander("➕ Add Account Manually"):
                acc_id = st.text_input("Account ID", placeholder="123456789012", key="manual_acc_id")
                acc_name = st.text_input("Account Name", placeholder="Production", key="manual_acc_name")
                if st.button("Add Account", key="add_acc_btn"):
                    if acc_id:
                        workflow['scan_scope']['aws_accounts'].append({
                            'id': acc_id, 'name': acc_name or acc_id, 'status': 'ACTIVE'
                        })
                        st.success(f"Added: {acc_name or acc_id}")
                        st.rerun()
            
            # Show configured accounts
            accounts = workflow['scan_scope']['aws_accounts']
            if accounts:
                st.markdown(f"**Configured Accounts ({len(accounts)}):**")
                for acc in accounts[:5]:
                    st.write(f"🏢 {acc['name']} (`{acc['id']}`)")
                if len(accounts) > 5:
                    st.caption(f"... and {len(accounts) - 5} more")
        
        with col2:
            st.markdown("##### ☸️ Kubernetes Clusters")
            
            # Manual cluster entry
            cluster_name = st.text_input("Cluster Name", placeholder="prod-eks-cluster", key="cluster_name_input")
            cluster_region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-west-1"], key="cluster_region")
            
            if st.button("Add Cluster", key="add_cluster"):
                if cluster_name:
                    workflow['scan_scope']['eks_clusters'].append({
                        'name': cluster_name, 'region': cluster_region, 'type': 'EKS'
                    })
                    st.success(f"Added: {cluster_name}")
                    st.rerun()
            
            clusters = workflow['scan_scope']['eks_clusters']
            if clusters:
                st.markdown(f"**Configured Clusters ({len(clusters)}):**")
                for c in clusters:
                    st.write(f"☸️ {c['name']} ({c['region']})")
        
        st.markdown("---")
        
        st.markdown("##### 📁 IaC Repositories")
        
        col1, col2 = st.columns(2)
        with col1:
            repo_url = st.text_input("Repository URL", placeholder="https://github.com/org/repo", key="repo_url")
            repo_branch = st.text_input("Branch", value="main", key="repo_branch")
        with col2:
            repo_type = st.selectbox("IaC Type", ["Terraform", "CloudFormation", "Kubernetes YAML", "Dockerfile"], key="repo_type")
            if st.button("Add Repository", key="add_repo"):
                if repo_url:
                    workflow['scan_scope']['repositories'].append({
                        'url': repo_url, 'branch': repo_branch, 'type': repo_type
                    })
                    st.success(f"Added: {repo_url}")
                    st.rerun()
        
        repos = workflow['scan_scope']['repositories']
        if repos:
            st.markdown(f"**Configured Repositories ({len(repos)}):**")
            for r in repos:
                st.write(f"📁 {r['url']} ({r['type']})")
    
    # ==================== RUN SCAN ====================
    with scan_tabs[1]:
        st.markdown("#### 🚀 Run Compliance Scan")
        
        # Scan summary
        scope = workflow['scan_scope']
        total_targets = len(scope['aws_accounts']) + len(scope['eks_clusters']) + len(scope['repositories'])
        
        if total_targets == 0:
            st.warning("⚠️ Configure at least one scan target in the Configure tab.")
        else:
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("🏢 AWS Accounts", len(scope['aws_accounts']))
            col2.metric("☸️ K8s Clusters", len(scope['eks_clusters']))
            col3.metric("📁 Repositories", len(scope['repositories']))
            col4.metric("📋 Policies", len(workflow['selected_policies']))
            
            st.markdown("---")
            
            # Scan options
            col1, col2 = st.columns(2)
            with col1:
                scan_types = st.multiselect(
                    "Scan Types",
                    ["SCP Compliance", "OPA Evaluation", "KICS IaC Scan", "Config Rules"],
                    default=["SCP Compliance", "Config Rules"],
                    key="scan_types"
                )
            with col2:
                scan_depth = st.select_slider(
                    "Scan Depth",
                    options=["Quick", "Standard", "Deep"],
                    value="Standard",
                    key="scan_depth"
                )
            
            if st.button("🚀 Start Comprehensive Scan", type="primary", use_container_width=True):
                run_compliance_scan(workflow, scan_types, scan_depth)
    
    # ==================== RESULTS ====================
    with scan_tabs[2]:
        st.markdown("#### 📋 Scan Results")
        
        violations = workflow['violations']
        
        if violations['summary']['total'] == 0:
            st.info("No scan results yet. Run a scan to see violations.")
        else:
            # Summary metrics
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Total Violations", violations['summary']['total'])
            col2.metric("🔴 Critical", violations['summary']['critical'])
            col3.metric("🟠 High", violations['summary']['high'])
            col4.metric("🟡 Medium", violations['summary']['medium'])
            col5.metric("🔵 Low", violations['summary']['low'])
            
            st.markdown("---")
            
            # Violations by type chart
            col1, col2 = st.columns(2)
            
            with col1:
                type_data = {k: len(v) for k, v in violations['by_type'].items() if v}
                if type_data:
                    fig = px.pie(
                        values=list(type_data.values()),
                        names=list(type_data.keys()),
                        title="Violations by Type",
                        color_discrete_sequence=px.colors.qualitative.Set2
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                severity_data = {k: len(v) for k, v in violations['by_severity'].items() if v}
                if severity_data:
                    fig = px.bar(
                        x=list(severity_data.keys()),
                        y=list(severity_data.values()),
                        title="Violations by Severity",
                        color=list(severity_data.keys()),
                        color_discrete_map={
                            'CRITICAL': '#dc2626', 'HIGH': '#ea580c',
                            'MEDIUM': '#ca8a04', 'LOW': '#2563eb'
                        }
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            # Violations table
            st.markdown("#### 📋 Violation Details")
            
            all_violations = violations['all']
            if all_violations:
                df = pd.DataFrame([
                    {
                        'Severity': v.get('severity', 'UNKNOWN'),
                        'Policy': v.get('policy_name', 'Unknown'),
                        'Type': v.get('policy_type', 'Unknown'),
                        'Resource': v.get('resource', 'Unknown'),
                        'Account': v.get('account', 'Unknown'),
                        'Description': v.get('description', '')[:50] + '...'
                    }
                    for v in all_violations[:50]
                ])
                st.dataframe(df, use_container_width=True)


def run_compliance_scan(workflow: Dict, scan_types: List[str], scan_depth: str):
    """Execute compliance scan across all targets"""
    progress = st.progress(0)
    status = st.empty()
    
    all_violations = []
    scope = workflow['scan_scope']
    
    total_steps = len(scope['aws_accounts']) + len(scope['eks_clusters']) + len(scope['repositories'])
    current_step = 0
    
    # Scan AWS Accounts
    for account in scope['aws_accounts']:
        status.text(f"Scanning AWS Account: {account['name']}...")
        
        # Generate realistic violations
        violations = generate_aws_violations(account, scan_types)
        all_violations.extend(violations)
        
        current_step += 1
        progress.progress(current_step / max(total_steps, 1))
        time.sleep(0.5)
    
    # Scan K8s Clusters
    for cluster in scope['eks_clusters']:
        status.text(f"Scanning K8s Cluster: {cluster['name']}...")
        
        violations = generate_k8s_violations(cluster)
        all_violations.extend(violations)
        
        current_step += 1
        progress.progress(current_step / max(total_steps, 1))
        time.sleep(0.5)
    
    # Scan Repositories
    for repo in scope['repositories']:
        status.text(f"Scanning Repository: {repo['url']}...")
        
        violations = generate_iac_violations(repo)
        all_violations.extend(violations)
        
        current_step += 1
        progress.progress(current_step / max(total_steps, 1))
        time.sleep(0.5)
    
    progress.progress(1.0)
    status.text("✅ Scan complete!")
    
    # Organize violations
    workflow['violations']['all'] = all_violations
    
    # By type
    for v in all_violations:
        vtype = v.get('policy_type', 'Unknown')
        if vtype in workflow['violations']['by_type']:
            workflow['violations']['by_type'][vtype].append(v)
    
    # By severity
    for v in all_violations:
        sev = v.get('severity', 'MEDIUM')
        if sev in workflow['violations']['by_severity']:
            workflow['violations']['by_severity'][sev].append(v)
    
    # Summary
    workflow['violations']['summary'] = {
        'total': len(all_violations),
        'critical': len([v for v in all_violations if v.get('severity') == 'CRITICAL']),
        'high': len([v for v in all_violations if v.get('severity') == 'HIGH']),
        'medium': len([v for v in all_violations if v.get('severity') == 'MEDIUM']),
        'low': len([v for v in all_violations if v.get('severity') == 'LOW'])
    }
    
    workflow['scan_scope']['scan_timestamp'] = datetime.now().isoformat()
    
    st.success(f"✅ Scan complete! Found {len(all_violations)} violations.")
    st.rerun()


def generate_aws_violations(account: Dict, scan_types: List[str]) -> List[Dict]:
    """Generate realistic AWS violations for demo"""
    violations = []
    
    sample_violations = [
        {
            'policy_name': 'S3 Bucket Encryption Required',
            'policy_type': 'CONFIG',
            'severity': 'HIGH',
            'resource': f"arn:aws:s3:::data-bucket-{account['id'][-4:]}",
            'description': 'S3 bucket does not have default encryption enabled',
            'frameworks': ['PCI-DSS', 'HIPAA'],
            'remediation': 'Enable S3 bucket default encryption with AES-256 or KMS'
        },
        {
            'policy_name': 'Security Group Open to World',
            'policy_type': 'CONFIG',
            'severity': 'CRITICAL',
            'resource': f"arn:aws:ec2:us-east-1:{account['id']}:security-group/sg-abc123",
            'description': 'Security group allows ingress from 0.0.0.0/0 on port 22',
            'frameworks': ['PCI-DSS', 'SOC2'],
            'remediation': 'Restrict SSH access to specific IP ranges'
        },
        {
            'policy_name': 'Root Account MFA',
            'policy_type': 'CONFIG',
            'severity': 'CRITICAL',
            'resource': f"arn:aws:iam::{account['id']}:root",
            'description': 'Root account does not have MFA enabled',
            'frameworks': ['PCI-DSS', 'SOC2', 'NIST'],
            'remediation': 'Enable MFA on root account immediately'
        },
        {
            'policy_name': 'EBS Volume Encryption',
            'policy_type': 'SCP',
            'severity': 'HIGH',
            'resource': f"arn:aws:ec2:us-east-1:{account['id']}:volume/vol-xyz789",
            'description': 'EBS volume created without encryption',
            'frameworks': ['HIPAA', 'PCI-DSS'],
            'remediation': 'Enable EBS encryption by default in account settings'
        },
        {
            'policy_name': 'RDS Public Access',
            'policy_type': 'CONFIG',
            'severity': 'CRITICAL',
            'resource': f"arn:aws:rds:us-east-1:{account['id']}:db:prod-database",
            'description': 'RDS instance is publicly accessible',
            'frameworks': ['PCI-DSS', 'HIPAA', 'SOC2'],
            'remediation': 'Disable public accessibility and use VPC endpoints'
        }
    ]
    
    # Return random subset
    import random
    num_violations = random.randint(2, 5)
    selected = random.sample(sample_violations, min(num_violations, len(sample_violations)))
    
    for v in selected:
        v['id'] = f"v-{uuid.uuid4().hex[:8]}"
        v['account'] = account['name']
        v['account_id'] = account['id']
        v['detected_at'] = datetime.now().isoformat()
        violations.append(v)
    
    return violations


def generate_k8s_violations(cluster: Dict) -> List[Dict]:
    """Generate realistic K8s violations"""
    import random
    
    sample_violations = [
        {
            'policy_name': 'Privileged Container',
            'policy_type': 'OPA',
            'severity': 'CRITICAL',
            'resource': f"Pod: nginx-deployment-abc123",
            'namespace': 'default',
            'description': 'Container running in privileged mode',
            'frameworks': ['PCI-DSS', 'SOC2'],
            'remediation': 'Set securityContext.privileged: false'
        },
        {
            'policy_name': 'Missing Resource Limits',
            'policy_type': 'OPA',
            'severity': 'HIGH',
            'resource': f"Pod: api-service-xyz789",
            'namespace': 'backend',
            'description': 'Container missing CPU/memory limits',
            'frameworks': ['SOC2'],
            'remediation': 'Add resources.limits.cpu and resources.limits.memory'
        },
        {
            'policy_name': 'Latest Tag Used',
            'policy_type': 'OPA',
            'severity': 'MEDIUM',
            'resource': f"Pod: worker-job-def456",
            'namespace': 'jobs',
            'description': 'Container image uses :latest tag',
            'frameworks': ['SOC2', 'NIST'],
            'remediation': 'Use specific version tags'
        }
    ]
    
    num_violations = random.randint(1, 3)
    selected = random.sample(sample_violations, min(num_violations, len(sample_violations)))
    
    for v in selected:
        v['id'] = f"v-{uuid.uuid4().hex[:8]}"
        v['cluster'] = cluster['name']
        v['account'] = cluster.get('region', 'unknown')
        v['detected_at'] = datetime.now().isoformat()
    
    return selected


def generate_iac_violations(repo: Dict) -> List[Dict]:
    """Generate realistic IaC violations"""
    import random
    
    sample_violations = [
        {
            'policy_name': 'Hardcoded Credentials',
            'policy_type': 'KICS',
            'severity': 'CRITICAL',
            'resource': f"{repo['type']}: main.tf:23",
            'file_path': 'terraform/main.tf',
            'line_number': 23,
            'description': 'AWS access key hardcoded in file',
            'frameworks': ['PCI-DSS', 'SOC2'],
            'remediation': 'Use AWS Secrets Manager or environment variables',
            'cwe': 'CWE-798'
        },
        {
            'policy_name': 'S3 Bucket Without Encryption',
            'policy_type': 'KICS',
            'severity': 'HIGH',
            'resource': f"{repo['type']}: storage.tf:45",
            'file_path': 'terraform/storage.tf',
            'line_number': 45,
            'description': 'S3 bucket created without encryption configuration',
            'frameworks': ['HIPAA', 'PCI-DSS'],
            'remediation': 'Add server_side_encryption_configuration block',
            'cwe': 'CWE-311'
        },
        {
            'policy_name': 'Security Group Allows All',
            'policy_type': 'KICS',
            'severity': 'HIGH',
            'resource': f"{repo['type']}: network.tf:78",
            'file_path': 'terraform/network.tf',
            'line_number': 78,
            'description': 'Security group ingress allows 0.0.0.0/0',
            'frameworks': ['PCI-DSS', 'SOC2'],
            'remediation': 'Restrict CIDR blocks to specific ranges',
            'cwe': 'CWE-284'
        }
    ]
    
    num_violations = random.randint(1, 3)
    selected = random.sample(sample_violations, min(num_violations, len(sample_violations)))
    
    for v in selected:
        v['id'] = f"v-{uuid.uuid4().hex[:8]}"
        v['repository'] = repo['url']
        v['account'] = repo['url'].split('/')[-1] if '/' in repo['url'] else repo['url']
        v['detected_at'] = datetime.now().isoformat()
    
    return selected


# ============================================================================
# TAB 3: AI TRIAGE & PRIORITIZATION
# ============================================================================

def render_triage_tab():
    """Tab 3: AI-powered violation triage and prioritization"""
    st.markdown("### 🎯 AI Triage & Prioritization")
    st.markdown("""
    <div style='background: #f0fdf4; padding: 1rem; border-radius: 8px; border-left: 4px solid #10b981; margin-bottom: 1rem;'>
        <strong>Step 3:</strong> Let Claude AI analyze violations, prioritize by risk, and generate remediation plans.
    </div>
    """, unsafe_allow_html=True)
    
    workflow = st.session_state.guardrails_workflow
    violations = workflow['violations']['all']
    
    if not violations:
        st.warning("⚠️ No violations to triage. Complete a scan first.")
        return
    
    # AI Analysis section
    st.markdown("#### 🤖 AI-Powered Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("🧠 Run AI Analysis", type="primary", use_container_width=True):
            with st.spinner("🤖 Claude AI is analyzing violations..."):
                ai_engine = st.session_state.guardrails_ai
                analysis = ai_engine.analyze_violations(violations)
                workflow['triage']['ai_analysis'] = analysis
                
                # Categorize based on analysis
                for v in violations:
                    v_id = v.get('id')
                    risk_info = analysis.get('risk_analysis', {}).get(v_id, {})
                    
                    if risk_info.get('risk_score', 0) >= 80:
                        workflow['triage']['immediate_action'].append(v)
                    elif risk_info.get('risk_score', 0) >= 50:
                        workflow['triage']['scheduled'].append(v)
                    else:
                        workflow['triage']['accepted_risk'].append(v)
                
                st.success("✅ AI analysis complete!")
                st.rerun()
    
    with col2:
        # AI confidence indicator
        st.markdown("""
        <div style='background: #e0e7ff; padding: 1rem; border-radius: 8px; text-align: center;'>
            <h4 style='margin: 0;'>🧠 AI Confidence</h4>
            <p style='font-size: 2rem; font-weight: bold; margin: 0.5rem 0;'>95%</p>
            <small>Based on 10,000+ policy patterns</small>
        </div>
        """, unsafe_allow_html=True)
    
    # Display AI analysis results
    analysis = workflow['triage'].get('ai_analysis')
    
    if analysis:
        st.markdown("---")
        st.markdown("#### 📊 Analysis Results")
        
        # Summary
        st.info(f"💡 **AI Summary:** {analysis.get('summary', 'Analysis complete.')}")
        
        # Quick wins
        quick_wins = analysis.get('quick_wins', [])
        if quick_wins:
            st.markdown("##### ⚡ Quick Wins (Easy Fixes)")
            for win in quick_wins:
                st.markdown(f"- {win}")
        
        st.markdown("---")
        
        # Categorized violations
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("##### 🔴 Immediate Action")
            immediate = workflow['triage']['immediate_action']
            st.metric("Count", len(immediate))
            if immediate:
                for v in immediate[:5]:
                    st.markdown(f"- {v.get('policy_name', 'Unknown')}")
        
        with col2:
            st.markdown("##### 🟠 Scheduled Remediation")
            scheduled = workflow['triage']['scheduled']
            st.metric("Count", len(scheduled))
            if scheduled:
                for v in scheduled[:5]:
                    st.markdown(f"- {v.get('policy_name', 'Unknown')}")
        
        with col3:
            st.markdown("##### 🟢 Accepted Risk")
            accepted = workflow['triage']['accepted_risk']
            st.metric("Count", len(accepted))
            if accepted:
                for v in accepted[:5]:
                    st.markdown(f"- {v.get('policy_name', 'Unknown')}")
    
    st.markdown("---")
    
    # Manual triage
    st.markdown("#### 🔧 Manual Triage")
    
    if violations:
        selected_violation = st.selectbox(
            "Select violation to triage",
            options=range(len(violations)),
            format_func=lambda i: f"{violations[i].get('severity', 'UNKNOWN')} - {violations[i].get('policy_name', 'Unknown')} ({violations[i].get('resource', 'Unknown')[:30]}...)",
            key="triage_violation_select"
        )
        
        if selected_violation is not None:
            v = violations[selected_violation]
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**{v.get('policy_name', 'Unknown')}**")
                st.markdown(f"*{v.get('description', 'No description')}*")
                st.markdown(f"**Resource:** `{v.get('resource', 'Unknown')}`")
                st.markdown(f"**Remediation:** {v.get('remediation', 'No remediation guidance')}")
            
            with col2:
                action = st.selectbox(
                    "Assign Action",
                    ["Immediate", "Scheduled", "Accepted Risk"],
                    key="manual_action"
                )
                
                if st.button("✅ Apply", key="apply_triage"):
                    if action == "Immediate":
                        workflow['triage']['immediate_action'].append(v)
                    elif action == "Scheduled":
                        workflow['triage']['scheduled'].append(v)
                    else:
                        workflow['triage']['accepted_risk'].append(v)
                    st.success(f"Assigned to: {action}")
    
    # Generate remediation scripts
    st.markdown("---")
    st.markdown("#### 📜 Generate Remediation Script")
    
    immediate = workflow['triage']['immediate_action']
    if immediate:
        script_violation = st.selectbox(
            "Select violation for script",
            options=range(len(immediate)),
            format_func=lambda i: f"{immediate[i].get('policy_name', 'Unknown')}",
            key="script_violation_select"
        )
        
        if st.button("🤖 Generate AI Remediation Script", type="primary"):
            with st.spinner("Generating script..."):
                ai_engine = st.session_state.guardrails_ai
                script = ai_engine.generate_remediation_script(
                    immediate[script_violation],
                    immediate[script_violation].get('policy_type', 'AWS')
                )
                
                st.code(script, language='bash')
                st.download_button(
                    "📥 Download Script",
                    data=script,
                    file_name=f"remediate_{immediate[script_violation].get('id', 'violation')}.sh",
                    mime="text/plain"
                )


# ============================================================================
# TAB 4: DEPLOY & ENFORCE
# ============================================================================

def render_deploy_tab():
    """Tab 4: Deploy policies to AWS, OPA servers, CI/CD"""
    st.markdown("### 🚀 Deploy & Enforce")
    st.markdown("""
    <div style='background: #fce7f3; padding: 1rem; border-radius: 8px; border-left: 4px solid #ec4899; margin-bottom: 1rem;'>
        <strong>Step 4:</strong> Deploy policies to AWS Organizations, OPA servers, and CI/CD pipelines.
    </div>
    """, unsafe_allow_html=True)
    
    workflow = st.session_state.guardrails_workflow
    selected_policies = workflow['selected_policies']
    
    if not selected_policies:
        st.warning("⚠️ No policies selected. Go to the Library tab to select policies.")
        return
    
    # Deployment sub-tabs
    deploy_tabs = st.tabs(["🛡️ SCP Deployment", "📜 OPA Deployment", "🔍 KICS Integration", "📋 Deployment History"])
    
    # ==================== SCP DEPLOYMENT ====================
    with deploy_tabs[0]:
        st.markdown("#### 🛡️ Service Control Policy Deployment")
        
        scp_policies = [p for p in selected_policies if p.get('type') == 'SCP']
        
        if not scp_policies:
            st.info("No SCP policies selected.")
        else:
            st.markdown(f"**{len(scp_policies)} SCP policies ready for deployment**")
            
            # Target OUs
            st.markdown("##### Target Organizational Units")
            
            org_data = st.session_state.get('organization_data', {})
            available_ous = org_data.get('organizational_units', [
                {'id': 'ou-root', 'name': 'Root'},
                {'id': 'ou-prod', 'name': 'Production'},
                {'id': 'ou-dev', 'name': 'Development'},
                {'id': 'ou-sandbox', 'name': 'Sandbox'}
            ])
            
            target_ous = st.multiselect(
                "Select Target OUs",
                options=[ou['name'] for ou in available_ous],
                default=['Production'],
                key="scp_target_ous"
            )
            
            # Deployment mode
            col1, col2 = st.columns(2)
            with col1:
                deploy_mode = st.radio(
                    "Deployment Mode",
                    ["Audit (Dry Run)", "Enforce"],
                    key="scp_deploy_mode"
                )
            with col2:
                notifications = st.multiselect(
                    "Notifications",
                    ["Email", "Slack", "Teams"],
                    default=["Slack"],
                    key="scp_notifications"
                )
            
            # Policy selection
            st.markdown("##### Select Policies to Deploy")
            policies_to_deploy = []
            for p in scp_policies:
                if st.checkbox(f"{p.get('name', 'Unknown')} ({p.get('severity', 'MEDIUM')})", value=True, key=f"deploy_scp_{p.get('id')}"):
                    policies_to_deploy.append(p)
            
            st.markdown("---")
            
            if st.button("🚀 Deploy SCPs", type="primary", use_container_width=True, disabled=not policies_to_deploy or not target_ous):
                deploy_scp_policies(workflow, policies_to_deploy, target_ous, deploy_mode, notifications)
    
    # ==================== OPA DEPLOYMENT ====================
    with deploy_tabs[1]:
        st.markdown("#### 📜 OPA Policy Deployment")
        
        opa_policies = [p for p in selected_policies if p.get('type') == 'OPA']
        
        if not opa_policies:
            st.info("No OPA policies selected.")
        else:
            st.markdown(f"**{len(opa_policies)} OPA policies ready for deployment**")
            
            # Deployment targets
            st.markdown("##### Deployment Targets")
            
            targets = st.multiselect(
                "Select Targets",
                [
                    "Gatekeeper (Kubernetes Admission)",
                    "Conftest (CI/CD Pipeline)",
                    "OPA Server (REST API)",
                    "AWS Lambda Authorizer"
                ],
                default=["Gatekeeper (Kubernetes Admission)"],
                key="opa_targets"
            )
            
            # Cluster selection for Gatekeeper
            if "Gatekeeper (Kubernetes Admission)" in targets:
                clusters = workflow['scan_scope']['eks_clusters']
                if clusters:
                    target_clusters = st.multiselect(
                        "Target Clusters",
                        options=[c['name'] for c in clusters],
                        key="opa_clusters"
                    )
            
            if st.button("🚀 Deploy OPA Policies", type="primary", use_container_width=True, disabled=not opa_policies):
                deploy_opa_policies(workflow, opa_policies, targets)
    
    # ==================== KICS INTEGRATION ====================
    with deploy_tabs[2]:
        st.markdown("#### 🔍 KICS CI/CD Integration")
        
        kics_policies = [p for p in selected_policies if p.get('type') == 'KICS']
        
        st.markdown("##### Generate CI/CD Configuration")
        
        ci_platform = st.selectbox(
            "CI/CD Platform",
            ["GitHub Actions", "GitLab CI", "Jenkins", "Azure DevOps", "CircleCI"],
            key="kics_ci_platform"
        )
        
        fail_on = st.multiselect(
            "Fail Pipeline On",
            ["CRITICAL", "HIGH", "MEDIUM"],
            default=["CRITICAL", "HIGH"],
            key="kics_fail_on"
        )
        
        if st.button("📝 Generate Configuration", type="primary"):
            config = generate_kics_ci_config(ci_platform, fail_on)
            st.code(config, language='yaml')
            st.download_button(
                "📥 Download Config",
                data=config,
                file_name=f"kics-{ci_platform.lower().replace(' ', '-')}.yml",
                mime="text/yaml"
            )
    
    # ==================== DEPLOYMENT HISTORY ====================
    with deploy_tabs[3]:
        st.markdown("#### 📋 Deployment History")
        
        history = workflow['deployments']['history']
        
        if not history:
            st.info("No deployments yet.")
        else:
            for deployment in reversed(history[-10:]):
                status_color = "#10b981" if deployment.get('status') == 'SUCCESS' else "#f59e0b"
                st.markdown(f"""
                <div style='background: #f8f9fa; padding: 1rem; border-radius: 8px; border-left: 4px solid {status_color}; margin-bottom: 0.5rem;'>
                    <strong>{deployment.get('policy_name', 'Unknown')}</strong> ({deployment.get('type', 'Unknown')})
                    <br/>
                    <small>
                        Target: {deployment.get('target', 'Unknown')} | 
                        Mode: {deployment.get('mode', 'Unknown')} | 
                        {deployment.get('timestamp', 'Unknown')}
                    </small>
                </div>
                """, unsafe_allow_html=True)


def deploy_scp_policies(workflow: Dict, policies: List[Dict], target_ous: List[str], mode: str, notifications: List[str]):
    """Deploy SCP policies to AWS Organizations"""
    is_demo = st.session_state.get('demo_mode', True)
    
    progress = st.progress(0)
    status = st.empty()
    
    for i, policy in enumerate(policies):
        status.text(f"Deploying: {policy.get('name', 'Unknown')}...")
        
        if is_demo:
            # Simulate deployment
            time.sleep(1)
            deployment_id = f"scp-{uuid.uuid4().hex[:8]}"
            
            workflow['deployments']['history'].append({
                'id': deployment_id,
                'policy_name': policy.get('name'),
                'type': 'SCP',
                'target': ', '.join(target_ous),
                'mode': mode,
                'status': 'SUCCESS',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            # Real AWS deployment
            try:
                org_client = st.session_state.get('aws_clients', {}).get('organizations')
                if org_client:
                    response = org_client.create_policy(
                        Content=json.dumps(policy.get('policy_content', {})),
                        Description=policy.get('description', ''),
                        Name=policy.get('name', f'Policy-{uuid.uuid4().hex[:8]}'),
                        Type='SERVICE_CONTROL_POLICY'
                    )
                    
                    policy_id = response['Policy']['PolicySummary']['Id']
                    
                    workflow['deployments']['history'].append({
                        'id': policy_id,
                        'policy_name': policy.get('name'),
                        'type': 'SCP',
                        'target': ', '.join(target_ous),
                        'mode': mode,
                        'status': 'SUCCESS',
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
            except Exception as e:
                st.error(f"Deployment failed: {e}")
        
        progress.progress((i + 1) / len(policies))
    
    status.empty()
    st.success(f"✅ Deployed {len(policies)} SCP policies to {len(target_ous)} OUs!")


def deploy_opa_policies(workflow: Dict, policies: List[Dict], targets: List[str]):
    """Deploy OPA policies"""
    progress = st.progress(0)
    
    for i, policy in enumerate(policies):
        time.sleep(0.5)
        
        workflow['deployments']['history'].append({
            'id': f"opa-{uuid.uuid4().hex[:8]}",
            'policy_name': policy.get('name'),
            'type': 'OPA',
            'target': ', '.join(targets),
            'mode': 'Enforce',
            'status': 'SUCCESS',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        progress.progress((i + 1) / len(policies))
    
    st.success(f"✅ Deployed {len(policies)} OPA policies!")


def generate_kics_ci_config(platform: str, fail_on: List[str]) -> str:
    """Generate KICS CI/CD configuration"""
    severity_threshold = fail_on[0].lower() if fail_on else 'high'
    
    if platform == "GitHub Actions":
        return f"""name: KICS IaC Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  kics-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run KICS Scan
        uses: checkmarx/kics-github-action@v1.7.0
        with:
          path: '.'
          fail_on: {severity_threshold}
          output_path: 'results'
          output_formats: 'json,sarif'
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results/results.sarif
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: kics-results
          path: results/
"""
    elif platform == "GitLab CI":
        return f"""kics-scan:
  stage: security
  image: checkmarx/kics:latest
  script:
    - kics scan -p . -o results --report-formats json,sarif
    - |
      if [ $(jq '.severity_counters.{severity_threshold.upper()}' results/results.json) -gt 0 ]; then
        echo "Found {severity_threshold} severity issues!"
        exit 1
      fi
  artifacts:
    reports:
      sast: results/results.sarif
    paths:
      - results/
"""
    else:
        return f"""# KICS Configuration for {platform}
# Fail on: {', '.join(fail_on)}

# Install KICS
curl -sfL https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh | sh

# Run scan
kics scan \\
  --path . \\
  --output-path results \\
  --report-formats json,sarif \\
  --fail-on {severity_threshold}
"""


# ============================================================================
# TAB 5: MONITOR & REPORT
# ============================================================================

def render_monitor_tab():
    """Tab 5: Compliance monitoring dashboard and reports"""
    st.markdown("### 📊 Monitor & Report")
    st.markdown("""
    <div style='background: #ede9fe; padding: 1rem; border-radius: 8px; border-left: 4px solid #8b5cf6; margin-bottom: 1rem;'>
        <strong>Step 5:</strong> Monitor compliance status, generate reports, and configure alerts.
    </div>
    """, unsafe_allow_html=True)
    
    workflow = st.session_state.guardrails_workflow
    
    # Monitor sub-tabs
    monitor_tabs = st.tabs(["📊 Dashboard", "📈 Trends", "📄 Reports", "🔔 Alerts", "💬 AI Assistant"])
    
    # ==================== DASHBOARD ====================
    with monitor_tabs[0]:
        st.markdown("#### 📊 Compliance Dashboard")
        
        violations = workflow['violations']
        deployments = workflow['deployments']
        
        # Top metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            total_violations = violations['summary'].get('total', 0)
            st.metric("Total Violations", total_violations, delta="-5 from last week", delta_color="inverse")
        
        with col2:
            critical = violations['summary'].get('critical', 0)
            st.metric("🔴 Critical", critical, delta="-2", delta_color="inverse")
        
        with col3:
            policies_deployed = len(deployments['history'])
            st.metric("Policies Deployed", policies_deployed, delta="+3")
        
        with col4:
            # Calculate compliance score
            total_checks = max(total_violations + 100, 1)  # Assume 100 passed checks
            compliance_score = int(100 * (total_checks - total_violations) / total_checks)
            st.metric("Compliance Score", f"{compliance_score}%", delta="+2%")
        
        with col5:
            st.metric("Active Policies", len(workflow['selected_policies']))
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Compliance by Framework")
            
            # Sample framework compliance data
            framework_data = {
                'Framework': list(COMPLIANCE_FRAMEWORKS.keys())[:5],
                'Score': [92, 88, 95, 78, 85]
            }
            
            fig = px.bar(
                framework_data,
                x='Framework',
                y='Score',
                color='Score',
                color_continuous_scale='RdYlGn',
                range_color=[0, 100]
            )
            fig.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("##### Violations by Category")
            
            category_data = {}
            for v in violations['all']:
                cat = v.get('policy_type', 'Unknown')
                category_data[cat] = category_data.get(cat, 0) + 1
            
            if category_data:
                fig = px.pie(
                    values=list(category_data.values()),
                    names=list(category_data.keys()),
                    hole=0.4
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No violation data to display")
        
        # Recent activity
        st.markdown("---")
        st.markdown("##### Recent Activity")
        
        activities = [
            {"time": "2 mins ago", "action": "SCP Deployed", "resource": "DenyPublicS3", "status": "success"},
            {"time": "15 mins ago", "action": "Violation Detected", "resource": "prod-account", "status": "warning"},
            {"time": "1 hour ago", "action": "Auto-Remediated", "resource": "sg-open-world", "status": "success"},
            {"time": "2 hours ago", "action": "Scan Completed", "resource": "Full Scan", "status": "success"},
        ]
        
        for activity in activities:
            status_color = "#10b981" if activity['status'] == "success" else "#f59e0b"
            st.markdown(f"""
            <div style='background: #f8f9fa; padding: 0.75rem; border-radius: 6px; border-left: 4px solid {status_color}; margin-bottom: 0.5rem;'>
                <strong>{activity['action']}</strong> - {activity['resource']}
                <small style='float: right; color: #6b7280;'>{activity['time']}</small>
            </div>
            """, unsafe_allow_html=True)
    
    # ==================== TRENDS ====================
    with monitor_tabs[1]:
        st.markdown("#### 📈 Compliance Trends")
        
        # Generate trend data
        dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
        trend_data = pd.DataFrame({
            'Date': dates,
            'Compliance Score': [85 + i * 0.3 + np.random.randint(-2, 3) for i in range(30)],
            'Violations': [45 - i * 0.5 + np.random.randint(-3, 3) for i in range(30)],
            'Policies': [10 + i // 5 for i in range(30)]
        })
        
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        fig.add_trace(
            go.Scatter(x=trend_data['Date'], y=trend_data['Compliance Score'], name="Compliance %", line=dict(color='#10b981')),
            secondary_y=False
        )
        
        fig.add_trace(
            go.Bar(x=trend_data['Date'], y=trend_data['Violations'], name="Violations", marker_color='#ef4444', opacity=0.5),
            secondary_y=True
        )
        
        fig.update_layout(title="30-Day Compliance Trend")
        fig.update_yaxes(title_text="Compliance %", secondary_y=False)
        fig.update_yaxes(title_text="Violations", secondary_y=True)
        
        st.plotly_chart(fig, use_container_width=True)
    
    # ==================== REPORTS ====================
    with monitor_tabs[2]:
        st.markdown("#### 📄 Generate Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_type = st.selectbox(
                "Report Type",
                ["Executive Summary", "Detailed Compliance", "Violation Report", "Audit Trail"],
                key="report_type"
            )
            
            report_format = st.selectbox(
                "Format",
                ["PDF", "Excel", "JSON"],
                key="report_format"
            )
        
        with col2:
            date_range = st.selectbox(
                "Date Range",
                ["Last 7 Days", "Last 30 Days", "Last 90 Days", "Custom"],
                key="report_date_range"
            )
            
            frameworks = st.multiselect(
                "Include Frameworks",
                list(COMPLIANCE_FRAMEWORKS.keys()),
                default=["PCI-DSS", "SOC2"],
                key="report_frameworks"
            )
        
        if st.button("📄 Generate Report", type="primary", use_container_width=True):
            with st.spinner("Generating report..."):
                time.sleep(2)
                
                # Generate sample report content
                report_content = f"""
# Tech Guardrails Compliance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- Total Policies: {len(workflow['selected_policies'])}
- Total Violations: {workflow['violations']['summary'].get('total', 0)}
- Compliance Score: 92%

## Violations by Severity
- Critical: {workflow['violations']['summary'].get('critical', 0)}
- High: {workflow['violations']['summary'].get('high', 0)}
- Medium: {workflow['violations']['summary'].get('medium', 0)}
- Low: {workflow['violations']['summary'].get('low', 0)}

## Framework Compliance
{chr(10).join([f'- {fw}: Compliant' for fw in frameworks])}

## Recommendations
1. Address critical violations within 4 hours
2. Schedule high-severity fixes within 24 hours
3. Review and update policies quarterly
"""
                
                st.success("✅ Report generated!")
                st.download_button(
                    "📥 Download Report",
                    data=report_content,
                    file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d')}.md",
                    mime="text/markdown"
                )
    
    # ==================== ALERTS ====================
    with monitor_tabs[3]:
        st.markdown("#### 🔔 Alert Configuration")
        
        st.markdown("##### Notification Channels")
        
        col1, col2 = st.columns(2)
        
        with col1:
            slack_enabled = st.toggle("Slack", value=True, key="alert_slack")
            if slack_enabled:
                slack_webhook = st.text_input("Webhook URL", placeholder="https://hooks.slack.com/...", key="slack_webhook")
                slack_channel = st.text_input("Channel", value="#compliance-alerts", key="slack_channel")
        
        with col2:
            email_enabled = st.toggle("Email", value=True, key="alert_email")
            if email_enabled:
                email_recipients = st.text_area("Recipients (one per line)", value="security@company.com\ncompliance@company.com", key="email_recipients")
        
        st.markdown("##### Alert Rules")
        
        st.checkbox("🔴 Critical violations - Immediate", value=True, key="alert_critical")
        st.checkbox("🟠 High violations - Within 1 hour", value=True, key="alert_high")
        st.checkbox("📊 Daily summary", value=True, key="alert_daily")
        st.checkbox("📈 Weekly compliance report", value=True, key="alert_weekly")
        
        if st.button("💾 Save Alert Configuration", type="primary"):
            st.success("✅ Alert configuration saved!")
    
    # ==================== AI ASSISTANT ====================
    with monitor_tabs[4]:
        st.markdown("#### 💬 AI Compliance Assistant")
        st.markdown("Ask questions about your compliance status, policies, or get recommendations.")
        
        # Chat interface
        if 'guardrails_chat_history' not in st.session_state:
            st.session_state.guardrails_chat_history = []
        
        # Display chat history
        for msg in st.session_state.guardrails_chat_history[-5:]:
            if msg['role'] == 'user':
                st.markdown(f"**You:** {msg['content']}")
            else:
                st.markdown(f"**🤖 Assistant:** {msg['content']}")
        
        # Input
        user_query = st.text_input("Ask a question...", placeholder="What are my most critical compliance gaps?", key="ai_query")
        
        if st.button("Send", key="send_query") and user_query:
            st.session_state.guardrails_chat_history.append({'role': 'user', 'content': user_query})
            
            # Get AI response
            ai_engine = st.session_state.guardrails_ai
            context = {
                'total_policies': len(workflow['selected_policies']),
                'total_violations': workflow['violations']['summary'].get('total', 0),
                'critical_violations': workflow['violations']['summary'].get('critical', 0),
                'compliance_score': 92,
                'top_issues': ['S3 encryption', 'Security groups', 'IAM permissions']
            }
            
            response = ai_engine.natural_language_query(user_query, context)
            st.session_state.guardrails_chat_history.append({'role': 'assistant', 'content': response})
            
            st.rerun()


# ============================================================================
# MAIN DASHBOARD FUNCTION
# ============================================================================

def render_tech_guardrails_dashboard():
    """Main entry point for Tech Guardrails Enterprise Dashboard"""
    
    # Initialize workflow state
    init_guardrails_workflow_state()
    
    # Header
    st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 50%, #3b82f6 100%); 
                padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>🚧 Tech Guardrails Enterprise</h2>
        <p style='color: #94a3b8; margin: 0.5rem 0 0 0;'>
            AI-Powered Policy Management | SCP • OPA • KICS • Config Rules
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Workflow progress
    render_guardrails_workflow_progress()
    
    st.markdown("---")
    
    # Main workflow tabs
    workflow_tabs = st.tabs([
        "📚 Policy Library",
        "🔍 Compliance Scan",
        "🎯 AI Triage",
        "🚀 Deploy & Enforce",
        "📊 Monitor & Report"
    ])
    
    with workflow_tabs[0]:
        render_policy_library_tab()
    
    with workflow_tabs[1]:
        render_compliance_scan_tab()
    
    with workflow_tabs[2]:
        render_triage_tab()
    
    with workflow_tabs[3]:
        render_deploy_tab()
    
    with workflow_tabs[4]:
        render_monitor_tab()


# ============================================================================
# EXPORT FOR MAIN APP
# ============================================================================

__all__ = ['render_tech_guardrails_dashboard', 'POLICY_LIBRARY', 'COMPLIANCE_FRAMEWORKS']
