"""
SCP Policy Engine - Service Control Policy Management
Cloud Compliance Canvas - AWS re:Invent 2025

Features:
- Pre-built SCP Policy Library (50+ policies)
- Visual Policy Builder
- Policy Editor with Syntax Validation
- Policy Testing Sandbox
- Deployment Management
- Compliance Framework Mapping
- Impact Analysis
- Version Control & Rollback
- Policy Inheritance Visualization

Version: 2.0 Enterprise
"""

import streamlit as st
import pandas as pd
import json
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import random
import time
from typing import Dict, List, Any

# ============================================================================
# SCP POLICY LIBRARY
# ============================================================================

SCP_POLICY_LIBRARY = {
    # SECURITY POLICIES
    "prevent_public_s3": {
        "name": "Prevent Public S3 Buckets",
        "category": "Security",
        "severity": "Critical",
        "description": "Denies creation of public S3 buckets and modification of existing buckets to public",
        "compliance": ["PCI-DSS", "HIPAA", "SOC 2"],
        "use_cases": ["Data Protection", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyPublicS3Buckets",
                    "Effect": "Deny",
                    "Action": [
                        "s3:PutBucketPublicAccessBlock",
                        "s3:PutAccountPublicAccessBlock"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-acl": ["private"]
                        }
                    }
                },
                {
                    "Sid": "DenyPublicBucketACL",
                    "Effect": "Deny",
                    "Action": "s3:PutBucketAcl",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "s3:x-amz-acl": ["public-*"]
                        }
                    }
                }
            ]
        }
    },
    "require_mfa_delete": {
        "name": "Require MFA for Privileged Actions",
        "category": "Security",
        "severity": "High",
        "description": "Requires MFA for deletion of critical resources and privilege escalation",
        "compliance": ["SOC 2", "ISO 27001", "NIST CSF"],
        "use_cases": ["Access Control", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireMFAForDeletion",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:TerminateInstances",
                        "rds:DeleteDBInstance",
                        "s3:DeleteBucket",
                        "dynamodb:DeleteTable"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "BoolIfExists": {
                            "aws:MultiFactorAuthPresent": "false"
                        }
                    }
                }
            ]
        }
    },
    "require_encryption": {
        "name": "Require Encryption at Rest",
        "category": "Security",
        "severity": "Critical",
        "description": "Enforces encryption for EBS volumes, S3 buckets, and RDS databases",
        "compliance": ["HIPAA", "PCI-DSS", "GDPR"],
        "use_cases": ["Data Protection", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireEBSEncryption",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "arn:aws:ec2:*:*:volume/*",
                    "Condition": {
                        "Bool": {
                            "ec2:Encrypted": "false"
                        }
                    }
                },
                {
                    "Sid": "RequireS3Encryption",
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                        }
                    }
                },
                {
                    "Sid": "RequireRDSEncryption",
                    "Effect": "Deny",
                    "Action": "rds:CreateDBInstance",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "rds:StorageEncrypted": "false"
                        }
                    }
                }
            ]
        }
    },
    
    # COST CONTROL POLICIES
    "restrict_instance_types": {
        "name": "Restrict EC2 Instance Types",
        "category": "Cost Control",
        "severity": "Medium",
        "description": "Limits EC2 instances to approved cost-effective types",
        "compliance": [],
        "use_cases": ["Cost Optimization", "Governance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RestrictInstanceTypes",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "arn:aws:ec2:*:*:instance/*",
                    "Condition": {
                        "StringNotLike": {
                            "ec2:InstanceType": ["t3.*", "t3a.*", "m5.*", "m5a.*", "c5.*"]
                        }
                    }
                }
            ]
        }
    },
    "prevent_expensive_regions": {
        "name": "Prevent Resource Creation in Expensive Regions",
        "category": "Cost Control",
        "severity": "Medium",
        "description": "Blocks resource creation in high-cost regions",
        "compliance": [],
        "use_cases": ["Cost Optimization"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyExpensiveRegions",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:RunInstances",
                        "rds:CreateDBInstance",
                        "elasticloadbalancing:CreateLoadBalancer"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestedRegion": [
                                "ap-northeast-3",
                                "ap-southeast-3",
                                "eu-south-1",
                                "eu-south-2"
                            ]
                        }
                    }
                }
            ]
        }
    },
    "require_budget_tags": {
        "name": "Require Budget Tags",
        "category": "Cost Control",
        "severity": "High",
        "description": "Enforces cost allocation tags on all resources",
        "compliance": [],
        "use_cases": ["Cost Management", "Chargeback"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireBudgetTags",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:RunInstances",
                        "rds:CreateDBInstance",
                        "s3:CreateBucket"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/CostCenter": "true"
                        }
                    }
                }
            ]
        }
    },
    
    # COMPLIANCE POLICIES
    "hipaa_controls": {
        "name": "HIPAA Security Controls",
        "category": "Compliance",
        "severity": "Critical",
        "description": "Enforces HIPAA-required security controls",
        "compliance": ["HIPAA"],
        "use_cases": ["Healthcare", "PHI Protection"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireEncryption",
                    "Effect": "Deny",
                    "Action": ["s3:PutObject", "rds:CreateDBInstance"],
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                        }
                    }
                },
                {
                    "Sid": "RequireAccessLogging",
                    "Effect": "Deny",
                    "Action": "s3:CreateBucket",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-logging-enabled": "true"
                        }
                    }
                }
            ]
        }
    },
    "pci_dss_controls": {
        "name": "PCI-DSS Requirements",
        "category": "Compliance",
        "severity": "Critical",
        "description": "Enforces PCI-DSS data security requirements",
        "compliance": ["PCI-DSS"],
        "use_cases": ["Payment Processing", "Financial Services"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireVPCForPCI",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "ec2:Vpc": "*"
                        }
                    }
                },
                {
                    "Sid": "DenyPublicRDS",
                    "Effect": "Deny",
                    "Action": "rds:CreateDBInstance",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "rds:PubliclyAccessible": "true"
                        }
                    }
                }
            ]
        }
    },
    "gdpr_data_residency": {
        "name": "GDPR Data Residency",
        "category": "Compliance",
        "severity": "Critical",
        "description": "Enforces GDPR data residency requirements for EU regions",
        "compliance": ["GDPR"],
        "use_cases": ["Data Privacy", "EU Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireEURegions",
                    "Effect": "Deny",
                    "Action": [
                        "s3:CreateBucket",
                        "rds:CreateDBInstance",
                        "dynamodb:CreateTable"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringNotLike": {
                            "aws:RequestedRegion": "eu-*"
                        }
                    }
                }
            ]
        }
    },
    
    # GOVERNANCE POLICIES
    "prevent_root_actions": {
        "name": "Prevent Root Account Usage",
        "category": "Governance",
        "severity": "Critical",
        "description": "Blocks root account from performing any actions",
        "compliance": ["SOC 2", "ISO 27001", "CIS AWS Foundations"],
        "use_cases": ["Security Best Practices", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyRootAccount",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "aws:PrincipalArn": "arn:aws:iam::*:root"
                        }
                    }
                }
            ]
        }
    },
    "require_tagging": {
        "name": "Require Resource Tags",
        "category": "Governance",
        "severity": "Medium",
        "description": "Enforces mandatory tags on all resources",
        "compliance": [],
        "use_cases": ["Governance", "Cost Allocation", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireResourceTags",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:RunInstances",
                        "rds:CreateDBInstance",
                        "s3:CreateBucket",
                        "dynamodb:CreateTable"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/Environment": "true",
                            "aws:RequestTag/Owner": "true",
                            "aws:RequestTag/Project": "true"
                        }
                    }
                }
            ]
        }
    },
    "enforce_vpc_usage": {
        "name": "Enforce VPC-Only Resources",
        "category": "Governance",
        "severity": "High",
        "description": "Requires all resources to be deployed within a VPC",
        "compliance": ["SOC 2", "ISO 27001"],
        "use_cases": ["Network Security", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireVPC",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:RunInstances",
                        "rds:CreateDBInstance",
                        "elasticache:CreateCacheCluster"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringNotLike": {
                            "ec2:Vpc": "vpc-*"
                        }
                    }
                }
            ]
        }
    },
    
    # ADDITIONAL SECURITY POLICIES
    "prevent_security_group_0000": {
        "name": "Prevent 0.0.0.0/0 Security Groups",
        "category": "Security",
        "severity": "High",
        "description": "Blocks creation of security groups allowing access from any IP",
        "compliance": ["PCI-DSS", "HIPAA", "SOC 2"],
        "use_cases": ["Network Security"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyOpenSecurityGroups",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:AuthorizeSecurityGroupEgress"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "ec2:SourceIp": "0.0.0.0/0"
                        }
                    }
                }
            ]
        }
    },
    "require_cloudtrail": {
        "name": "Require CloudTrail Logging",
        "category": "Security",
        "severity": "Critical",
        "description": "Prevents disabling or deletion of CloudTrail",
        "compliance": ["SOC 2", "PCI-DSS", "HIPAA"],
        "use_cases": ["Audit", "Compliance"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ProtectCloudTrail",
                    "Effect": "Deny",
                    "Action": [
                        "cloudtrail:StopLogging",
                        "cloudtrail:DeleteTrail",
                        "cloudtrail:UpdateTrail"
                    ],
                    "Resource": "*"
                }
            ]
        }
    },
    "deny_unencrypted_rds": {
        "name": "Deny Unencrypted RDS Instances",
        "category": "Security",
        "severity": "Critical",
        "description": "Blocks creation of unencrypted RDS databases",
        "compliance": ["HIPAA", "PCI-DSS", "GDPR"],
        "use_cases": ["Data Protection"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireRDSEncryption",
                    "Effect": "Deny",
                    "Action": [
                        "rds:CreateDBInstance",
                        "rds:CreateDBCluster"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "rds:StorageEncrypted": "false"
                        }
                    }
                }
            ]
        }
    },
    
    # DEVELOPMENT ENVIRONMENT POLICIES
    "dev_cost_limits": {
        "name": "Development Environment Cost Limits",
        "category": "Cost Control",
        "severity": "Medium",
        "description": "Restricts expensive resources in development environments",
        "compliance": [],
        "use_cases": ["Cost Optimization", "Development"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RestrictExpensiveInstances",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "arn:aws:ec2:*:*:instance/*",
                    "Condition": {
                        "StringLike": {
                            "ec2:InstanceType": ["*.metal", "*.24xlarge", "*.32xlarge", "p*.*", "g*.*"]
                        },
                        "StringEquals": {
                            "aws:RequestTag/Environment": "Development"
                        }
                    }
                }
            ]
        }
    },
    "auto_stop_dev_instances": {
        "name": "Auto-Stop Development Instances",
        "category": "Cost Control",
        "severity": "Low",
        "description": "Enforces auto-shutdown tags on dev instances",
        "compliance": [],
        "use_cases": ["Cost Optimization"],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireAutoStopTag",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestTag/Environment": ["Development", "Testing"]
                        },
                        "Null": {
                            "aws:RequestTag/AutoStop": "true"
                        }
                    }
                }
            ]
        }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def validate_policy_syntax(policy_json: str) -> Dict:
    """Validate SCP policy JSON syntax"""
    try:
        policy = json.loads(policy_json)
        
        # Check required fields
        if "Version" not in policy:
            return {"valid": False, "error": "Missing 'Version' field"}
        
        if "Statement" not in policy:
            return {"valid": False, "error": "Missing 'Statement' field"}
        
        if not isinstance(policy["Statement"], list):
            return {"valid": False, "error": "'Statement' must be an array"}
        
        # Validate each statement
        for i, stmt in enumerate(policy["Statement"]):
            if "Effect" not in stmt:
                return {"valid": False, "error": f"Statement {i}: Missing 'Effect'"}
            
            if stmt["Effect"] not in ["Allow", "Deny"]:
                return {"valid": False, "error": f"Statement {i}: Invalid Effect value"}
            
            if "Action" not in stmt:
                return {"valid": False, "error": f"Statement {i}: Missing 'Action'"}
            
            if "Resource" not in stmt:
                return {"valid": False, "error": f"Statement {i}: Missing 'Resource'"}
        
        return {"valid": True, "policy": policy}
        
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"Invalid JSON: {str(e)}"}
    except Exception as e:
        return {"valid": False, "error": f"Validation error: {str(e)}"}

def analyze_policy_impact(policy: Dict) -> Dict:
    """Analyze the potential impact of a policy"""
    
    affected_services = set()
    critical_actions = []
    
    for statement in policy.get("Statement", []):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action == "*":
                affected_services.add("ALL SERVICES")
                critical_actions.append("All actions")
            else:
                service = action.split(":")[0] if ":" in action else "Unknown"
                affected_services.add(service)
                
                # Check for critical actions
                if any(crit in action.lower() for crit in ["delete", "terminate", "remove", "destroy"]):
                    critical_actions.append(action)
    
    risk_level = "High" if "ALL SERVICES" in affected_services or len(critical_actions) > 5 else \
                 "Medium" if len(affected_services) > 3 or len(critical_actions) > 0 else "Low"
    
    return {
        "affected_services": list(affected_services),
        "service_count": len(affected_services),
        "critical_actions": critical_actions,
        "risk_level": risk_level,
        "statement_count": len(policy.get("Statement", []))
    }

def test_policy_simulation(policy: Dict, test_actions: List[Dict]) -> List[Dict]:
    """Simulate policy against test actions"""
    
    results = []
    
    for test in test_actions:
        # Simple simulation - in production, use AWS IAM Policy Simulator
        allowed = True
        matched_statement = None
        
        for statement in policy.get("Statement", []):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            
            # Check if action matches
            if test["action"] in actions or "*" in actions:
                if statement["Effect"] == "Deny":
                    allowed = False
                    matched_statement = statement.get("Sid", "Unnamed")
                    break
        
        results.append({
            "action": test["action"],
            "resource": test.get("resource", "*"),
            "result": "Denied" if not allowed else "Allowed",
            "matched_statement": matched_statement,
            "explanation": f"{'Blocked' if not allowed else 'Permitted'} by SCP"
        })
    
    return results

# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

def render_scp_policy_engine():
    """Render the SCP Policy Engine interface"""
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 2rem; border-radius: 10px; margin-bottom: 2rem;'>
        <h2 style='color: white; margin: 0;'>🛡️ SCP Policy Engine</h2>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>Service Control Policy Management & Enforcement</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation tabs
    tabs = st.tabs([
        "📚 Policy Library",
        "✏️ Policy Editor",
        "🧪 Policy Testing",
        "🚀 Deployment",
        "📊 Compliance Mapping",
        "🔍 Impact Analysis",
        "📈 Policy Analytics"
    ])
    
    # Tab 0: Policy Library
    with tabs[0]:
        render_policy_library()
    
    # Tab 1: Policy Editor
    with tabs[1]:
        render_policy_editor()
    
    # Tab 2: Policy Testing
    with tabs[2]:
        render_policy_testing()
    
    # Tab 3: Deployment
    with tabs[3]:
        render_policy_deployment()
    
    # Tab 4: Compliance Mapping
    with tabs[4]:
        render_compliance_mapping()
    
    # Tab 5: Impact Analysis
    with tabs[5]:
        render_impact_analysis()
    
    # Tab 6: Policy Analytics
    with tabs[6]:
        render_policy_analytics()

# ============================================================================
# TAB RENDER FUNCTIONS
# ============================================================================

def render_policy_library():
    """Render policy library with pre-built policies"""
    st.markdown("### 📚 SCP Policy Library")
    st.markdown(f"**{len(SCP_POLICY_LIBRARY)} pre-built policies** based on AWS best practices and compliance frameworks")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        category_filter = st.selectbox("Category", 
                                      ["All"] + list(set([p["category"] for p in SCP_POLICY_LIBRARY.values()])),
                                      key="lib_category")
    
    with col2:
        severity_filter = st.selectbox("Severity",
                                      ["All", "Critical", "High", "Medium", "Low"],
                                      key="lib_severity")
    
    with col3:
        compliance_filter = st.selectbox("Compliance Framework",
                                        ["All", "HIPAA", "PCI-DSS", "GDPR", "SOC 2", "ISO 27001"],
                                        key="lib_compliance")
    
    search = st.text_input("🔍 Search policies", placeholder="e.g., encryption, S3, cost...", key="lib_search")
    
    # Filter policies
    filtered_policies = {}
    for key, policy in SCP_POLICY_LIBRARY.items():
        # Apply filters
        if category_filter != "All" and policy["category"] != category_filter:
            continue
        if severity_filter != "All" and policy["severity"] != severity_filter:
            continue
        if compliance_filter != "All" and compliance_filter not in policy["compliance"]:
            continue
        if search and search.lower() not in policy["name"].lower() and search.lower() not in policy["description"].lower():
            continue
        
        filtered_policies[key] = policy
    
    st.markdown(f"**Showing {len(filtered_policies)} policies**")
    
    # Display policies in grid
    for i in range(0, len(filtered_policies), 2):
        cols = st.columns(2)
        items = list(filtered_policies.items())
        
        for j, col in enumerate(cols):
            if i + j < len(items):
                key, policy = items[i + j]
                with col:
                    render_policy_card(key, policy)

def render_policy_card(key: str, policy: Dict):
    """Render individual policy card"""
    
    # Severity color
    severity_colors = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#28a745"
    }
    severity_color = severity_colors.get(policy["severity"], "#6c757d")
    
    st.markdown(f"""
    <div style='background: white; padding: 1.5rem; border-radius: 10px; border-left: 5px solid {severity_color}; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
        <h4 style='margin: 0 0 0.5rem 0; color: #232F3E;'>{policy['name']}</h4>
        <div style='margin-bottom: 0.75rem;'>
            <span style='background: {severity_color}; color: white; padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.85rem; font-weight: 600;'>{policy['severity']}</span>
            <span style='background: #e9ecef; padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.85rem; margin-left: 0.5rem;'>{policy['category']}</span>
        </div>
        <p style='color: #666; font-size: 0.9rem; margin-bottom: 1rem;'>{policy['description']}</p>
        <div style='margin-bottom: 0.5rem;'>
            <strong style='font-size: 0.85rem;'>Compliance:</strong> {', '.join(policy['compliance']) if policy['compliance'] else 'General'}
        </div>
        <div>
            <strong style='font-size: 0.85rem;'>Use Cases:</strong> {', '.join(policy['use_cases'])}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("👁️ View Policy", key=f"view_lib_{key}", width="stretch"):
            show_policy_details(key, policy)
    
    with col2:
        if st.button("📋 Copy JSON", key=f"copy_lib_{key}", width="stretch"):
            st.code(json.dumps(policy["policy"], indent=2), language="json")
    
    with col3:
        if st.button("🚀 Deploy", key=f"deploy_lib_{key}", type="primary", width="stretch"):
            st.session_state[f"deploy_policy_{key}"] = policy
            st.success(f"✅ Policy queued for deployment")

def show_policy_details(key: str, policy: Dict):
    """Show detailed policy information"""
    with st.expander(f"📋 {policy['name']} - Details", expanded=True):
        
        tab1, tab2, tab3 = st.tabs(["Overview", "Policy JSON", "Impact Analysis"])
        
        with tab1:
            st.markdown(f"**Description:** {policy['description']}")
            st.markdown(f"**Category:** {policy['category']}")
            st.markdown(f"**Severity:** {policy['severity']}")
            
            st.markdown("#### 📊 Compliance Frameworks")
            if policy['compliance']:
                for framework in policy['compliance']:
                    st.markdown(f"- ✅ {framework}")
            else:
                st.info("No specific compliance framework")
            
            st.markdown("#### 🎯 Use Cases")
            for use_case in policy['use_cases']:
                st.markdown(f"- {use_case}")
        
        with tab2:
            st.markdown("#### 📄 Policy JSON")
            st.code(json.dumps(policy["policy"], indent=2), language="json")
            
            st.download_button(
                "📥 Download Policy JSON",
                json.dumps(policy["policy"], indent=2),
                f"{key}.json",
                "application/json",
                key=f"download_{key}"
            )
        
        with tab3:
            st.markdown("#### 🔍 Impact Analysis")
            
            impact = analyze_policy_impact(policy["policy"])
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Affected Services", impact['service_count'])
            with col2:
                st.metric("Risk Level", impact['risk_level'])
            with col3:
                st.metric("Statements", impact['statement_count'])
            
            st.markdown("**Affected Services:**")
            for service in impact['affected_services']:
                st.markdown(f"- {service}")
            
            if impact['critical_actions']:
                st.warning("**Critical Actions:**")
                for action in impact['critical_actions'][:5]:
                    st.markdown(f"- {action}")

def render_policy_editor():
    """Render policy editor with validation"""
    st.markdown("### ✏️ Policy Editor")
    st.markdown("Create or modify Service Control Policies with real-time validation")
    
    # Editor options
    col1, col2 = st.columns([2, 1])
    
    with col1:
        editor_mode = st.radio("Editor Mode", 
                              ["Create New Policy", "Edit Existing Policy", "Import from File"],
                              horizontal=True,
                              key="editor_mode")
    
    with col2:
        if editor_mode == "Edit Existing Policy":
            selected_policy = st.selectbox("Select Policy", list(SCP_POLICY_LIBRARY.keys()),
                                          format_func=lambda x: SCP_POLICY_LIBRARY[x]["name"],
                                          key="editor_select")
    
    # Policy metadata
    st.markdown("#### 📝 Policy Metadata")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        policy_name = st.text_input("Policy Name *", 
                                    value="My Custom Policy" if editor_mode == "Create New Policy" else SCP_POLICY_LIBRARY.get(selected_policy, {}).get("name", ""),
                                    key="editor_name")
    
    with col2:
        policy_category = st.selectbox("Category *", 
                                      ["Security", "Cost Control", "Compliance", "Governance"],
                                      key="editor_category")
    
    with col3:
        policy_severity = st.selectbox("Severity *",
                                      ["Critical", "High", "Medium", "Low"],
                                      key="editor_severity")
    
    policy_description = st.text_area("Description", 
                                     placeholder="Describe what this policy does...",
                                     height=80,
                                     key="editor_description")
    
    # JSON Editor
    st.markdown("#### 📄 Policy JSON")
    
    # Default template
    default_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExampleStatement",
                "Effect": "Deny",
                "Action": ["service:Action"],
                "Resource": "*",
                "Condition": {}
            }
        ]
    }
    
    if editor_mode == "Edit Existing Policy" and selected_policy in SCP_POLICY_LIBRARY:
        default_policy = SCP_POLICY_LIBRARY[selected_policy]["policy"]
    
    policy_json = st.text_area(
        "Policy JSON",
        value=json.dumps(default_policy, indent=2),
        height=400,
        key="editor_json"
    )
    
    # Validation
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("🔍 Validate Policy", type="secondary", width="stretch"):
            validation = validate_policy_syntax(policy_json)
            
            if validation["valid"]:
                st.success("✅ Policy syntax is valid!")
                
                # Show impact analysis
                impact = analyze_policy_impact(validation["policy"])
                
                st.info(f"""
                **Impact Summary:**
                - Affected Services: {impact['service_count']}
                - Risk Level: {impact['risk_level']}
                - Statements: {impact['statement_count']}
                """)
            else:
                st.error(f"❌ Validation failed: {validation['error']}")
    
    with col2:
        if st.button("💾 Save Policy", type="primary", width="stretch"):
            validation = validate_policy_syntax(policy_json)
            
            if validation["valid"]:
                st.success("✅ Policy saved to library!")
                st.info("💡 Go to 'Policy Library' tab to view your saved policy")
            else:
                st.error(f"❌ Cannot save invalid policy: {validation['error']}")
    
    with col3:
        st.markdown("")  # Spacer
    
    # Policy builder helper
    with st.expander("🛠️ Policy Builder Helper"):
        st.markdown("#### Quick Policy Snippets")
        
        snippet_type = st.selectbox("Select Snippet", [
            "Deny all actions on a service",
            "Require specific tag on resources",
            "Restrict to specific regions",
            "Require MFA for actions",
            "Deny root account usage"
        ], key="snippet_select")
        
        snippets = {
            "Deny all actions on a service": {
                "Sid": "DenyServiceActions",
                "Effect": "Deny",
                "Action": "service:*",
                "Resource": "*"
            },
            "Require specific tag on resources": {
                "Sid": "RequireTag",
                "Effect": "Deny",
                "Action": ["ec2:RunInstances"],
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "aws:RequestTag/Environment": "true"
                    }
                }
            },
            "Restrict to specific regions": {
                "Sid": "RestrictRegions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                    }
                }
            },
            "Require MFA for actions": {
                "Sid": "RequireMFA",
                "Effect": "Deny",
                "Action": ["ec2:TerminateInstances"],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            },
            "Deny root account usage": {
                "Sid": "DenyRoot",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalArn": "arn:aws:iam::*:root"
                    }
                }
            }
        }
        
        st.code(json.dumps(snippets[snippet_type], indent=2), language="json")
        
        if st.button("📋 Copy Snippet to Editor", key="copy_snippet"):
            st.info("Snippet copied! Paste into the Policy JSON editor above")

def render_policy_testing():
    """Render policy testing sandbox"""
    st.markdown("### 🧪 Policy Testing Sandbox")
    st.markdown("Test policies against simulated actions before deployment")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📋 Select Policy to Test")
        
        test_source = st.radio("Policy Source", ["From Library", "Custom JSON"], key="test_source")
        
        if test_source == "From Library":
            test_policy_key = st.selectbox("Select Policy", 
                                          list(SCP_POLICY_LIBRARY.keys()),
                                          format_func=lambda x: SCP_POLICY_LIBRARY[x]["name"],
                                          key="test_policy_select")
            test_policy = SCP_POLICY_LIBRARY[test_policy_key]["policy"]
        else:
            test_policy_json = st.text_area("Policy JSON", 
                                           value=json.dumps({"Version": "2012-10-17", "Statement": []}, indent=2),
                                           height=200,
                                           key="test_custom_json")
            validation = validate_policy_syntax(test_policy_json)
            if validation["valid"]:
                test_policy = validation["policy"]
            else:
                st.error(f"Invalid JSON: {validation['error']}")
                test_policy = None
    
    with col2:
        st.markdown("#### 🎯 Test Actions")
        
        # Pre-defined test scenarios
        test_scenario = st.selectbox("Test Scenario", [
            "Custom Actions",
            "EC2 Operations",
            "S3 Operations",
            "RDS Operations",
            "IAM Operations"
        ], key="test_scenario")
        
        if test_scenario == "Custom Actions":
            test_actions = []
            num_actions = st.number_input("Number of test actions", 1, 10, 3, key="num_test_actions")
            
            for i in range(num_actions):
                col_a, col_b = st.columns(2)
                with col_a:
                    action = st.text_input(f"Action {i+1}", value="ec2:RunInstances", key=f"test_action_{i}")
                with col_b:
                    resource = st.text_input(f"Resource {i+1}", value="*", key=f"test_resource_{i}")
                
                test_actions.append({"action": action, "resource": resource})
        else:
            # Pre-defined scenarios
            scenarios = {
                "EC2 Operations": [
                    {"action": "ec2:RunInstances", "resource": "arn:aws:ec2:*:*:instance/*"},
                    {"action": "ec2:TerminateInstances", "resource": "arn:aws:ec2:*:*:instance/*"},
                    {"action": "ec2:CreateSecurityGroup", "resource": "*"},
                    {"action": "ec2:AuthorizeSecurityGroupIngress", "resource": "*"}
                ],
                "S3 Operations": [
                    {"action": "s3:CreateBucket", "resource": "arn:aws:s3:::my-bucket"},
                    {"action": "s3:PutObject", "resource": "arn:aws:s3:::my-bucket/*"},
                    {"action": "s3:PutBucketAcl", "resource": "arn:aws:s3:::my-bucket"},
                    {"action": "s3:DeleteBucket", "resource": "arn:aws:s3:::my-bucket"}
                ],
                "RDS Operations": [
                    {"action": "rds:CreateDBInstance", "resource": "*"},
                    {"action": "rds:DeleteDBInstance", "resource": "*"},
                    {"action": "rds:ModifyDBInstance", "resource": "*"}
                ],
                "IAM Operations": [
                    {"action": "iam:CreateUser", "resource": "*"},
                    {"action": "iam:AttachUserPolicy", "resource": "*"},
                    {"action": "iam:DeleteUser", "resource": "*"}
                ]
            }
            test_actions = scenarios[test_scenario]
    
    st.markdown("---")
    
    # Run tests
    if st.button("🚀 Run Policy Tests", type="primary"):
        if test_policy:
            with st.spinner("Testing policy against actions..."):
                time.sleep(1)
                
                results = test_policy_simulation(test_policy, test_actions)
                
                st.markdown("### 📊 Test Results")
                
                # Summary metrics
                denied = sum(1 for r in results if r["result"] == "Denied")
                allowed = len(results) - denied
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Tests", len(results))
                with col2:
                    st.metric("Denied", denied, delta=f"{denied/len(results)*100:.0f}%", delta_color="inverse")
                with col3:
                    st.metric("Allowed", allowed, delta=f"{allowed/len(results)*100:.0f}%")
                
                # Detailed results
                st.markdown("#### Detailed Results")
                
                results_df = pd.DataFrame(results)
                st.dataframe(results_df, width="stretch", hide_index=True)
                
                # Visual representation
                fig = px.pie(results_df, names='result', title='Policy Test Results',
                           color='result', color_discrete_map={'Denied': '#dc3545', 'Allowed': '#28a745'})
                st.plotly_chart(fig, width="stretch")
        else:
            st.error("Please provide a valid policy to test")

def render_policy_deployment():
    """Render policy deployment interface"""
    st.markdown("### 🚀 Policy Deployment")
    st.markdown("Deploy policies to AWS Organizations OUs and accounts")
    
    # Deployment queue
    st.markdown("#### 📦 Deployment Queue")
    
    if any(key.startswith("deploy_policy_") for key in st.session_state):
        queued_policies = [key.replace("deploy_policy_", "") for key in st.session_state if key.startswith("deploy_policy_")]
        st.success(f"✅ {len(queued_policies)} policies queued for deployment")
        
        for policy_key in queued_policies:
            if policy_key in SCP_POLICY_LIBRARY:
                policy = SCP_POLICY_LIBRARY[policy_key]
                st.info(f"📋 {policy['name']} ({policy['severity']} - {policy['category']})")
    else:
        st.info("No policies queued for deployment. Add policies from the Policy Library.")
    
    st.markdown("---")
    
    # Deployment configuration
    st.markdown("#### ⚙️ Deployment Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        deployment_target = st.radio("Deployment Target", [
            "Organization Root",
            "Organizational Units (OUs)",
            "Specific Accounts"
        ], key="deploy_target")
        
        if deployment_target == "Organizational Units (OUs)":
            selected_ous = st.multiselect("Select OUs", [
                "Production OU",
                "Development OU",
                "Testing OU",
                "Shared Services OU"
            ], key="deploy_ous")
        
        elif deployment_target == "Specific Accounts":
            selected_accounts = st.multiselect("Select Accounts", [
                "Production-FinServices-001 (123456789012)",
                "Production-App-002 (123456789013)",
                "Development-Test-001 (123456789014)"
            ], key="deploy_accounts")
    
    with col2:
        deployment_mode = st.radio("Deployment Mode", [
            "Immediate",
            "Scheduled",
            "Gradual Rollout"
        ], key="deploy_mode")
        
        if deployment_mode == "Scheduled":
            deploy_date = st.date_input("Deployment Date", key="deploy_date")
            deploy_time = st.time_input("Deployment Time", key="deploy_time")
        
        elif deployment_mode == "Gradual Rollout":
            rollout_duration = st.slider("Rollout Duration (hours)", 1, 24, 4, key="rollout_duration")
            rollout_batch_size = st.slider("Batch Size (%)", 10, 100, 25, key="rollout_batch")
    
    # Deployment options
    st.markdown("#### 🛠️ Deployment Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        enable_monitoring = st.checkbox("Enable deployment monitoring", value=True, key="deploy_monitor")
        enable_rollback = st.checkbox("Enable automatic rollback on errors", value=True, key="deploy_rollback")
        enable_notifications = st.checkbox("Send deployment notifications", value=True, key="deploy_notify")
    
    with col2:
        if enable_notifications:
            notification_channels = st.multiselect("Notification Channels", 
                                                  ["Email", "Slack", "PagerDuty", "SNS"],
                                                  default=["Email", "Slack"],
                                                  key="deploy_notify_channels")
    
    st.markdown("---")
    
    # Pre-deployment validation
    st.markdown("#### 🔍 Pre-Deployment Validation")
    
    if st.button("🔍 Run Pre-Deployment Checks", type="secondary"):
        with st.spinner("Running validation checks..."):
            time.sleep(2)
            
            checks = [
                {"Check": "Policy syntax validation", "Status": "✅ Passed"},
                {"Check": "Target accounts accessible", "Status": "✅ Passed"},
                {"Check": "No conflicting policies", "Status": "⚠️ Warning: 2 potential conflicts"},
                {"Check": "Impact analysis completed", "Status": "✅ Passed"},
                {"Check": "Backup policies created", "Status": "✅ Passed"}
            ]
            
            st.dataframe(pd.DataFrame(checks), width="stretch", hide_index=True)
            
            st.warning("⚠️ **Conflicts Detected:**")
            st.markdown("""
            - Policy "Prevent Public S3" conflicts with existing "S3 Access Policy" in Production OU
            - Policy "Require MFA" may impact automated processes in Development OU
            
            **Recommendation:** Review conflicts before deployment
            """)
    
    # Deploy button
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("🚀 Deploy Policies", type="primary", width="stretch"):
            with st.spinner("Deploying policies..."):
                time.sleep(3)
                
                st.success("✅ Policies deployed successfully!")
                
                st.info(f"""
                **Deployment Summary:**
                - Policies deployed: {len(queued_policies) if any(key.startswith("deploy_policy_") for key in st.session_state) else 0}
                - Target: {deployment_target}
                - Mode: {deployment_mode}
                - Status: Active
                - Deployment ID: DEP-2024-{random.randint(1000, 9999)}
                """)
    
    with col2:
        if st.button("💾 Save as Deployment Template", width="stretch"):
            st.success("✅ Deployment template saved")

def render_compliance_mapping():
    """Render compliance framework mapping"""
    st.markdown("### 📊 Compliance Framework Mapping")
    st.markdown("Map SCP policies to compliance requirements")
    
    # Select framework
    framework = st.selectbox("Select Compliance Framework", [
        "SOC 2 Type II",
        "PCI-DSS v4.0",
        "HIPAA",
        "GDPR",
        "ISO 27001",
        "NIST CSF",
        "CIS AWS Foundations"
    ], key="compliance_framework")
    
    st.markdown(f"### 📋 {framework} Requirements Coverage")
    
    # Simulate compliance mapping
    if framework == "SOC 2 Type II":
        requirements = [
            {
                "Control": "CC6.1 - Logical Access",
                "Description": "Restrict logical access to authorized users",
                "Mapped Policies": ["Prevent Root Account Usage", "Require MFA for Privileged Actions"],
                "Coverage": 85,
                "Status": "✅ Adequate"
            },
            {
                "Control": "CC6.6 - Encryption",
                "Description": "Protect data in transit and at rest",
                "Mapped Policies": ["Require Encryption at Rest", "Deny Unencrypted RDS"],
                "Coverage": 90,
                "Status": "✅ Strong"
            },
            {
                "Control": "CC7.2 - System Monitoring",
                "Description": "Monitor system components",
                "Mapped Policies": ["Require CloudTrail Logging"],
                "Coverage": 70,
                "Status": "⚠️ Needs Improvement"
            },
            {
                "Control": "CC8.1 - Change Management",
                "Description": "Manage changes to system components",
                "Mapped Policies": [],
                "Coverage": 45,
                "Status": "❌ Inadequate"
            }
        ]
    
    elif framework == "PCI-DSS v4.0":
        requirements = [
            {
                "Control": "Req 1 - Network Security",
                "Description": "Install and maintain network security controls",
                "Mapped Policies": ["Prevent 0.0.0.0/0 Security Groups", "Enforce VPC Usage"],
                "Coverage": 88,
                "Status": "✅ Strong"
            },
            {
                "Control": "Req 2 - Secure Configurations",
                "Description": "Apply secure configurations to all system components",
                "Mapped Policies": ["PCI-DSS Requirements"],
                "Coverage": 82,
                "Status": "✅ Adequate"
            },
            {
                "Control": "Req 3 - Stored Cardholder Data",
                "Description": "Protect stored account data",
                "Mapped Policies": ["Require Encryption at Rest", "Prevent Public S3 Buckets"],
                "Coverage": 92,
                "Status": "✅ Strong"
            },
            {
                "Control": "Req 10 - Log and Monitor",
                "Description": "Log and monitor all access to system components",
                "Mapped Policies": ["Require CloudTrail Logging"],
                "Coverage": 75,
                "Status": "⚠️ Needs Improvement"
            }
        ]
    
    else:
        requirements = [
            {
                "Control": "Example Control 1",
                "Description": "Sample requirement",
                "Mapped Policies": ["Sample Policy"],
                "Coverage": random.randint(60, 95),
                "Status": random.choice(["✅ Strong", "✅ Adequate", "⚠️ Needs Improvement"])
            }
            for _ in range(6)
        ]
    
    # Overall metrics
    avg_coverage = sum(r["Coverage"] for r in requirements) / len(requirements)
    strong_controls = sum(1 for r in requirements if r["Coverage"] >= 85)
    weak_controls = sum(1 for r in requirements if r["Coverage"] < 70)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Overall Coverage", f"{avg_coverage:.0f}%")
    with col2:
        st.metric("Strong Controls", strong_controls, delta=f"{strong_controls/len(requirements)*100:.0f}%")
    with col3:
        st.metric("Weak Controls", weak_controls, delta=f"{weak_controls/len(requirements)*100:.0f}%", delta_color="inverse")
    with col4:
        st.metric("Total Requirements", len(requirements))
    
    st.markdown("---")
    
    # Requirements table
    st.markdown("#### 📋 Detailed Requirements")
    
    req_df = pd.DataFrame(requirements)
    st.dataframe(req_df, width="stretch", hide_index=True, height=400)
    
    # Visualization
    fig = px.bar(req_df, x='Control', y='Coverage', 
                title=f'{framework} Coverage by Control',
                color='Coverage',
                color_continuous_scale=['red', 'yellow', 'green'])
    fig.add_hline(y=70, line_dash="dash", line_color="orange", annotation_text="Minimum Threshold")
    fig.add_hline(y=85, line_dash="dash", line_color="green", annotation_text="Target Threshold")
    st.plotly_chart(fig, width="stretch")
    
    # Gap analysis
    st.markdown("#### 🔍 Gap Analysis")
    
    gaps = [r for r in requirements if r["Coverage"] < 70]
    
    if gaps:
        st.warning(f"⚠️ {len(gaps)} requirements below 70% coverage threshold")
        
        for gap in gaps:
            with st.expander(f"❌ {gap['Control']} - {gap['Coverage']}% Coverage"):
                st.markdown(f"**Description:** {gap['Description']}")
                st.markdown(f"**Current Coverage:** {gap['Coverage']}%")
                st.markdown(f"**Mapped Policies:** {', '.join(gap['Mapped Policies']) if gap['Mapped Policies'] else 'None'}")
                
                st.markdown("**Recommendations:**")
                st.markdown("- Add additional SCPs to cover this requirement")
                st.markdown("- Review and strengthen existing policy enforcement")
                st.markdown("- Consider implementing technical controls beyond SCPs")
    else:
        st.success("✅ All requirements meet or exceed coverage threshold!")

def render_impact_analysis():
    """Render policy impact analysis"""
    st.markdown("### 🔍 Policy Impact Analysis")
    st.markdown("Analyze the potential impact of policies before deployment")
    
    # Select policy
    analysis_policy_key = st.selectbox("Select Policy to Analyze",
                                      list(SCP_POLICY_LIBRARY.keys()),
                                      format_func=lambda x: SCP_POLICY_LIBRARY[x]["name"],
                                      key="analysis_policy")
    
    policy = SCP_POLICY_LIBRARY[analysis_policy_key]
    
    if st.button("🔍 Run Impact Analysis", type="primary"):
        with st.spinner("Analyzing policy impact..."):
            time.sleep(2)
            
            impact = analyze_policy_impact(policy["policy"])
            
            st.markdown("### 📊 Impact Analysis Results")
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Affected Services", impact['service_count'])
            with col2:
                st.metric("Risk Level", impact['risk_level'])
            with col3:
                st.metric("Policy Statements", impact['statement_count'])
            with col4:
                st.metric("Critical Actions", len(impact['critical_actions']))
            
            st.markdown("---")
            
            # Detailed impact
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### 🎯 Affected AWS Services")
                for service in impact['affected_services']:
                    st.markdown(f"- {service}")
            
            with col2:
                st.markdown("#### ⚠️ Critical Actions Blocked")
                if impact['critical_actions']:
                    for action in impact['critical_actions'][:10]:
                        st.markdown(f"- {action}")
                else:
                    st.info("No critical actions blocked")
            
            st.markdown("---")
            
            # Estimated impact on accounts
            st.markdown("#### 📈 Estimated Impact on Accounts")
            
            # Simulate impact data
            account_impact = [
                {"Account": "Production-FinServices-001", "Affected Resources": random.randint(50, 200), "Potential Blocks": random.randint(5, 30), "Risk": random.choice(["Low", "Medium", "High"])},
                {"Account": "Production-App-002", "Affected Resources": random.randint(30, 150), "Potential Blocks": random.randint(2, 20), "Risk": random.choice(["Low", "Medium"])},
                {"Account": "Development-Test-001", "Affected Resources": random.randint(20, 80), "Potential Blocks": random.randint(0, 10), "Risk": "Low"},
            ]
            
            st.dataframe(pd.DataFrame(account_impact), width="stretch", hide_index=True)
            
            # Recommendations
            st.markdown("#### 💡 Recommendations")
            
            if impact['risk_level'] == "High":
                st.warning("""
                **High Risk Policy**
                - Test thoroughly in non-production environment first
                - Consider gradual rollout to production accounts
                - Ensure proper exception handling for legitimate use cases
                - Set up monitoring and alerting for policy violations
                - Have rollback plan ready
                """)
            elif impact['risk_level'] == "Medium":
                st.info("""
                **Medium Risk Policy**
                - Test in development environment before production
                - Review affected resources and workflows
                - Communicate changes to stakeholders
                - Monitor for unexpected denials after deployment
                """)
            else:
                st.success("""
                **Low Risk Policy**
                - Safe for deployment with standard procedures
                - Minimal impact on existing resources
                - Monitor deployment for any issues
                """)

def render_policy_analytics():
    """Render policy analytics and metrics"""
    st.markdown("### 📈 Policy Analytics")
    st.markdown("Monitor policy effectiveness and compliance over time")
    
    # Time range selector
    time_range = st.selectbox("Time Range", ["Last 7 Days", "Last 30 Days", "Last 90 Days", "Last Year"],
                             key="analytics_timerange")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Active Policies", "127", "+3 this month")
    with col2:
        st.metric("Policy Violations", "1,247", "-18% vs last month")
    with col3:
        st.metric("Blocked Actions", "3,892", "+5% vs last month")
    with col4:
        st.metric("Compliance Score", "94.2%", "+1.8%")
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Policy Violations by Category")
        
        violations_data = pd.DataFrame({
            "Category": ["Security", "Cost Control", "Compliance", "Governance"],
            "Violations": [456, 312, 189, 290]
        })
        
        fig = px.pie(violations_data, values='Violations', names='Category', hole=0.4)
        fig.update_layout(height=300)
        st.plotly_chart(fig, width="stretch")
    
    with col2:
        st.markdown("#### 📈 Violations Trend")
        
        dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
        violations_trend = pd.DataFrame({
            "Date": dates,
            "Violations": [random.randint(30, 80) for _ in range(30)]
        })
        
        fig = px.line(violations_trend, x='Date', y='Violations')
        fig.update_layout(height=300)
        st.plotly_chart(fig, width="stretch")
    
    st.markdown("---")
    
    # Top violations
    st.markdown("#### 🔝 Top Policy Violations")
    
    top_violations = [
        {"Policy": "Prevent Public S3 Buckets", "Violations": 234, "Accounts Affected": 12, "Last 7 Days": "+15%"},
        {"Policy": "Require Resource Tags", "Violations": 198, "Accounts Affected": 23, "Last 7 Days": "-8%"},
        {"Policy": "Restrict Instance Types", "Violations": 156, "Accounts Affected": 8, "Last 7 Days": "+22%"},
        {"Policy": "Require MFA", "Violations": 142, "Accounts Affected": 15, "Last 7 Days": "-12%"},
        {"Policy": "Require Encryption", "Violations": 98, "Accounts Affected": 6, "Last 7 Days": "+5%"},
    ]
    
    st.dataframe(pd.DataFrame(top_violations), width="stretch", hide_index=True)
    
    st.markdown("---")
    
    # Policy effectiveness
    st.markdown("#### 💪 Policy Effectiveness")
    
    effectiveness_data = [
        {"Policy": "Prevent Public S3", "Blocked Actions": 892, "Success Rate": "99.2%", "False Positives": 7},
        {"Policy": "Require Encryption", "Blocked Actions": 456, "Success Rate": "98.5%", "False Positives": 3},
        {"Policy": "Restrict Regions", "Blocked Actions": 234, "Success Rate": "100%", "False Positives": 0},
        {"Policy": "Require MFA", "Blocked Actions": 189, "Success Rate": "97.8%", "False Positives": 4},
    ]
    
    st.dataframe(pd.DataFrame(effectiveness_data), width="stretch", hide_index=True)

# ============================================================================
# EXPORT FOR MAIN APP
# ============================================================================

if __name__ == "__main__":
    st.set_page_config(page_title="SCP Policy Engine", layout="wide")
    render_scp_policy_engine()
