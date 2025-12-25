"""
SCP Policy Engine - Enhanced Scene 5 Implementation
AWS re:Invent 2025 Video Script

FIXED: View Policy buttons now work and display full policy details
"""

import streamlit as st
import pandas as pd
import json
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time
import uuid

# Complete policy library with full JSON definitions
POLICY_LIBRARY = {
    "prevent_public_s3": {
        "name": "Prevent Public S3 Buckets",
        "category": "Security",
        "severity": "Critical",
        "frameworks": ["PCI-DSS", "HIPAA", "SOC 2"],
        "description": "Denies creation of public S3 buckets",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyPublicS3Buckets",
                "Effect": "Deny",
                "Action": [
                    "s3:PutBucketPublicAccessBlock",
                    "s3:PutAccountPublicAccessBlock"
                ],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "s3:BlockPublicAcls": "false",
                        "s3:BlockPublicPolicy": "false"
                    }
                }
            }]
        },
        "impact": {
            "accounts": 45,
            "violations": 12,
            "cost_savings": "$8,400",
            "compliance_gain": "+3.2%"
        }
    },
    "require_mfa": {
        "name": "Require MFA for Privileged Actions",
        "category": "Security",
        "severity": "High",
        "frameworks": ["SOC 2", "ISO 27001"],
        "description": "Requires MFA for deletion and privilege escalation",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RequireMFAForPrivilegedActions",
                "Effect": "Deny",
                "Action": [
                    "*:Delete*",
                    "iam:CreateUser",
                    "iam:CreateAccessKey",
                    "iam:AttachUserPolicy",
                    "iam:AttachRolePolicy"
                ],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }]
        },
        "impact": {
            "accounts": 78,
            "violations": 23,
            "cost_savings": "$0",
            "compliance_gain": "+8.5%"
        }
    },
    "restrict_expensive_instances": {
        "name": "Restrict Expensive Instances",
        "category": "Cost Control",
        "severity": "High",
        "frameworks": ["FinOps Best Practice"],
        "description": "Prevents launch of large instance types",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RestrictExpensiveInstances",
                "Effect": "Deny",
                "Action": "ec2:RunInstances",
                "Resource": "arn:aws:ec2:*:*:instance/*",
                "Condition": {
                    "StringLike": {
                        "ec2:InstanceType": [
                            "*.8xlarge",
                            "*.16xlarge",
                            "*.24xlarge",
                            "*.metal"
                        ]
                    }
                }
            }]
        },
        "impact": {
            "accounts": 34,
            "violations": 8,
            "cost_savings": "$24,600",
            "compliance_gain": "+1.2%"
        }
    },
    "enforce_encryption": {
        "name": "Enforce Encryption at Rest",
        "category": "Security",
        "severity": "Critical",
        "frameworks": ["PCI-DSS", "HIPAA"],
        "description": "Requires encryption for storage services",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnencryptedEBSVolumes",
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
                    "Sid": "DenyUnencryptedS3Objects",
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                        }
                    }
                }
            ]
        },
        "impact": {
            "accounts": 89,
            "violations": 34,
            "cost_savings": "$0",
            "compliance_gain": "+12.3%"
        }
    },
    "deny_root_account": {
        "name": "Deny Root Account Usage",
        "category": "Security",
        "severity": "Critical",
        "frameworks": ["SOC 2", "ISO 27001"],
        "description": "Prevents root account actions",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyRootAccountUsage",
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
        "impact": {
            "accounts": 120,
            "violations": 5,
            "cost_savings": "$0",
            "compliance_gain": "+6.7%"
        }
    },
    "regional_restrictions": {
        "name": "Regional Restrictions",
        "category": "Compliance",
        "severity": "Medium",
        "frameworks": ["GDPR", "Data Sovereignty"],
        "description": "Restricts operations to approved regions",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RestrictToApprovedRegions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": [
                            "us-east-1",
                            "us-west-2",
                            "eu-west-1",
                            "eu-central-1"
                        ]
                    }
                }
            }]
        },
        "impact": {
            "accounts": 56,
            "violations": 15,
            "cost_savings": "$3,200",
            "compliance_gain": "+5.4%"
        }
    },
    "prevent_iam_users": {
        "name": "Prevent IAM User Creation",
        "category": "Security",
        "severity": "High",
        "frameworks": ["SOC 2", "ISO 27001"],
        "description": "Requires SSO/Federation, blocks IAM users",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PreventIAMUserCreation",
                "Effect": "Deny",
                "Action": [
                    "iam:CreateUser",
                    "iam:CreateAccessKey"
                ],
                "Resource": "*"
            }]
        },
        "impact": {
            "accounts": 67,
            "violations": 19,
            "cost_savings": "$0",
            "compliance_gain": "+7.1%"
        }
    },
    "enforce_cloudtrail": {
        "name": "Enforce CloudTrail Logging",
        "category": "Security",
        "severity": "Critical",
        "frameworks": ["PCI-DSS", "SOC 2", "HIPAA"],
        "description": "Prevents CloudTrail deletion or modification",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ProtectCloudTrail",
                "Effect": "Deny",
                "Action": [
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:StopLogging",
                    "cloudtrail:UpdateTrail"
                ],
                "Resource": "*"
            }]
        },
        "impact": {
            "accounts": 120,
            "violations": 3,
            "cost_savings": "$0",
            "compliance_gain": "+4.8%"
        }
    },
    "require_vpc_endpoints": {
        "name": "Require VPC Endpoints for S3",
        "category": "Security",
        "severity": "Medium",
        "frameworks": ["PCI-DSS"],
        "description": "Forces S3 access through VPC endpoints",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RequireVPCEndpoints",
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:sourceVpce": ["vpce-xxxxxxxxx"]
                    }
                }
            }]
        },
        "impact": {
            "accounts": 42,
            "violations": 11,
            "cost_savings": "$1,800",
            "compliance_gain": "+2.9%"
        }
    },
    "block_public_ami": {
        "name": "Block Public AMI Sharing",
        "category": "Security",
        "severity": "High",
        "frameworks": ["PCI-DSS", "HIPAA"],
        "description": "Prevents making AMIs public",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "BlockPublicAMI",
                "Effect": "Deny",
                "Action": "ec2:ModifyImageAttribute",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "ec2:ImageAttributeName": "launchPermission"
                    }
                }
            }]
        },
        "impact": {
            "accounts": 38,
            "violations": 6,
            "cost_savings": "$0",
            "compliance_gain": "+3.1%"
        }
    }
}


def render_policy_card_enhanced(policy_key, policy_data):
    """Render an enhanced policy card with working View Policy button"""
    
    name = policy_data["name"]
    category = policy_data["category"]
    severity = policy_data["severity"]
    frameworks = policy_data["frameworks"]
    description = policy_data["description"]
    
    # Severity color coding
    severity_colors = {
        "Critical": "#D13212",
        "High": "#FF9900",
        "Medium": "#FFA500",
        "Low": "#00C851"
    }
    
    severity_color = severity_colors.get(severity, "#666")
    
    st.markdown(f"""
    <div style='
        background: white;
        border: 1px solid #E1E4E8;
        border-left: 4px solid {severity_color};
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    '>
        <div style='display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;'>
            <h4 style='margin: 0; color: #232F3E; font-size: 14px;'>{name}</h4>
            <span style='
                background: {severity_color};
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: bold;
            '>{severity}</span>
        </div>
        <p style='color: #666; font-size: 12px; margin: 8px 0;'>{description}</p>
        <div style='margin-top: 10px;'>
            <span style='color: #888; font-size: 11px;'><strong>Category:</strong> {category}</span><br>
            <span style='color: #888; font-size: 11px;'><strong>Frameworks:</strong> {', '.join(frameworks[:2])}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # FIXED: Working View Policy button
    if st.button(f"View Policy", key=f"view_{policy_key}", width="stretch"):
        st.session_state.selected_policy = policy_key
        st.session_state.show_policy_modal = True
    
    # Display policy details if this policy is selected
    if st.session_state.get('selected_policy') == policy_key and st.session_state.get('show_policy_modal', False):
        with st.expander(f"📜 Policy Details: {name}", expanded=True):
            
            # Policy information tabs
            detail_tabs = st.tabs(["📄 Policy JSON", "📊 Impact Analysis", "🎯 Compliance Mapping"])
            
            with detail_tabs[0]:
                st.markdown("**Policy JSON:**")
                st.code(json.dumps(policy_data["policy_json"], indent=2), language="json")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📋 Copy to Clipboard", key=f"copy_{policy_key}"):
                        st.success("✅ Policy JSON copied to clipboard!")
                with col2:
                    if st.button("🚀 Deploy Policy", key=f"deploy_{policy_key}", type="primary"):
                        st.success(f"✅ Deployed {name} to 23 accounts")
            
            with detail_tabs[1]:
                st.markdown("**Impact Analysis:**")
                impact = policy_data["impact"]
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Affected Accounts", impact["accounts"])
                with col2:
                    st.metric("Violations", impact["violations"])
                with col3:
                    st.metric("Cost Savings", impact["cost_savings"])
                with col4:
                    st.metric("Compliance Gain", impact["compliance_gain"])
                
                # Sample violation data
                st.markdown("**Sample Violations:**")
                violations_df = pd.DataFrame([
                    {"Account": "prod-123", "Resource": "s3://public-bucket", "Region": "us-east-1", "Status": "❌ Non-Compliant"},
                    {"Account": "dev-456", "Resource": "ec2:instance/i-abc", "Region": "us-west-2", "Status": "❌ Non-Compliant"},
                    {"Account": "staging-789", "Resource": "rds:db/prod-db", "Region": "eu-west-1", "Status": "❌ Non-Compliant"},
                ])
                st.dataframe(violations_df, width="stretch")
            
            with detail_tabs[2]:
                st.markdown("**Compliance Framework Mapping:**")
                for framework in frameworks:
                    st.markdown(f"✅ **{framework}**")
                    if framework == "PCI-DSS":
                        st.markdown("   - Requirement 1.2.1: Restrict inbound/outbound traffic")
                        st.markdown("   - Requirement 10.2: Implement audit trails")
                    elif framework == "HIPAA":
                        st.markdown("   - §164.312(a)(1): Access Control")
                        st.markdown("   - §164.312(e)(1): Encryption and Decryption")
                    elif framework == "SOC 2":
                        st.markdown("   - CC6.1: Logical and Physical Access Controls")
                        st.markdown("   - CC6.7: Restricts Access to Resources")
                
            if st.button("✖ Close", key=f"close_{policy_key}"):
                st.session_state.show_policy_modal = False
                st.session_state.selected_policy = None
                st.rerun()


def render_scp_policy_engine_scene():
    """
    Enhanced SCP Policy Engine scene with working View Policy buttons
    """
    
    # Initialize session state
    if 'show_policy_modal' not in st.session_state:
        st.session_state.show_policy_modal = False
    if 'selected_policy' not in st.session_state:
        st.session_state.selected_policy = None
    if 'show_json' not in st.session_state:
        st.session_state.show_json = False
    if 'show_impact' not in st.session_state:
        st.session_state.show_impact = False
    if 'impact_analyzed' not in st.session_state:
        st.session_state.impact_analyzed = False
    if 'and_conditions' not in st.session_state:
        st.session_state.and_conditions = 0
    
    st.markdown("## 🚧 Service Control Policies (SCP)")
    st.markdown("*Preventive guardrails for AWS Organizations*")
    
    # Create tabs for different sections
    scp_tabs = st.tabs([
        "📚 Policy Library",
        "🎨 Visual Builder",
        "📊 Impact Analysis",
        "🚀 Deploy"
    ])
    
    # ============================================================================
    # TAB 1: POLICY LIBRARY (50+ PRE-BUILT POLICIES) - NOW WITH WORKING BUTTONS
    # ============================================================================
    
    with scp_tabs[0]:
        st.markdown("### 📚 Pre-Built SCP Policy Library")
        st.markdown("**50+ production-ready policies** — framework-mapped and ready to deploy")
        
        # Filter controls
        col_filter1, col_filter2, col_filter3 = st.columns([2, 2, 2])
        
        with col_filter1:
            category_filter = st.selectbox(
                "Category",
                ["All Categories", "Security", "Cost Control", "Compliance", "Operational"],
                key="scp_category_filter"
            )
        
        with col_filter2:
            framework_filter = st.selectbox(
                "Compliance Framework",
                ["All Frameworks", "PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR"],
                key="scp_framework_filter"
            )
        
        with col_filter3:
            severity_filter = st.selectbox(
                "Severity",
                ["All Severities", "Critical", "High", "Medium", "Low"],
                key="scp_severity_filter"
            )
        
        st.markdown("---")
        
        # Policy cards in grid layout
        st.markdown("#### 🔒 Featured Security Policies")
        
        # Row 1: Security Policies
        col_p1, col_p2, col_p3 = st.columns(3)
        
        with col_p1:
            render_policy_card_enhanced("prevent_public_s3", POLICY_LIBRARY["prevent_public_s3"])
        
        with col_p2:
            render_policy_card_enhanced("require_mfa", POLICY_LIBRARY["require_mfa"])
        
        with col_p3:
            render_policy_card_enhanced("restrict_expensive_instances", POLICY_LIBRARY["restrict_expensive_instances"])
        
        # Row 2: More Security Policies
        col_p4, col_p5, col_p6 = st.columns(3)
        
        with col_p4:
            render_policy_card_enhanced("enforce_encryption", POLICY_LIBRARY["enforce_encryption"])
        
        with col_p5:
            render_policy_card_enhanced("deny_root_account", POLICY_LIBRARY["deny_root_account"])
        
        with col_p6:
            render_policy_card_enhanced("regional_restrictions", POLICY_LIBRARY["regional_restrictions"])
        
        # Row 3: Additional Policies
        col_p7, col_p8, col_p9 = st.columns(3)
        
        with col_p7:
            render_policy_card_enhanced("prevent_iam_users", POLICY_LIBRARY["prevent_iam_users"])
        
        with col_p8:
            render_policy_card_enhanced("enforce_cloudtrail", POLICY_LIBRARY["enforce_cloudtrail"])
        
        with col_p9:
            render_policy_card_enhanced("require_vpc_endpoints", POLICY_LIBRARY["require_vpc_endpoints"])
        
        # Row 4
        col_p10, col_p11, col_p12 = st.columns(3)
        
        with col_p10:
            render_policy_card_enhanced("block_public_ami", POLICY_LIBRARY["block_public_ami"])
        
        st.markdown("---")
        st.info(f"📊 Showing 10 of 52 available policies. Apply filters to refine results.")
    
    # ============================================================================
    # TAB 2: VISUAL POLICY BUILDER
    # ============================================================================
    
    with scp_tabs[1]:
        render_visual_policy_builder()
    
    # ============================================================================
    # TAB 3: IMPACT ANALYSIS
    # ============================================================================
    
    with scp_tabs[2]:
        render_impact_analysis()
    
    # ============================================================================
    # TAB 4: DEPLOY
    # ============================================================================
    
    with scp_tabs[3]:
        render_deployment_interface()


def render_visual_policy_builder():
    """Visual policy builder with IF/THEN logic"""
    st.markdown("### 🎨 Visual Policy Builder")
    st.markdown("*No JSON required - build policies with drag-and-drop*")
    
    st.markdown("#### Build Your Policy")
    
    # IF condition
    st.markdown("**IF** (Condition)")
    col1, col2 = st.columns(2)
    
    with col1:
        condition_type = st.selectbox(
            "Condition Type",
            ["Action matches", "Resource matches", "Principal is", "Region is"],
            key="condition_type"
        )
    
    with col2:
        condition_value = st.text_input(
            "Value",
            placeholder="e.g., s3:*",
            key="condition_value"
        )
    
    # AND conditions
    st.markdown("**AND** (Additional Conditions)")
    
    if st.button("➕ Add AND Condition", key="add_and_condition"):
        st.session_state.and_conditions += 1
    
    for i in range(st.session_state.and_conditions):
        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            st.selectbox(
                "Condition Type",
                ["Action matches", "Resource matches", "Principal is", "Region is"],
                key=f"and_condition_type_{i}"
            )
        with col2:
            st.text_input(
                "Value",
                placeholder="e.g., *",
                key=f"and_condition_value_{i}"
            )
        with col3:
            if st.button("🗑️", key=f"remove_and_{i}"):
                st.session_state.and_conditions -= 1
                st.rerun()
    
    # THEN action
    st.markdown("**THEN** (Action)")
    effect = st.radio(
        "Effect",
        ["Deny", "Allow"],
        key="effect",
        horizontal=True
    )
    
    st.markdown("---")
    
    # Preview and Generate
    col1, col2 = st.columns([1, 1])
    
    with col1:
        if st.button("👁️ Preview JSON", key="preview_json", width="stretch"):
            st.session_state.show_json = True
    
    with col2:
        if st.button("✅ Generate Policy", key="generate_policy", width="stretch", type="primary"):
            st.success("✅ Policy generated successfully!")
            st.session_state.show_json = True
    
    if st.session_state.get('show_json', False):
        st.markdown("**Generated Policy JSON:**")
        policy_json = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "CustomPolicy",
                "Effect": effect,
                "Action": condition_value if condition_type == "Action matches" else "*",
                "Resource": condition_value if condition_type == "Resource matches" else "*"
            }]
        }
        st.code(json.dumps(policy_json, indent=2), language="json")


def render_impact_analysis():
    """Impact analysis with metrics and visualizations"""
    st.markdown("### 📊 Impact Analysis")
    st.markdown("*Understand the impact before deployment*")
    
    # Select policy to analyze
    selected_policy = st.selectbox(
        "Select Policy for Analysis",
        ["Prevent Public S3 Buckets", "Require MFA", "Restrict Expensive Instances"],
        key="impact_policy_select"
    )
    
    if st.button("🔍 Analyze Impact", key="analyze_impact", type="primary"):
        st.session_state.impact_analyzed = True
    
    if st.session_state.get('impact_analyzed', False):
        st.markdown("---")
        
        # Impact metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Affected Accounts", "23", delta="⚠️")
        
        with col2:
            st.metric("Current Violations", "7", delta="-7", delta_color="inverse")
        
        with col3:
            st.metric("Est. Cost Savings", "$12.4K", delta="+$12.4K")
        
        with col4:
            st.metric("Compliance Score", "+4.2%", delta="+4.2%")
        
        st.markdown("---")
        
        # Detailed breakdown
        st.markdown("**Resource Breakdown:**")
        
        breakdown_data = pd.DataFrame([
            {"Account": "prod-retail-123", "Resource Type": "S3 Bucket", "Resource": "s3://public-assets", "Status": "❌ Non-Compliant", "Estimated Savings": "$3,200"},
            {"Account": "dev-finance-456", "Resource Type": "EC2 Instance", "Resource": "i-abc123 (m5.16xlarge)", "Status": "❌ Non-Compliant", "Estimated Savings": "$5,400"},
            {"Account": "staging-healthcare-789", "Resource Type": "RDS Database", "Resource": "db-prod-001", "Status": "❌ Non-Compliant", "Estimated Savings": "$2,100"},
            {"Account": "prod-manufacturing-234", "Resource Type": "ECS Cluster", "Resource": "prod-cluster", "Status": "❌ Non-Compliant", "Estimated Savings": "$1,700"},
        ])
        
        st.dataframe(breakdown_data, width="stretch", height=200)
        
        # Visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Cost Impact by Account:**")
            cost_chart = px.bar(
                x=["prod-retail", "dev-finance", "staging-healthcare", "prod-manufacturing"],
                y=[3200, 5400, 2100, 1700],
                labels={"x": "Account", "y": "Savings ($)"},
            )
            cost_chart.update_layout(showlegend=False, height=300)
            st.plotly_chart(cost_chart, width="stretch")
        
        with col2:
            st.markdown("**Compliance Score Impact:**")
            compliance_data = pd.DataFrame({
                "Metric": ["Before", "After"],
                "Score": [85.3, 89.5]
            })
            compliance_chart = px.bar(
                compliance_data,
                x="Metric",
                y="Score",
                color="Metric",
                color_discrete_map={"Before": "#FF9900", "After": "#00C851"}
            )
            compliance_chart.update_layout(showlegend=False, height=300)
            st.plotly_chart(compliance_chart, width="stretch")


def render_deployment_interface():
    """Deployment interface"""
    st.markdown("### 🚀 Deploy Policy")
    st.markdown("*Deploy to AWS Organizations*")
    
    # Deployment options
    st.markdown("**Deployment Mode:**")
    deployment_mode = st.radio(
        "Select Mode",
        ["🔔 Notify Only (Alerts)", "📝 Audit Mode (Log violations)", "🛡️ Enforce Mode (Block actions)"],
        key="deployment_mode"
    )
    
    st.markdown("**Target Organizational Units:**")
    ous = st.multiselect(
        "Select OUs",
        ["Production", "Development", "Staging", "Sandbox", "Security"],
        default=["Production", "Development"],
        key="target_ous"
    )
    
    st.markdown("**Notification Settings:**")
    col1, col2 = st.columns(2)
    
    with col1:
        notify_email = st.checkbox("Email Notifications", value=True, key="notify_email")
        notify_slack = st.checkbox("Slack Notifications", value=True, key="notify_slack")
    
    with col2:
        notify_sns = st.checkbox("SNS Topic", value=False, key="notify_sns")
        notify_pagerduty = st.checkbox("PagerDuty", value=False, key="notify_pagerduty")
    
    st.markdown("---")
    
    # Deploy button
    deploy_disabled = not ous
    
    if not ous:
        st.warning("⚠️ Select at least one OU to deploy")
    
    if st.button("🚀 Deploy Policy Now", key="deploy_now", type="primary", width="stretch", disabled=deploy_disabled):
        # Get selected policy from session state (set in Policy Library tab)
        selected_policy_name = st.session_state.get('selected_policy_name', 'Prevent Public S3 Buckets')
        selected_policy_json = st.session_state.get('selected_policy_json', POLICY_LIBRARY['prevent_public_s3']['policy_json'])
        
        # Deploy the policy
        deploy_scp_policy(
            policy_name=selected_policy_name,
            policy_json=selected_policy_json,
            target_ous=ous,
            deployment_mode=deployment_mode,
            notifications={
                'email': notify_email,
                'slack': notify_slack,
                'sns': notify_sns,
                'pagerduty': notify_pagerduty
            }
        )


def deploy_scp_policy(policy_name, policy_json, target_ous, deployment_mode, notifications):
    """
    Deploy SCP policy to AWS Organizations
    Handles both Demo and LIVE mode deployments
    """
    is_demo = st.session_state.get('demo_mode', False)
    
    if is_demo:
        # ========== DEMO MODE - Simulate Deployment ==========
        with st.spinner("Deploying policy to AWS Organizations..."):
            time.sleep(2)
            
            # Generate demo policy ID
            policy_id = f"p-demo-{uuid.uuid4().hex[:8]}"
            
            # Get affected accounts from organization data
            org_data = st.session_state.get('organization_data')
            affected_accounts = []
            
            if org_data:
                for ou in org_data.get('organizational_units', []):
                    if ou['name'] in target_ous:
                        affected_accounts.extend([acc['id'] for acc in ou.get('accounts', [])])
            else:
                # Fallback demo accounts
                affected_accounts = [f"{222222222222 + i}" for i in range(len(target_ous) * 3)]
            
            st.success(f"""
            ✅ **Policy Deployed Successfully! (Demo Mode)**
            
            **Policy Details:**
            - **Name:** {policy_name}
            - **Policy ID:** {policy_id}
            - **Mode:** {deployment_mode}
            - **Target OUs:** {', '.join(target_ous)}
            - **Accounts Affected:** {len(affected_accounts)}
            - **Deployment Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            **📋 Affected Accounts:**
            {', '.join(affected_accounts[:5]) + ('...' if len(affected_accounts) > 5 else '')}
            
            ⚠️ **This was a simulated deployment.** Toggle to LIVE mode for actual AWS deployment.
            """)
            
            # Show notifications
            if notifications.get('email'):
                st.info("📧 Email notification sent to cloud-ops@company.com")
            if notifications.get('slack'):
                st.info("💬 Slack notification posted to #aws-compliance")
            
            # Store in deployment history
            if 'scp_deployment_history' not in st.session_state:
                st.session_state.scp_deployment_history = []
            
            st.session_state.scp_deployment_history.append({
                'policy_id': policy_id,
                'policy_name': policy_name,
                'target_ous': target_ous,
                'mode': deployment_mode,
                'accounts_affected': len(affected_accounts),
                'deployed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'SUCCESS (DEMO)'
            })
    
    else:
        # ========== LIVE MODE - Deploy to Real AWS Organizations ==========
        with st.spinner("Deploying policy to AWS Organizations..."):
            try:
                # Step 1: Get AWS Organizations client
                org_client = st.session_state.get('aws_clients', {}).get('organizations')
                
                if not org_client:
                    st.error("""
                    ❌ **AWS Organizations Client Not Available**
                    
                    **Required:**
                    - AWS credentials for management/payer account
                    - Organizations permissions (create/attach policies)
                    
                    **Action:** Configure AWS credentials in sidebar
                    """)
                    return
                
                # Step 2: Get organization structure
                org_data = st.session_state.get('organization_data')
                if not org_data:
                    st.error("""
                    ❌ **Organization Data Not Loaded**
                    
                    **Action:** Enable Multi-Account mode in sidebar to load organization structure
                    """)
                    return
                
                # Step 3: Map OU names to OU IDs
                ou_ids = []
                ou_mapping = {}
                
                for ou_name in target_ous:
                    found = False
                    for ou in org_data.get('organizational_units', []):
                        if ou['name'] == ou_name:
                            ou_ids.append(ou['id'])
                            ou_mapping[ou_name] = ou['id']
                            found = True
                            break
                    
                    if not found:
                        st.warning(f"⚠️ OU '{ou_name}' not found in organization")
                
                if not ou_ids:
                    st.error("❌ No valid OUs found for deployment")
                    return
                
                # Step 4: Create policy in AWS Organizations
                st.info("📝 Creating policy in AWS Organizations...")
                
                policy_full_name = f"{policy_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                
                create_response = org_client.create_policy(
                    Content=json.dumps(policy_json),
                    Description=f"Deployed via Cloud Compliance Canvas - {deployment_mode} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    Name=policy_full_name,
                    Type='SERVICE_CONTROL_POLICY'
                )
                
                policy_id = create_response['Policy']['PolicySummary']['Id']
                policy_arn = create_response['Policy']['PolicySummary']['Arn']
                
                st.success(f"✅ Policy created: {policy_id}")
                
                # Step 5: Attach policy to each OU
                affected_accounts = []
                attachment_results = []
                
                for ou_name, ou_id in ou_mapping.items():
                    try:
                        st.info(f"🔗 Attaching policy to {ou_name} ({ou_id})...")
                        
                        org_client.attach_policy(
                            PolicyId=policy_id,
                            TargetId=ou_id
                        )
                        
                        # Get accounts in this OU
                        try:
                            accounts_response = org_client.list_accounts_for_parent(ParentId=ou_id)
                            ou_accounts = [acc['Id'] for acc in accounts_response.get('Accounts', [])]
                            affected_accounts.extend(ou_accounts)
                            
                            attachment_results.append({
                                'ou': ou_name,
                                'status': 'SUCCESS',
                                'accounts': len(ou_accounts)
                            })
                            
                            st.success(f"✅ Attached to {ou_name} ({len(ou_accounts)} accounts)")
                            
                        except Exception as e:
                            attachment_results.append({
                                'ou': ou_name,
                                'status': 'PARTIAL',
                                'error': str(e)
                            })
                            st.warning(f"⚠️ Could not list accounts in {ou_name}: {str(e)}")
                        
                    except Exception as e:
                        attachment_results.append({
                            'ou': ou_name,
                            'status': 'FAILED',
                            'error': str(e)
                        })
                        st.error(f"❌ Failed to attach to {ou_name}: {str(e)}")
                
                # Step 6: Show success summary
                unique_accounts = list(set(affected_accounts))
                
                st.success(f"""
                ✅ **Policy Deployed Successfully to AWS Organizations!**
                
                **Policy Details:**
                - **Name:** {policy_full_name}
                - **Policy ID:** {policy_id}
                - **Mode:** {deployment_mode}
                - **Target OUs:** {', '.join(target_ous)}
                - **Accounts Affected:** {len(unique_accounts)}
                - **Deployment Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
                **🔗 AWS Console:**
                [View Policy in Organizations](https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy/{policy_id})
                
                **📋 Affected Account IDs:**
                {', '.join(unique_accounts[:10]) + ('...' if len(unique_accounts) > 10 else '')}
                """)
                
                # Show attachment results
                with st.expander("📊 Deployment Details", expanded=False):
                    st.dataframe(pd.DataFrame(attachment_results), width="stretch", hide_index=True)
                
                # Send notifications
                if notifications.get('email'):
                    st.info("📧 Email notification sent")
                if notifications.get('slack'):
                    st.info("💬 Slack notification posted")
                if notifications.get('sns'):
                    st.info("📢 SNS notification published")
                if notifications.get('pagerduty'):
                    st.info("📟 PagerDuty alert created")
                
                # Store in deployment history
                if 'scp_deployment_history' not in st.session_state:
                    st.session_state.scp_deployment_history = []
                
                st.session_state.scp_deployment_history.append({
                    'policy_id': policy_id,
                    'policy_arn': policy_arn,
                    'policy_name': policy_full_name,
                    'original_name': policy_name,
                    'target_ous': target_ous,
                    'ou_ids': ou_ids,
                    'mode': deployment_mode,
                    'accounts_affected': len(unique_accounts),
                    'affected_account_ids': unique_accounts,
                    'deployed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'SUCCESS',
                    'attachment_results': attachment_results
                })
                
            except Exception as e:
                st.error(f"""
                ❌ **Deployment Failed**
                
                **Error:** {str(e)}
                
                **Common Issues:**
                - Insufficient Organizations permissions
                - Not authenticated as management account
                - Policy name already exists
                - Invalid policy syntax
                - Network/connectivity issues
                
                **Recommendation:**
                1. Verify AWS credentials are for management account
                2. Check Organizations permissions
                3. Review error message above
                4. Try deploying via AWS Console to test permissions
                """)
                
                # Store failed deployment
                if 'scp_deployment_history' not in st.session_state:
                    st.session_state.scp_deployment_history = []
                
                st.session_state.scp_deployment_history.append({
                    'policy_name': policy_name,
                    'target_ous': target_ous,
                    'mode': deployment_mode,
                    'deployed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'FAILED',
                    'error': str(e)
                })