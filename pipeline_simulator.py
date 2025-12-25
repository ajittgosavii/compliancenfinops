"""
DevSecOps Pipeline Simulator with Demo and Real Mode Support
Simulates the entire CI/CD pipeline with tech guardrails and AI orchestration

Author: Future Minds
Version: 1.0
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import time
import random
from typing import Dict, List, Any, Optional
import plotly.graph_objects as go
import plotly.express as px

# ============================================================================
# PIPELINE STAGES CONFIGURATION
# ============================================================================

PIPELINE_STAGES = [
    {
        "id": 1,
        "name": "PRE-COMMIT",
        "icon": "👨‍💻",
        "color": "#667eea",
        "description": "Developer Workstation",
        "checks": ["KICS Scan", "Pre-commit Hooks", "Code Quality"],
        "duration": 2
    },
    {
        "id": 2,
        "name": "PULL REQUEST / CI",
        "icon": "🐙",
        "color": "#FF9900",
        "description": "GitHub Actions",
        "checks": ["KICS Scan", "OPA Validation", "AI Analysis", "Security Tests"],
        "duration": 5
    },
    {
        "id": 3,
        "name": "BUILD & TEST",
        "icon": "🔨",
        "color": "#4CAF50",
        "description": "Build Pipeline",
        "checks": ["Unit Tests", "Integration Tests", "Container Scan", "Dependency Check"],
        "duration": 8
    },
    {
        "id": 4,
        "name": "DEPLOY",
        "icon": "🚀",
        "color": "#2196F3",
        "description": "Deployment Stage",
        "checks": ["SCP Validation", "Config Compliance", "Pre-deployment Scan"],
        "duration": 3
    },
    {
        "id": 5,
        "name": "RUNTIME MONITORING",
        "icon": "📡",
        "color": "#9C27B0",
        "description": "Production Monitoring",
        "checks": ["GuardDuty", "Security Hub", "CloudTrail", "Config"],
        "duration": 1
    }
]

# ============================================================================
# DEMO DATA GENERATORS
# ============================================================================

def generate_demo_pipeline_run() -> Dict[str, Any]:
    """Generate demo pipeline execution data"""
    vulnerabilities = {
        "CRITICAL": random.randint(0, 3),
        "HIGH": random.randint(2, 8),
        "MEDIUM": random.randint(5, 15),
        "LOW": random.randint(10, 25)
    }
    
    return {
        "run_id": f"RUN-{random.randint(1000, 9999)}",
        "timestamp": datetime.now(),
        "status": random.choice(["SUCCESS", "SUCCESS", "SUCCESS", "BLOCKED", "WARNING"]),
        "duration": random.randint(15, 45),
        "vulnerabilities": vulnerabilities,
        "compliance_score": round(random.uniform(85, 98), 1),
        "auto_remediated": random.randint(5, 20),
        "blocked_issues": random.randint(0, 5)
    }

def generate_demo_findings() -> List[Dict[str, Any]]:
    """Generate demo security findings"""
    finding_templates = [
        {
            "type": "S3 Bucket Public Access",
            "severity": "CRITICAL",
            "resource": "s3://prod-data-bucket",
            "description": "S3 bucket has public read access enabled"
        },
        {
            "type": "Unencrypted EBS Volume",
            "severity": "HIGH",
            "resource": "vol-0abc123def456",
            "description": "EBS volume not encrypted at rest"
        },
        {
            "type": "IAM User Without MFA",
            "severity": "HIGH",
            "resource": "arn:aws:iam::123456:user/admin",
            "description": "IAM user does not have MFA enabled"
        },
        {
            "type": "Security Group Ingress 0.0.0.0/0",
            "severity": "CRITICAL",
            "resource": "sg-0abc123",
            "description": "Security group allows unrestricted inbound access"
        },
        {
            "type": "Lambda Function No VPC",
            "severity": "MEDIUM",
            "resource": "lambda:prod-api-function",
            "description": "Lambda function not configured with VPC"
        },
        {
            "type": "RDS Instance No Encryption",
            "severity": "HIGH",
            "resource": "rds:prod-database",
            "description": "RDS instance storage not encrypted"
        },
        {
            "type": "CloudTrail Logging Disabled",
            "severity": "CRITICAL",
            "resource": "cloudtrail:audit-trail",
            "description": "CloudTrail logging is disabled"
        },
        {
            "type": "Outdated AMI",
            "severity": "MEDIUM",
            "resource": "ami-0abc123",
            "description": "EC2 instance using outdated AMI"
        }
    ]
    
    findings = []
    for _ in range(random.randint(8, 15)):
        template = random.choice(finding_templates)
        findings.append({
            "id": f"FINDING-{random.randint(1000, 9999)}",
            "stage": random.choice([s["name"] for s in PIPELINE_STAGES]),
            "timestamp": datetime.now() - timedelta(minutes=random.randint(1, 120)),
            **template,
            "status": random.choice(["OPEN", "OPEN", "IN_PROGRESS", "REMEDIATED"])
        })
    
    return findings

def generate_tech_guardrails_data() -> Dict[str, Any]:
    """Generate tech guardrails execution data"""
    return {
        "kics": {
            "enabled": True,
            "scans": random.randint(50, 200),
            "findings": random.randint(10, 50),
            "blocked": random.randint(2, 10),
            "last_scan": datetime.now() - timedelta(minutes=random.randint(1, 30))
        },
        "opa": {
            "enabled": True,
            "policies": random.randint(15, 30),
            "violations": random.randint(3, 15),
            "enforced": random.randint(20, 50),
            "last_check": datetime.now() - timedelta(minutes=random.randint(1, 20))
        },
        "scp": {
            "enabled": True,
            "policies": random.randint(10, 25),
            "denied_actions": random.randint(5, 20),
            "accounts_protected": random.randint(500, 640),
            "last_update": datetime.now() - timedelta(hours=random.randint(1, 24))
        }
    }

# ============================================================================
# REAL MODE DATA FETCHERS
# ============================================================================

def fetch_real_pipeline_data(aws_clients: Dict) -> Optional[Dict[str, Any]]:
    """Fetch real pipeline data from AWS"""
    try:
        # In real mode, fetch from CodePipeline, CodeBuild, etc.
        codepipeline = aws_clients.get('codepipeline')
        if codepipeline:
            # Fetch pipeline executions
            response = codepipeline.list_pipeline_executions(
                pipelineName='DeploymentPipeline',
                maxResults=10
            )
            # Process and return data
            return response
    except Exception as e:
        st.error(f"Error fetching pipeline data: {str(e)}")
        return None

def fetch_real_security_scans(aws_clients: Dict) -> Optional[List[Dict]]:
    """Fetch real security scan results"""
    try:
        findings = []
        
        # Security Hub
        securityhub = aws_clients.get('securityhub')
        if securityhub:
            response = securityhub.get_findings(
                Filters={'ProductName': [{'Value': 'Security Hub', 'Comparison': 'EQUALS'}]},
                MaxResults=100
            )
            findings.extend(response.get('Findings', []))
        
        # Inspector
        inspector = aws_clients.get('inspector2')
        if inspector:
            response = inspector.list_findings(maxResults=100)
            findings.extend(response.get('findings', []))
        
        return findings
    except Exception as e:
        st.error(f"Error fetching security scans: {str(e)}")
        return None

# ============================================================================
# PIPELINE VISUALIZATION
# ============================================================================

def render_pipeline_diagram():
    """Render interactive pipeline diagram"""
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                padding: 1.5rem; 
                border-radius: 10px; 
                margin-bottom: 2rem;
                border-top: 4px solid #FF9900;'>
        <h2 style='color: white; margin: 0;'>🔄 DevSecOps Pipeline Flow</h2>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>
            Shift-Left Security | AI-Enhanced Detection | Automated Remediation
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Create columns for each stage
    cols = st.columns(5)
    
    for idx, stage in enumerate(PIPELINE_STAGES):
        with cols[idx]:
            # Get stage status from session state
            stage_status = st.session_state.get(f'stage_{stage["id"]}_status', 'idle')
            
            # Determine border color based on status
            border_colors = {
                'idle': '#E0E0E0',
                'running': '#FF9900',
                'success': '#4CAF50',
                'failed': '#F44336',
                'blocked': '#F44336'
            }
            border_color = border_colors.get(stage_status, '#E0E0E0')
            
            # Determine background based on status
            bg_opacity = '0.1' if stage_status == 'idle' else '0.2'
            
            st.markdown(f"""
            <div style='background: white; 
                        border: 3px solid {border_color}; 
                        border-radius: 10px; 
                        padding: 1rem; 
                        text-align: center;
                        min-height: 200px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                <div style='font-size: 3rem; margin-bottom: 0.5rem;'>{stage["icon"]}</div>
                <div style='font-weight: bold; color: {stage["color"]}; margin-bottom: 0.5rem;'>
                    {stage["name"]}
                </div>
                <div style='font-size: 0.85rem; color: #666; margin-bottom: 0.5rem;'>
                    {stage["description"]}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Stage checks
            with st.expander(f"📋 Checks ({len(stage['checks'])})"):
                for check in stage["checks"]:
                    st.markdown(f"✓ {check}")

def render_pipeline_execution_simulator():
    """Render pipeline execution simulator with real-time updates"""
    
    st.markdown("### 🎬 Pipeline Execution Simulator")
    
    col1, col2, col3 = st.columns([2, 2, 1])
    
    with col1:
        if st.button("▶️ Start Pipeline Run", type="primary", width="stretch"):
            st.session_state.pipeline_running = True
            st.session_state.current_stage = 0
            st.session_state.pipeline_start_time = time.time()
            st.rerun()
    
    with col2:
        if st.button("⏹️ Stop Pipeline", width="stretch"):
            st.session_state.pipeline_running = False
            # Reset all stages
            for stage in PIPELINE_STAGES:
                st.session_state[f'stage_{stage["id"]}_status'] = 'idle'
            st.rerun()
    
    with col3:
        inject_failure = st.checkbox("💥 Inject Failure", help="Simulate a security issue blocking the pipeline")
    
    # Pipeline execution logic
    if st.session_state.get('pipeline_running', False):
        current_stage = st.session_state.get('current_stage', 0)
        
        if current_stage < len(PIPELINE_STAGES):
            stage = PIPELINE_STAGES[current_stage]
            
            # Update stage status
            st.session_state[f'stage_{stage["id"]}_status'] = 'running'
            
            # Show progress
            progress_container = st.container()
            with progress_container:
                st.info(f"🔄 Running: **{stage['name']}** - {stage['description']}")
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Simulate stage execution
                for i in range(100):
                    progress_bar.progress(i + 1)
                    status_text.text(f"Processing... {i+1}%")
                    time.sleep(stage["duration"] / 100)
                
                # Check for failure injection
                if inject_failure and current_stage == 1:  # Fail at PR/CI stage
                    st.session_state[f'stage_{stage["id"]}_status'] = 'blocked'
                    st.error(f"❌ **{stage['name']}** - Security issues detected! Pipeline blocked.")
                    st.session_state.pipeline_running = False
                else:
                    st.session_state[f'stage_{stage["id"]}_status'] = 'success'
                    st.success(f"✅ **{stage['name']}** - Completed successfully!")
                    st.session_state.current_stage = current_stage + 1
                
                time.sleep(0.5)
                st.rerun()
        else:
            # Pipeline completed
            st.session_state.pipeline_running = False
            elapsed_time = time.time() - st.session_state.get('pipeline_start_time', time.time())
            st.success(f"🎉 **Pipeline Completed Successfully!** - Total time: {elapsed_time:.1f}s")
            
            # Record pipeline run
            if 'pipeline_history' not in st.session_state:
                st.session_state.pipeline_history = []
            
            st.session_state.pipeline_history.append({
                'timestamp': datetime.now(),
                'duration': elapsed_time,
                'status': 'SUCCESS',
                'stages': len(PIPELINE_STAGES)
            })

def render_tech_guardrails_status():
    """Render tech guardrails status dashboard"""
    
    st.markdown("### 🛡️ Tech Guardrails Status")
    
    # Get data based on mode
    if st.session_state.get('demo_mode', False):
        guardrails_data = generate_tech_guardrails_data()
    else:
        # In real mode, fetch from AWS
        guardrails_data = generate_tech_guardrails_data()  # Placeholder for now
    
    col1, col2, col3 = st.columns(3)
    
    # KICS
    with col1:
        kics = guardrails_data['kics']
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); 
                    padding: 1.5rem; 
                    border-radius: 10px; 
                    color: white;
                    text-align: center;'>
            <h3 style='margin: 0; font-size: 2rem;'>🔍 KICS</h3>
            <p style='margin: 0.5rem 0; font-size: 0.9rem;'>Infrastructure as Code Security</p>
            <div style='margin-top: 1rem;'>
                <div style='font-size: 2rem; font-weight: bold;'>{kics['scans']}</div>
                <div style='font-size: 0.85rem;'>Total Scans</div>
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.85rem;'>
                📊 {kics['findings']} Findings | 🚫 {kics['blocked']} Blocked
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.75rem; opacity: 0.9;'>
                Last scan: {kics['last_scan'].strftime('%H:%M:%S')}
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # OPA
    with col2:
        opa = guardrails_data['opa']
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #FF9900 0%, #FF6B00 100%); 
                    padding: 1.5rem; 
                    border-radius: 10px; 
                    color: white;
                    text-align: center;'>
            <h3 style='margin: 0; font-size: 2rem;'>🎯 OPA</h3>
            <p style='margin: 0.5rem 0; font-size: 0.9rem;'>Open Policy Agent</p>
            <div style='margin-top: 1rem;'>
                <div style='font-size: 2rem; font-weight: bold;'>{opa['policies']}</div>
                <div style='font-size: 0.85rem;'>Active Policies</div>
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.85rem;'>
                ⚠️ {opa['violations']} Violations | ✅ {opa['enforced']} Enforced
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.75rem; opacity: 0.9;'>
                Last check: {opa['last_check'].strftime('%H:%M:%S')}
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # SCP
    with col3:
        scp = guardrails_data['scp']
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                    padding: 1.5rem; 
                    border-radius: 10px; 
                    color: white;
                    text-align: center;'>
            <h3 style='margin: 0; font-size: 2rem;'>🔐 SCP</h3>
            <p style='margin: 0.5rem 0; font-size: 0.9rem;'>Service Control Policies</p>
            <div style='margin-top: 1rem;'>
                <div style='font-size: 2rem; font-weight: bold;'>{scp['accounts_protected']}</div>
                <div style='font-size: 0.85rem;'>Accounts Protected</div>
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.85rem;'>
                📋 {scp['policies']} Policies | 🚫 {scp['denied_actions']} Denied
            </div>
            <div style='margin-top: 0.5rem; font-size: 0.75rem; opacity: 0.9;'>
                Last update: {scp['last_update'].strftime('%Y-%m-%d %H:%M')}
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_ai_orchestration_hub():
    """Render Claude AI orchestration hub"""
    
    st.markdown("### 🤖 Claude AI Orchestration Hub")
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 2rem; 
                border-radius: 10px; 
                color: white;
                margin-bottom: 1rem;'>
        <div style='display: flex; align-items: center; margin-bottom: 1rem;'>
            <div style='font-size: 3rem; margin-right: 1rem;'>🤖</div>
            <div>
                <h3 style='margin: 0;'>Intelligent Detection, Analysis & Automated Remediation</h3>
                <p style='margin: 0.5rem 0 0 0; opacity: 0.9;'>
                    Real-time security orchestration powered by Anthropic Claude AI
                </p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # AI Features Grid
    col1, col2, col3, col4 = st.columns(4)
    
    features = [
        {
            "icon": "🔍",
            "title": "Real-time Detection",
            "description": "Continuous scanning across all pipeline stages",
            "metric": "558 scans/day"
        },
        {
            "icon": "🎯",
            "title": "Smart Prioritization",
            "description": "Risk-based ranking with business context",
            "metric": "95.2% accuracy"
        },
        {
            "icon": "⚡",
            "title": "Auto-Remediation",
            "description": "One-click fixes with generated code",
            "metric": "489 fixed issues"
        },
        {
            "icon": "📊",
            "title": "Compliance Tracking",
            "description": "PCI DSS, HIPAA, SOC 2 monitoring",
            "metric": "12 frameworks"
        }
    ]
    
    cols = [col1, col2, col3, col4]
    for idx, feature in enumerate(features):
        with cols[idx]:
            st.markdown(f"""
            <div style='background: white; 
                        border: 2px solid #E0E0E0; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        text-align: center;
                        min-height: 180px;'>
                <div style='font-size: 2.5rem; margin-bottom: 0.5rem;'>{feature["icon"]}</div>
                <div style='font-weight: bold; color: #667eea; margin-bottom: 0.5rem;'>
                    {feature["title"]}
                </div>
                <div style='font-size: 0.85rem; color: #666; margin-bottom: 0.5rem;'>
                    {feature["description"]}
                </div>
                <div style='background: #667eea; 
                            color: white; 
                            padding: 0.3rem; 
                            border-radius: 5px; 
                            font-size: 0.85rem;
                            font-weight: bold;'>
                    {feature["metric"]}
                </div>
            </div>
            """, unsafe_allow_html=True)

def render_pipeline_metrics():
    """Render pipeline security metrics"""
    
    st.markdown("### 📈 Pipeline Security Metrics")
    
    # Generate or fetch metrics based on mode
    if st.session_state.get('demo_mode', False):
        metrics = {
            "auto_remediated": 489,
            "compliance_score": 95.2,
            "avg_remediation_time": "2.1m",
            "critical_vulns": 12,
            "active_scans": 558,
            "aws_accounts": 640
        }
    else:
        # In real mode, calculate from actual data
        metrics = {
            "auto_remediated": len(st.session_state.get('remediated_findings', [])),
            "compliance_score": st.session_state.get('overall_compliance_score', 0),
            "avg_remediation_time": "N/A",
            "critical_vulns": len([f for f in st.session_state.get('security_findings', []) 
                                  if f.get('Severity', {}).get('Label') == 'CRITICAL']),
            "active_scans": 0,
            "aws_accounts": len(st.session_state.get('aws_accounts', []))
        }
    
    cols = st.columns(6)
    
    metric_configs = [
        {"label": "Auto-Remediated Issues", "value": metrics["auto_remediated"], "color": "#4CAF50"},
        {"label": "Compliance Score", "value": f"{metrics['compliance_score']}%", "color": "#FF9900"},
        {"label": "Avg Remediation Time", "value": metrics["avg_remediation_time"], "color": "#667eea"},
        {"label": "Critical Vulnerabilities", "value": metrics["critical_vulns"], "color": "#F44336"},
        {"label": "Active Scans Today", "value": metrics["active_scans"], "color": "#4CAF50"},
        {"label": "AWS Accounts", "value": metrics["aws_accounts"], "color": "#232F3E"}
    ]
    
    for idx, metric in enumerate(metric_configs):
        with cols[idx]:
            st.markdown(f"""
            <div style='background: white; 
                        border: 2px solid {metric["color"]}; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        text-align: center;'>
                <div style='font-size: 1.8rem; font-weight: bold; color: {metric["color"]};'>
                    {metric["value"]}
                </div>
                <div style='font-size: 0.75rem; color: #666; margin-top: 0.3rem;'>
                    {metric["label"]}
                </div>
            </div>
            """, unsafe_allow_html=True)

def render_security_findings_timeline():
    """Render security findings timeline"""
    
    st.markdown("### 🔍 Security Findings Timeline")
    
    # Get findings based on mode
    if st.session_state.get('demo_mode', False):
        findings = generate_demo_findings()
    else:
        # Convert real findings to timeline format
        findings = []
        for f in st.session_state.get('security_findings', []):
            findings.append({
                'id': f.get('Id', '')[:16],
                'type': f.get('Title', ''),
                'severity': f.get('Severity', {}).get('Label', ''),
                'stage': 'Runtime Monitoring',
                'timestamp': datetime.now(),
                'status': f.get('Compliance', {}).get('Status', 'OPEN')
            })
    
    if findings:
        # Create DataFrame
        df = pd.DataFrame(findings)
        df = df.sort_values('timestamp', ascending=False)
        
        # Severity distribution
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Timeline view
            st.dataframe(
                df[['id', 'type', 'severity', 'stage', 'status']].head(10),
                width="stretch",
                hide_index=True,
                column_config={
                    "id": "Finding ID",
                    "type": "Issue Type",
                    "severity": "Severity",
                    "stage": "Detected At",
                    "status": "Status"
                }
            )
        
        with col2:
            # Severity chart
            severity_counts = df['severity'].value_counts()
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Findings by Severity",
                color=severity_counts.index,
                color_discrete_map={
                    'CRITICAL': '#F44336',
                    'HIGH': '#FF9900',
                    'MEDIUM': '#FFC107',
                    'LOW': '#4CAF50'
                }
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, width="stretch")
    else:
        st.info("No security findings to display")

def render_pipeline_history():
    """Render pipeline execution history"""
    
    st.markdown("### 📊 Pipeline Execution History")
    
    history = st.session_state.get('pipeline_history', [])
    
    if history:
        # Create DataFrame
        df = pd.DataFrame(history)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Runs", len(df))
        with col2:
            success_rate = (df['status'] == 'SUCCESS').sum() / len(df) * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
        with col3:
            avg_duration = df['duration'].mean()
            st.metric("Avg Duration", f"{avg_duration:.1f}s")
        with col4:
            last_run = df['timestamp'].max()
            st.metric("Last Run", last_run.strftime('%H:%M:%S'))
        
        # History chart
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['duration'],
            mode='lines+markers',
            name='Duration',
            line=dict(color='#FF9900', width=2),
            marker=dict(size=8)
        ))
        fig.update_layout(
            title="Pipeline Duration Over Time",
            xaxis_title="Time",
            yaxis_title="Duration (seconds)",
            hovermode='x unified'
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No pipeline execution history yet. Run the pipeline to see history.")

# ============================================================================
# MAIN PIPELINE SIMULATOR
# ============================================================================

def render_pipeline_simulator():
    """Main pipeline simulator interface"""
    
    # Initialize session state
    if 'pipeline_running' not in st.session_state:
        st.session_state.pipeline_running = False
    if 'current_stage' not in st.session_state:
        st.session_state.current_stage = 0
    if 'pipeline_history' not in st.session_state:
        st.session_state.pipeline_history = []
    
    # Main header
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                padding: 2rem; 
                border-radius: 10px; 
                text-align: center;
                margin-bottom: 2rem;
                border-top: 4px solid #FF9900;'>
        <h1 style='color: white; margin: 0;'>🔄 DevSecOps Pipeline Simulator</h1>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>
            Interactive Pipeline Visualization with Tech Guardrails & AI Orchestration
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Mode indicator
    if st.session_state.get('demo_mode', False):
        st.info("🟠 **DEMO MODE** - Viewing simulated pipeline data")
    else:
        if st.session_state.get('aws_connected'):
            st.success("🟢 **LIVE MODE** - Connected to AWS pipeline data")
        else:
            st.warning("🔴 **LIVE MODE** - Not connected. Enable Demo Mode to simulate.")
    
    st.markdown("---")
    
    # Pipeline diagram
    render_pipeline_diagram()
    
    st.markdown("---")
    
    # Pipeline execution simulator
    render_pipeline_execution_simulator()
    
    st.markdown("---")
    
    # Tech guardrails status
    render_tech_guardrails_status()
    
    st.markdown("---")
    
    # AI orchestration hub
    render_ai_orchestration_hub()
    
    st.markdown("---")
    
    # Pipeline metrics
    render_pipeline_metrics()
    
    st.markdown("---")
    
    # Security findings timeline
    render_security_findings_timeline()
    
    st.markdown("---")
    
    # Pipeline history
    render_pipeline_history()

# ============================================================================
# EXPORT FUNCTION
# ============================================================================

def main():
    """Standalone execution for testing"""
    st.set_page_config(
        page_title="DevSecOps Pipeline Simulator",
        page_icon="🔄",
        layout="wide"
    )
    
    # Initialize demo mode for testing
    if 'demo_mode' not in st.session_state:
        st.session_state.demo_mode = True
    if 'aws_connected' not in st.session_state:
        st.session_state.aws_connected = False
    
    render_pipeline_simulator()

if __name__ == "__main__":
    main()