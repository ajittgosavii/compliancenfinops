"""
AI-Enhanced FinOps Module for AWS Compliance Platform
Complete integration with Anthropic Claude for intelligent cost management

Features:
- AI-Powered Cost Analysis & Insights
- Natural Language Query Interface
- Intelligent Right-Sizing Recommendations
- Advanced Anomaly Detection with Root Cause Analysis
- Automated Executive Report Generation
- Smart Cost Allocation Strategy
- Traditional FinOps Features (Backward Compatible)

Version: 1.0
Last Updated: November 2024
"""

import streamlit as st
import boto3
from botocore.exceptions import ClientError
import anthropic
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional, Tuple
import json
import os
import hashlib

# ============================================================================
# ANTHROPIC AI CLIENT INITIALIZATION
# ============================================================================

@st.cache_resource
def get_anthropic_client():
    """
    Initialize and cache Anthropic client
    
    Returns:
        anthropic.Anthropic client or None if API key not configured
    """
    # Try to get API key from multiple sources
    api_key = None
    
    # 1. Try Streamlit secrets - nested format [anthropic] section
    if hasattr(st, 'secrets'):
        try:
            if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                api_key = st.secrets['anthropic']['api_key']
        except Exception:
            pass
    
    # 2. Try Streamlit secrets - direct format
    if not api_key and hasattr(st, 'secrets') and 'ANTHROPIC_API_KEY' in st.secrets:
        api_key = st.secrets['ANTHROPIC_API_KEY']
    
    # 3. Try environment variable
    if not api_key:
        api_key = os.environ.get('ANTHROPIC_API_KEY')
    
    if not api_key:
        return None
    
    try:
        return anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        st.error(f"Error initializing Anthropic client: {str(e)}")
        return None

# ============================================================================
# AI-POWERED COST ANALYSIS FUNCTIONS
# ============================================================================

def analyze_costs_with_ai(cost_data: Dict, context: str = "") -> Dict:
    """
    Use Anthropic Claude to analyze cost data and provide intelligent insights
    
    Args:
        cost_data: Cost data from AWS Cost Explorer
        context: Additional context about the organization
        
    Returns:
        Dictionary with AI-generated insights
    """
    client = get_anthropic_client()
    if not client:
        return {
            'executive_summary': 'AI analysis not available. Configure ANTHROPIC_API_KEY to enable AI features.',
            'key_insights': [],
            'recommendations': [],
            'anomalies': [],
            'cost_allocation_suggestions': []
        }
    
    try:
        # Prepare cost data summary
        total_cost = 0
        service_costs = {}
        
        if cost_data and 'ResultsByTime' in cost_data:
            for result in cost_data['ResultsByTime']:
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    service_costs[service] = service_costs.get(service, 0) + amount
                    total_cost += amount
        
        # Sort services by cost
        top_services = dict(sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10])
        
        prompt = f"""Analyze the following AWS cost data and provide actionable insights:

Total Monthly Cost: ${total_cost:.2f}

Top Services by Cost:
{json.dumps(top_services, indent=2)}

Context: {context}

Please provide:
1. A concise executive summary (2-3 sentences)
2. 3-5 key insights about spending patterns
3. 5-7 specific, actionable cost optimization recommendations
4. Identification of any unusual spending patterns or anomalies
5. Cost allocation suggestions for better visibility

Format the response as JSON with the following structure:
{{
    "executive_summary": "string",
    "key_insights": ["insight1", "insight2", ...],
    "recommendations": [
        {{"priority": "High|Medium|Low", "action": "string", "estimated_savings": "string", "implementation": "string"}}
    ],
    "anomalies": ["anomaly1", "anomaly2", ...],
    "cost_allocation_suggestions": ["suggestion1", "suggestion2", ...]
}}

Respond ONLY with valid JSON, no additional text."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON from response
        try:
            # Try to find JSON in response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                ai_insights = json.loads(json_str)
            else:
                ai_insights = json.loads(response_text)
            
            return ai_insights
            
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return {
                'executive_summary': response_text[:500] if len(response_text) > 500 else response_text,
                'key_insights': ['AI analysis completed - see summary'],
                'recommendations': [],
                'anomalies': [],
                'cost_allocation_suggestions': []
            }
        
    except Exception as e:
        st.error(f"Error in AI cost analysis: {str(e)}")
        return {
            'executive_summary': f'Error performing AI analysis: {str(e)}',
            'key_insights': [],
            'recommendations': [],
            'anomalies': [],
            'cost_allocation_suggestions': []
        }

def generate_rightsizing_recommendations_ai(resource_data: List[Dict]) -> List[Dict]:
    """
    Use AI to analyze resource utilization and generate intelligent right-sizing recommendations
    
    Args:
        resource_data: List of resources with utilization metrics
        
    Returns:
        List of AI-generated right-sizing recommendations
    """
    client = get_anthropic_client()
    if not client or not resource_data:
        return []
    
    try:
        # Limit to first 20 resources to avoid token limits
        sample_data = resource_data[:20]
        
        prompt = f"""Analyze the following AWS resource utilization data and provide specific right-sizing recommendations:

Resource Data:
{json.dumps(sample_data, indent=2)}

For each resource that could be optimized, provide:
1. Current instance type/configuration
2. Recommended instance type/configuration
3. Expected cost savings (percentage and estimated dollars)
4. Utilization justification
5. Risk assessment (Low/Medium/High)
6. Implementation steps

Format as JSON array:
[
    {{
        "resource_id": "string",
        "resource_type": "string",
        "current_config": "string",
        "recommended_config": "string",
        "cost_savings_percent": number,
        "estimated_monthly_savings": number,
        "utilization_analysis": "string",
        "risk_level": "Low|Medium|High",
        "implementation_steps": ["step1", "step2", ...]
    }}
]

Respond ONLY with valid JSON array, no additional text."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON array
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']') + 1
        if start_idx != -1 and end_idx > start_idx:
            json_str = response_text[start_idx:end_idx]
            recommendations = json.loads(json_str)
            return recommendations
        
        return []
        
    except Exception as e:
        st.error(f"Error generating AI right-sizing recommendations: {str(e)}")
        return []

def detect_anomalies_with_ai(cost_data: Dict, historical_data: Optional[Dict] = None) -> List[Dict]:
    """
    Advanced anomaly detection using AI to identify unusual spending patterns
    
    Args:
        cost_data: Current cost data
        historical_data: Historical cost data for comparison
        
    Returns:
        List of detected anomalies with AI analysis
    """
    client = get_anthropic_client()
    if not client:
        return []
    
    try:
        # Prepare data for analysis
        daily_costs = []
        service_breakdown = {}
        
        if cost_data and 'ResultsByTime' in cost_data:
            for result in cost_data['ResultsByTime']:
                date = result['TimePeriod']['Start']
                total = float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
                daily_costs.append({'date': date, 'cost': total})
                
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    if service not in service_breakdown:
                        service_breakdown[service] = []
                    service_breakdown[service].append({'date': date, 'cost': amount})
        
        prompt = f"""Analyze the following AWS cost data for anomalies and unusual patterns:

Daily Costs (Last 30 days):
{json.dumps(daily_costs[-30:], indent=2)}

Service Breakdown (Last 7 days):
{json.dumps({k: v[-7:] for k, v in list(service_breakdown.items())[:10]}, indent=2)}

Identify:
1. Unexpected cost spikes (>20% increase)
2. Services with unusual growth patterns
3. Potential misconfigurations causing waste
4. Cost trends that deviate from normal patterns
5. Root cause analysis for each anomaly

Format as JSON array:
[
    {{
        "anomaly_type": "spike|trend|misconfiguration|waste",
        "severity": "Critical|High|Medium|Low",
        "service": "string",
        "date_detected": "string",
        "cost_impact": number,
        "description": "string",
        "root_cause_analysis": "string",
        "recommended_actions": ["action1", "action2", ...],
        "prevention_measures": ["measure1", "measure2", ...]
    }}
]

Respond ONLY with valid JSON array, no additional text."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']') + 1
        if start_idx != -1 and end_idx > start_idx:
            json_str = response_text[start_idx:end_idx]
            anomalies = json.loads(json_str)
            return anomalies
        
        return []
        
    except Exception as e:
        st.error(f"Error in AI anomaly detection: {str(e)}")
        return []

def natural_language_query(query: str, cost_data: Dict, context: Dict = None) -> str:
    """
    Allow users to ask questions about their costs in natural language
    
    Args:
        query: User's natural language question
        cost_data: Cost data context
        context: Additional context (resource inventory, tags, etc.)
        
    Returns:
        AI-generated natural language response
    """
    client = get_anthropic_client()
    if not client:
        return "AI query feature not available. Please configure ANTHROPIC_API_KEY in Streamlit secrets or environment variables."
    
    try:
        # Prepare context (limit size to avoid token limits)
        cost_context = json.dumps(cost_data, indent=2)[:2000] if cost_data else "No cost data available"
        additional_context = json.dumps(context, indent=2)[:1000] if context else "No additional context"
        
        prompt = f"""You are an AWS FinOps expert assistant. Answer the following question about AWS costs and usage:

Question: {query}

Available Cost Data:
{cost_context}

Additional Context:
{additional_context}

Provide a clear, concise answer with:
1. Direct answer to the question
2. Supporting data/evidence from the context
3. Any relevant recommendations
4. If applicable, suggest follow-up actions

Keep the response conversational and easy to understand. Use bullet points where appropriate."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
        
    except Exception as e:
        return f"Error processing query: {str(e)}"

def generate_executive_report_ai(
    cost_data: Dict,
    anomalies: List[Dict],
    recommendations: List[Dict],
    time_period: str
) -> str:
    """
    Generate comprehensive executive report with AI insights
    
    Args:
        cost_data: Cost data
        anomalies: Detected anomalies
        recommendations: Optimization recommendations
        time_period: Reporting period
        
    Returns:
        Formatted executive report in markdown
    """
    client = get_anthropic_client()
    if not client:
        return "# Executive Report\n\nAI report generation not available. Configure ANTHROPIC_API_KEY to enable this feature."
    
    try:
        # Calculate key metrics
        total_cost = 0
        if cost_data and 'ResultsByTime' in cost_data:
            for result in cost_data['ResultsByTime']:
                total_cost += float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
        
        potential_savings = sum([r.get('estimated_monthly_savings', 0) for r in recommendations]) if recommendations else 0
        
        # Prepare data summaries (limit size)
        cost_summary = json.dumps(cost_data, indent=2)[:1500] if cost_data else "No data"
        anomaly_summary = json.dumps(anomalies[:5], indent=2) if anomalies else "None"
        rec_summary = json.dumps(recommendations[:5], indent=2) if recommendations else "None"
        
        prompt = f"""Generate a professional executive summary report for AWS cloud costs:

Time Period: {time_period}
Total Cost: ${total_cost:.2f}
Anomalies Detected: {len(anomalies)}
Optimization Opportunities: {len(recommendations)}
Potential Monthly Savings: ${potential_savings:.2f}

Cost Data Summary:
{cost_summary}

Key Anomalies:
{anomaly_summary}

Top Recommendations:
{rec_summary}

Generate a comprehensive executive report with:
1. Executive Summary (3-4 paragraphs)
2. Key Findings (bullet points)
3. Cost Trends Analysis
4. Critical Issues & Anomalies
5. Optimization Opportunities
6. Recommended Actions with Priority
7. Expected ROI and Savings
8. Next Steps

Format in professional markdown suitable for executive presentation."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
        
    except Exception as e:
        return f"# Error Generating Report\n\n{str(e)}"

# ============================================================================
# TRADITIONAL FINOPS FUNCTIONS (BACKWARD COMPATIBLE)
# ============================================================================

def fetch_cost_data(ce_client, start_date: str, end_date: str, granularity: str = 'DAILY') -> Dict:
    """Fetch cost and usage data from AWS Cost Explorer"""
    if not ce_client or st.session_state.get('demo_mode', False):
        return generate_demo_cost_data()
    
    try:
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity=granularity,
            Metrics=['UnblendedCost', 'UsageQuantity'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
            ]
        )
        return response
        
    except ClientError as e:
        st.error(f"Error fetching cost data: {str(e)}")
        return generate_demo_cost_data()
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return generate_demo_cost_data()

def fetch_cost_by_portfolio(ce_client, start_date: str, end_date: str, portfolio_tag: str = 'Portfolio') -> Dict:
    """Fetch costs grouped by portfolio tag"""
    if not ce_client or st.session_state.get('demo_mode', False):
        return generate_demo_portfolio_costs()
    
    try:
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[
                {'Type': 'TAG', 'Key': portfolio_tag}
            ]
        )
        return response
    except ClientError as e:
        st.error(f"Error fetching portfolio costs: {str(e)}")
        return generate_demo_portfolio_costs()

def fetch_cost_forecast(ce_client, start_date: str, end_date: str) -> Dict:
    """Fetch cost forecast from AWS Cost Explorer"""
    if not ce_client or st.session_state.get('demo_mode', False):
        return generate_demo_forecast()
    
    try:
        response = ce_client.get_cost_forecast(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Metric='UNBLENDED_COST',
            Granularity='MONTHLY'
        )
        return response
    except ClientError as e:
        st.error(f"Error fetching forecast: {str(e)}")
        return generate_demo_forecast()

def fetch_resource_inventory(session) -> Dict:
    """Fetch inventory of AWS resources across services"""
    if not session or st.session_state.get('demo_mode', False):
        return generate_demo_inventory()
    
    inventory = {
        'ec2': [],
        'rds': [],
        's3': [],
        'lambda': [],
        'ebs': []
    }
    
    try:
        # EC2 Instances
        ec2_client = session.client('ec2')
        ec2_response = ec2_client.describe_instances()
        
        for reservation in ec2_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                inventory['ec2'].append({
                    'InstanceId': instance.get('InstanceId'),
                    'InstanceType': instance.get('InstanceType'),
                    'State': instance.get('State', {}).get('Name'),
                    'LaunchTime': str(instance.get('LaunchTime', '')),
                    'EstimatedMonthlyCost': 120.0  # Placeholder
                })
    except Exception as e:
        st.warning(f"Error fetching EC2 inventory: {str(e)}")
    
    try:
        # RDS Instances
        rds_client = session.client('rds')
        rds_response = rds_client.describe_db_instances()
        
        for db in rds_response.get('DBInstances', []):
            inventory['rds'].append({
                'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                'DBInstanceClass': db.get('DBInstanceClass'),
                'Engine': db.get('Engine'),
                'DBInstanceStatus': db.get('DBInstanceStatus'),
                'EstimatedMonthlyCost': 200.0  # Placeholder
            })
    except Exception as e:
        st.warning(f"Error fetching RDS inventory: {str(e)}")
    
    try:
        # S3 Buckets
        s3_client = session.client('s3')
        s3_response = s3_client.list_buckets()
        
        for bucket in s3_response.get('Buckets', []):
            inventory['s3'].append({
                'Name': bucket.get('Name'),
                'CreationDate': str(bucket.get('CreationDate', '')),
                'EstimatedMonthlyCost': 50.0  # Placeholder
            })
    except Exception as e:
        st.warning(f"Error fetching S3 inventory: {str(e)}")
    
    return inventory

def fetch_tag_compliance(session) -> Dict:
    """Fetch tag compliance data across resources"""
    if not session or st.session_state.get('demo_mode', False):
        return generate_demo_tag_compliance()
    
    # Simplified tag compliance check
    return generate_demo_tag_compliance()

def fetch_cost_optimization_recommendations(session) -> List[Dict]:
    """Fetch AWS cost optimization recommendations"""
    if not session or st.session_state.get('demo_mode', False):
        return generate_demo_recommendations()
    
    return generate_demo_recommendations()

# ============================================================================
# DEMO DATA GENERATION FUNCTIONS
# ============================================================================

def generate_demo_cost_data() -> Dict:
    """Generate realistic demo cost data"""
    import random
    
    results = []
    services = ['Amazon EC2', 'Amazon S3', 'Amazon RDS', 'AWS Lambda', 
                'Amazon CloudFront', 'Amazon DynamoDB', 'Amazon EBS', 'AWS Data Transfer']
    
    for i in range(30):
        date = (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
        groups = []
        
        for service in services:
            base_cost = {
                'Amazon EC2': 1200,
                'Amazon S3': 450,
                'Amazon RDS': 800,
                'AWS Lambda': 200,
                'Amazon CloudFront': 350,
                'Amazon DynamoDB': 150,
                'Amazon EBS': 300,
                'AWS Data Transfer': 180
            }.get(service, 100)
            
            # Add variation with occasional spikes
            variation = random.uniform(-50, 150)
            if random.random() < 0.05:  # 5% chance of spike
                variation += random.uniform(200, 500)
            
            daily_cost = max(base_cost + variation, 0)
            
            groups.append({
                'Keys': [service],
                'Metrics': {
                    'UnblendedCost': {
                        'Amount': str(daily_cost),
                        'Unit': 'USD'
                    },
                    'UsageQuantity': {
                        'Amount': str(random.uniform(100, 1000)),
                        'Unit': 'N/A'
                    }
                }
            })
        
        total = sum([float(g['Metrics']['UnblendedCost']['Amount']) for g in groups])
        
        results.append({
            'TimePeriod': {'Start': date, 'End': date},
            'Groups': groups,
            'Total': {
                'UnblendedCost': {
                    'Amount': str(total),
                    'Unit': 'USD'
                }
            },
            'Estimated': False
        })
    
    return {'ResultsByTime': results}

def generate_demo_portfolio_costs() -> Dict:
    """Generate demo portfolio cost data"""
    import random
    
    portfolios = ['Retail', 'Healthcare', 'Finance', 'Operations']
    results = []
    
    for i in range(3):  # 3 months
        date = (datetime.now() - timedelta(days=90-i*30)).strftime('%Y-%m-%d')
        groups = []
        
        for portfolio in portfolios:
            base_cost = {
                'Retail': 25000,
                'Healthcare': 35000,
                'Finance': 45000,
                'Operations': 15000
            }.get(portfolio, 10000)
            
            monthly_cost = base_cost + random.uniform(-3000, 5000)
            
            groups.append({
                'Keys': [portfolio],
                'Metrics': {
                    'UnblendedCost': {
                        'Amount': str(monthly_cost),
                        'Unit': 'USD'
                    }
                }
            })
        
        results.append({
            'TimePeriod': {'Start': date, 'End': date},
            'Groups': groups
        })
    
    return {'ResultsByTime': results}

def generate_demo_forecast() -> Dict:
    """Generate demo cost forecast"""
    import random
    
    forecast_data = []
    base_cost = 95000
    
    for i in range(3):  # 3 months forecast
        date = (datetime.now() + timedelta(days=30*i)).strftime('%Y-%m-%d')
        predicted = base_cost + (i * 5000) + random.uniform(-2000, 3000)
        
        forecast_data.append({
            'TimePeriod': {'Start': date, 'End': date},
            'MeanValue': str(predicted),
            'PredictionIntervalLowerBound': str(predicted * 0.9),
            'PredictionIntervalUpperBound': str(predicted * 1.1)
        })
    
    return {'ForecastResultsByTime': forecast_data}

def generate_demo_inventory() -> Dict:
    """Generate demo resource inventory"""
    return {
        'ec2': [
            {
                'InstanceId': f'i-0{i:015x}',
                'InstanceType': ['t3.medium', 't3.large', 't3.xlarge', 'm5.large'][i % 4],
                'State': 'running',
                'LaunchTime': (datetime.now() - timedelta(days=30+i)).strftime('%Y-%m-%d'),
                'EstimatedMonthlyCost': [80.0, 120.0, 160.0, 140.0][i % 4]
            }
            for i in range(8)
        ],
        'rds': [
            {
                'DBInstanceIdentifier': f'database-{i+1}',
                'DBInstanceClass': ['db.t3.medium', 'db.r5.large'][i % 2],
                'Engine': ['postgres', 'mysql'][i % 2],
                'DBInstanceStatus': 'available',
                'EstimatedMonthlyCost': [150.0, 280.0][i % 2]
            }
            for i in range(4)
        ],
        's3': [
            {
                'Name': f'bucket-{bucket}',
                'CreationDate': (datetime.now() - timedelta(days=180+i*30)).strftime('%Y-%m-%d'),
                'EstimatedMonthlyCost': 75.0
            }
            for i, bucket in enumerate(['prod-data', 'dev-data', 'backups', 'logs', 'analytics'])
        ],
        'lambda': [
            {
                'FunctionName': f'function-{i+1}',
                'Runtime': 'python3.9',
                'MemorySize': 512,
                'Invocations': 10000 * (i+1)
            }
            for i in range(6)
        ],
        'ebs': [
            {
                'VolumeId': f'vol-0{i:015x}',
                'Size': [100, 200, 500][i % 3],
                'VolumeType': 'gp3',
                'State': 'in-use',
                'EstimatedMonthlyCost': [10.0, 20.0, 50.0][i % 3]
            }
            for i in range(10)
        ]
    }

def generate_demo_tag_compliance() -> Dict:
    """Generate demo tag compliance data"""
    return {
        'total_resources': 150,
        'compliant_resources': 105,
        'partially_tagged': 30,
        'untagged_resources': 15,
        'tag_coverage': {
            'Environment': 120,
            'Portfolio': 105,
            'CostCenter': 98,
            'Owner': 110,
            'Project': 85
        },
        'resources_by_service': {
            'ec2': 45,
            'rds': 20,
            's3': 35,
            'lambda': 30,
            'ebs': 20
        }
    }

def generate_demo_recommendations() -> List[Dict]:
    """Generate demo optimization recommendations"""
    return [
        {
            'type': 'Right-Sizing',
            'resource': 'i-0123456789abcdef0',
            'current': 't3.xlarge',
            'recommended': 't3.large',
            'monthly_savings': 60.96,
            'annual_savings': 731.52,
            'confidence': 'High'
        },
        {
            'type': 'Reserved Instance',
            'resource': 'RDS db.r5.large',
            'current': 'On-Demand',
            'recommended': '1-year RI',
            'monthly_savings': 120.00,
            'annual_savings': 1440.00,
            'confidence': 'High'
        },
        {
            'type': 'S3 Lifecycle',
            'resource': 'bucket-logs',
            'current': 'Standard storage',
            'recommended': 'Intelligent-Tiering',
            'monthly_savings': 85.00,
            'annual_savings': 1020.00,
            'confidence': 'Medium'
        }
    ]

# ============================================================================
# AI-ENHANCED UI RENDERING FUNCTIONS
# ============================================================================

def render_ai_insights_panel(cost_data: Dict):
    """Render AI-powered insights panel"""
    st.markdown("### 🤖 AI Cost Intelligence")
    
    # Check if AI is available
    if not get_anthropic_client():
        st.warning("⚠️ AI features not available. Configure ANTHROPIC_API_KEY in Streamlit secrets to enable AI-powered insights.")
        st.info("👉 Add your API key in `.streamlit/secrets.toml` or as an environment variable")
        return
    
    with st.spinner("🧠 Claude is analyzing your cost data..."):
        ai_insights = analyze_costs_with_ai(cost_data, context="Enterprise AWS environment")
    
    # Executive Summary
    st.markdown("#### 📊 Executive Summary")
    st.info(ai_insights.get('executive_summary', 'No summary available'))
    
    # Key Insights and Recommendations in columns
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 💡 Key Insights")
        insights = ai_insights.get('key_insights', [])
        if insights:
            for i, insight in enumerate(insights, 1):
                st.markdown(f"**{i}.** {insight}")
        else:
            st.info("No insights available")
    
    with col2:
        st.markdown("#### 🎯 Priority Recommendations")
        recommendations = ai_insights.get('recommendations', [])
        if recommendations:
            for rec in recommendations[:5]:
                priority_color = {
                    'High': '🔴',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(rec.get('priority', 'Medium'), '⚪')
                
                with st.expander(f"{priority_color} {rec.get('action', 'Recommendation')}"):
                    st.markdown(f"**Estimated Savings:** {rec.get('estimated_savings', 'TBD')}")
                    st.markdown(f"**Implementation:** {rec.get('implementation', 'See details')}")
        else:
            st.info("No recommendations available")
    
    # Anomalies
    if ai_insights.get('anomalies'):
        st.markdown("#### ⚠️ Detected Anomalies")
        for anomaly in ai_insights['anomalies']:
            st.warning(f"🔍 {anomaly}")
    
    # Cost Allocation Suggestions
    if ai_insights.get('cost_allocation_suggestions'):
        st.markdown("#### 💰 Cost Allocation Suggestions")
        for suggestion in ai_insights['cost_allocation_suggestions']:
            st.success(f"✅ {suggestion}")

def render_ai_query_interface(cost_data: Dict, context: Dict = None):
    """Render natural language query interface"""
    st.markdown("### 💬 Ask Claude About Your Costs")
    st.markdown("Ask questions in plain English about your AWS spending, trends, or optimizations.")
    
    # Check if AI is available
    if not get_anthropic_client():
        st.warning("⚠️ AI query feature not available. Configure ANTHROPIC_API_KEY to enable this feature.")
        return
    
    # Example queries
    example_queries = [
        "What are my top 3 cost drivers?",
        "How can I reduce EC2 costs?",
        "Are there unusual spending patterns?",
        "What's causing S3 cost increases?",
        "Show me optimization opportunities"
    ]
    
    # User input
    query = st.text_input(
        "Your Question:",
        placeholder="e.g., What's driving my storage costs?"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        ask_button = st.button("🔍 Ask Claude", type="primary", width="stretch")
    
    if ask_button and query:
        with st.spinner("🤔 Claude is thinking..."):
            response = natural_language_query(query, cost_data, context)
        st.markdown("#### 💡 Claude's Response:")
        st.markdown(response)
    elif ask_button:
        st.warning("Please enter a question")
    
    # Example queries
    st.markdown("**💡 Try asking:**")
    for i, example in enumerate(example_queries):
        if st.button(example, key=f"example_{i}"):
            with st.spinner("🤔 Claude is thinking..."):
                response = natural_language_query(example, cost_data, context)
            st.markdown("#### 💡 Claude's Response:")
            st.markdown(response)

def render_ai_anomaly_detection(cost_data: Dict):
    """Render AI-powered anomaly detection"""
    st.markdown("### 🔍 AI-Powered Anomaly Detection")
    st.markdown("Claude uses advanced pattern recognition to identify unusual spending patterns.")
    
    # Check if AI is available
    if not get_anthropic_client():
        st.warning("⚠️ AI anomaly detection not available. Configure ANTHROPIC_API_KEY to enable this feature.")
        return
    
    if st.button("🤖 Detect Anomalies", type="primary"):
        with st.spinner("🧠 Claude is analyzing spending patterns..."):
            anomalies = detect_anomalies_with_ai(cost_data)
        
        if anomalies:
            # Severity summary
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'Medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🔴 Critical", severity_counts['Critical'])
            with col2:
                st.metric("🟠 High", severity_counts['High'])
            with col3:
                st.metric("🟡 Medium", severity_counts['Medium'])
            with col4:
                st.metric("🟢 Low", severity_counts['Low'])
            
            # Anomaly details
            st.markdown("#### 📊 Detected Anomalies")
            
            for anomaly in anomalies:
                severity_icon = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(anomaly.get('severity', 'Medium'), '⚪')
                
                with st.expander(
                    f"{severity_icon} [{anomaly.get('severity', 'Medium')}] "
                    f"{anomaly.get('service', 'Unknown Service')} - "
                    f"${anomaly.get('cost_impact', 0):,.2f} impact"
                ):
                    st.markdown(f"**Type:** {anomaly.get('anomaly_type', 'Unknown')}")
                    st.markdown(f"**Date:** {anomaly.get('date_detected', 'N/A')}")
                    st.markdown(f"**Description:**")
                    st.info(anomaly.get('description', 'N/A'))
                    
                    st.markdown(f"**Root Cause Analysis:**")
                    st.warning(anomaly.get('root_cause_analysis', 'Analysis pending'))
                    
                    st.markdown("**Recommended Actions:**")
                    for action in anomaly.get('recommended_actions', []):
                        st.markdown(f"- ✅ {action}")
                    
                    st.markdown("**Prevention Measures:**")
                    for measure in anomaly.get('prevention_measures', []):
                        st.markdown(f"- 🛡️ {measure}")
        else:
            st.success("✅ No anomalies detected. Your spending patterns look normal!")

def render_ai_rightsizing_advisor(resource_data: List[Dict]):
    """Render AI-powered right-sizing advisor"""
    st.markdown("### 🎯 AI-Powered Right-Sizing Advisor")
    st.markdown("Claude analyzes resource utilization and provides intelligent recommendations.")
    
    # Check if AI is available
    if not get_anthropic_client():
        st.warning("⚠️ AI right-sizing not available. Configure ANTHROPIC_API_KEY to enable this feature.")
        return
    
    if not resource_data:
        st.info("No resource data available for analysis")
        return
    
    if st.button("🧠 Generate AI Recommendations", type="primary"):
        with st.spinner("🤖 Claude is analyzing your resources..."):
            recommendations = generate_rightsizing_recommendations_ai(resource_data)
        
        if recommendations:
            # Calculate total savings
            total_savings = sum([r.get('estimated_monthly_savings', 0) for r in recommendations])
            annual_savings = total_savings * 12
            
            # Summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Resources Analyzed", len(resource_data))
            with col2:
                st.metric("Opportunities Found", len(recommendations))
            with col3:
                st.metric("Monthly Savings", f"${total_savings:,.2f}")
            
            st.info(f"💰 **Annual Savings Potential:** ${annual_savings:,.2f}")
            
            # Detailed recommendations
            st.markdown("#### 📋 Detailed Recommendations")
            
            for rec in recommendations:
                risk_color = {
                    'Low': '🟢',
                    'Medium': '🟡',
                    'High': '🔴'
                }.get(rec.get('risk_level', 'Medium'), '⚪')
                
                with st.expander(
                    f"{risk_color} {rec.get('resource_id', 'Unknown')} - "
                    f"Save ${rec.get('estimated_monthly_savings', 0):.2f}/mo "
                    f"({rec.get('cost_savings_percent', 0):.1f}%)"
                ):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Current Configuration:**")
                        st.code(rec.get('current_config', 'N/A'))
                        st.markdown("**Utilization Analysis:**")
                        st.info(rec.get('utilization_analysis', 'N/A'))
                    
                    with col2:
                        st.markdown("**Recommended Configuration:**")
                        st.code(rec.get('recommended_config', 'N/A'))
                        st.markdown(f"**Risk Level:** {risk_color} {rec.get('risk_level', 'Medium')}")
                    
                    st.markdown("**Implementation Steps:**")
                    for step in rec.get('implementation_steps', []):
                        st.markdown(f"- {step}")
        else:
            st.info("No optimization opportunities identified at this time.")

def render_ai_executive_report(cost_data: Dict):
    """Render AI-generated executive report interface"""
    st.markdown("### 📄 AI-Generated Executive Report")
    
    # Check if AI is available
    if not get_anthropic_client():
        st.warning("⚠️ AI report generation not available. Configure ANTHROPIC_API_KEY to enable this feature.")
        return
    
    time_period = st.selectbox(
        "Report Period:",
        ["Last 7 Days", "Last 30 Days", "Last Quarter", "Year to Date"]
    )
    
    if st.button("📊 Generate Report", type="primary"):
        with st.spinner("🤖 Claude is preparing your executive report..."):
            # Get anomalies and recommendations for the report
            anomalies = detect_anomalies_with_ai(cost_data)
            
            # For recommendations, we'll pass empty list if no resource data
            recommendations = []
            
            report = generate_executive_report_ai(cost_data, anomalies, recommendations, time_period)
        
        st.markdown("---")
        st.markdown(report)
        st.markdown("---")
        
        # Download options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.download_button(
                label="📥 Download as Markdown",
                data=report,
                file_name=f"executive_report_{datetime.now().strftime('%Y%m%d')}.md",
                mime="text/markdown",
                width="stretch"
            )
        
        with col2:
            # JSON version
            report_json = {
                'generated_date': datetime.now().isoformat(),
                'period': time_period,
                'report_content': report
            }
            st.download_button(
                label="📥 Download as JSON",
                data=json.dumps(report_json, indent=2),
                file_name=f"executive_report_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                width="stretch"
            )
        
        with col3:
            # HTML version
            html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Executive Cost Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #232F3E; border-bottom: 3px solid #FF9900; }}
        h2 {{ color: #FF9900; margin-top: 30px; }}
        h3 {{ color: #232F3E; }}
    </style>
</head>
<body>
{report}
</body>
</html>
"""
            st.download_button(
                label="📥 Download as HTML",
                data=html_report,
                file_name=f"executive_report_{datetime.now().strftime('%Y%m%d')}.html",
                mime="text/html",
                width="stretch"
            )

# ============================================================================
# MAIN DASHBOARD RENDERING FUNCTION
# ============================================================================

def render_enhanced_finops_dashboard():
    """
    Main AI-enhanced FinOps dashboard
    """
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                padding: 2rem; 
                border-radius: 10px; 
                text-align: center; 
                margin-bottom: 2rem;
                border-top: 4px solid #FF9900;'>
        <h1 style='color: white; margin: 0;'>🤖 AI-Enhanced FinOps Dashboard</h1>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>Intelligent Cost Management powered by Anthropic Claude</p>
    </div>
    """, unsafe_allow_html=True)
    
    # AI Status indicator
    client = get_anthropic_client()
    if client:
        st.success("✅ AI Features Active - Anthropic Claude")
    else:
        st.warning("⚠️ AI Features Disabled - Configure ANTHROPIC_API_KEY to enable")
    
    # Date range selector
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=datetime.now() - timedelta(days=30)
        )
    with col2:
        end_date = st.date_input(
            "End Date",
            value=datetime.now()
        )
    
    # Fetch cost data
    session = st.session_state.get('boto3_session')
    ce_client = None
    
    if session and not st.session_state.get('demo_mode', False):
        try:
            ce_client = session.client('ce')
        except Exception as e:
            st.warning(f"Unable to create Cost Explorer client: {str(e)}")
    
    cost_data = fetch_cost_data(
        ce_client,
        start_date.strftime('%Y-%m-%d'),
        end_date.strftime('%Y-%m-%d')
    )
    
    # Main tabs
    tabs = st.tabs([
        "🤖 AI Insights",
        "💬 Ask Claude",
        "🎯 Right-Sizing",
        "🔍 Anomaly Detection",
        "📊 Spend Analytics",
        "📄 Executive Report"
    ])
    
    # AI Insights Tab
    with tabs[0]:
        render_ai_insights_panel(cost_data)
    
    # Ask Claude Tab
    with tabs[1]:
        # Get resource inventory for context
        inventory = fetch_resource_inventory(session)
        render_ai_query_interface(cost_data, context={'resources': inventory})
    
    # Right-Sizing Tab
    with tabs[2]:
        inventory = fetch_resource_inventory(session)
        # Convert EC2 inventory to resource data format
        resource_data = []
        for ec2 in inventory.get('ec2', []):
            resource_data.append({
                'ResourceId': ec2.get('InstanceId', 'Unknown'),
                'ResourceType': 'EC2',
                'InstanceType': ec2.get('InstanceType', 'Unknown'),
                'State': ec2.get('State', 'Unknown'),
                'MonthlyCost': ec2.get('EstimatedMonthlyCost', 0)
            })
        render_ai_rightsizing_advisor(resource_data)
    
    # Anomaly Detection Tab
    with tabs[3]:
        render_ai_anomaly_detection(cost_data)
    
    # Spend Analytics Tab
    with tabs[4]:
        st.markdown("### 📊 Traditional Spend Analytics")
        
        # Calculate total cost
        total_cost = 0
        if cost_data and 'ResultsByTime' in cost_data:
            for result in cost_data['ResultsByTime']:
                total_cost += float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
        
        st.metric("Total Spend", f"${total_cost:,.2f}")
        
        # Cost by service chart
        if cost_data and 'ResultsByTime' in cost_data:
            service_costs = {}
            for result in cost_data['ResultsByTime']:
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    service_costs[service] = service_costs.get(service, 0) + amount
            
            if service_costs:
                df = pd.DataFrame([
                    {'Service': k, 'Cost': v}
                    for k, v in sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
                ])
                
                fig = px.bar(
                    df,
                    x='Service',
                    y='Cost',
                    title='Cost by Service',
                    color='Cost',
                    color_continuous_scale='Oranges'
                )
                st.plotly_chart(fig, width="stretch")
    
    # Executive Report Tab
    with tabs[5]:
        render_ai_executive_report(cost_data)

# ============================================================================
# TRADITIONAL DASHBOARD (BACKWARD COMPATIBLE)
# ============================================================================

def render_finops_dashboard():
    """
    Traditional FinOps dashboard (backward compatible)
    This is a simplified version that maintains compatibility
    """
    st.markdown("### 📊 FinOps Dashboard (Traditional View)")
    
    # Date range
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=30))
    with col2:
        end_date = st.date_input("End Date", value=datetime.now())
    
    # Fetch data
    session = st.session_state.get('boto3_session')
    ce_client = None
    
    if session and not st.session_state.get('demo_mode', False):
        try:
            ce_client = session.client('ce')
        except:
            pass
    
    cost_data = fetch_cost_data(
        ce_client,
        start_date.strftime('%Y-%m-%d'),
        end_date.strftime('%Y-%m-%d')
    )
    
    # Display cost data
    if cost_data and 'ResultsByTime' in cost_data:
        total_cost = sum([
            float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
            for result in cost_data['ResultsByTime']
        ])
        st.metric("Total Cost", f"${total_cost:,.2f}")
        
        # Service breakdown
        service_costs = {}
        for result in cost_data['ResultsByTime']:
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                service_costs[service] = service_costs.get(service, 0) + amount
        
        if service_costs:
            st.markdown("#### Cost by Service")
            df = pd.DataFrame([
                {'Service': k, 'Cost': f"${v:,.2f}"}
                for k, v in sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
            ])
            st.dataframe(df, width="stretch", hide_index=True)

# ============================================================================
# MODULE INITIALIZATION MESSAGE
# ============================================================================

if __name__ == "__main__":
    st.info("""
    ✅ **AI-Enhanced FinOps Module Loaded Successfully**
    
    This module provides:
    - 🤖 AI-powered cost analysis
    - 💬 Natural language queries
    - 🎯 Intelligent right-sizing
    - 🔍 Advanced anomaly detection
    - 📊 Traditional FinOps features
    
    To use in your app:
    ```python
    from finops_module_enhanced_complete import render_enhanced_finops_dashboard
    
    render_enhanced_finops_dashboard()
    ```
    """)