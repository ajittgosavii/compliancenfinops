"""
Claude AI Predictions Engine
=============================
Proactive and predictive analytics powered by Anthropic Claude.

Features:
- Cost forecasting and budget breach prediction
- Compliance drift prediction and risk scoring
- Security threat forecasting
- Capacity planning and resource predictions
- Natural language FinOps assistant
- Proactive alerts and recommendations

Version: 1.0.0 (2024-12-25)
"""

import streamlit as st
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd

# Try to import anthropic
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("⚠️ Anthropic library not available")


def get_predictions_claude_client():
    """Get Anthropic Claude client for predictions"""
    if not ANTHROPIC_AVAILABLE:
        return None
    
    api_key = None
    try:
        # Check nested format first: [anthropic] api_key = "..."
        if "anthropic" in st.secrets and "api_key" in st.secrets["anthropic"]:
            api_key = st.secrets["anthropic"]["api_key"]
        # Then check flat formats
        elif st.secrets.get('ANTHROPIC_API_KEY'):
            api_key = st.secrets.get('ANTHROPIC_API_KEY')
        elif st.secrets.get('anthropic_api_key'):
            api_key = st.secrets.get('anthropic_api_key')
        elif st.secrets.get('CLAUDE_API_KEY'):
            api_key = st.secrets.get('CLAUDE_API_KEY')
        elif st.secrets.get('claude_api_key'):
            api_key = st.secrets.get('claude_api_key')
    except Exception as e:
        print(f"Error getting Claude API key: {e}")
        pass
    
    if not api_key:
        return None
    
    return anthropic.Anthropic(api_key=api_key)


def call_claude(prompt: str, system_prompt: str = None, max_tokens: int = 2048) -> Optional[str]:
    """Make a call to Claude API"""
    client = get_predictions_claude_client()
    if not client:
        return None
    
    try:
        messages = [{"role": "user", "content": prompt}]
        
        kwargs = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "messages": messages
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        response = client.messages.create(**kwargs)
        return response.content[0].text
    except Exception as e:
        print(f"Claude API error: {e}")
        return None


# ==================== COST PREDICTIONS ====================

def predict_monthly_cost(cost_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict next month's costs based on historical data
    """
    if not cost_data:
        return None
    
    # Prepare context for Claude
    context = f"""
Historical Cost Data:
- Current month spend: ${cost_data.get('current_month', 0):,.2f}
- Last month spend: ${cost_data.get('last_month', 0):,.2f}
- Month before that: ${cost_data.get('two_months_ago', 0):,.2f}
- Top services: {json.dumps(cost_data.get('top_services', [])[:5])}
- Daily average: ${cost_data.get('daily_average', 0):,.2f}
- Monthly budget: ${cost_data.get('budget', 0):,.2f}
- Days remaining in month: {cost_data.get('days_remaining', 15)}
"""
    
    prompt = f"""Based on this AWS cost data, provide a JSON prediction:

{context}

Return ONLY valid JSON in this exact format:
{{
    "predicted_month_end": <number>,
    "confidence_percent": <number 0-100>,
    "budget_breach_likely": <true/false>,
    "breach_date": "<YYYY-MM-DD or null>",
    "breach_amount": <number or 0>,
    "trend": "<increasing/decreasing/stable>",
    "trend_percent": <number>,
    "key_drivers": ["<driver1>", "<driver2>"],
    "recommendation": "<one sentence recommendation>"
}}"""

    system = "You are a FinOps analyst. Return ONLY valid JSON, no markdown, no explanation."
    
    response = call_claude(prompt, system, 1024)
    if not response:
        return None
    
    try:
        # Clean response
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


def predict_cost_anomalies(cost_history: List[Dict], patterns: Dict = None) -> Optional[Dict[str, Any]]:
    """
    Predict future cost anomalies based on patterns
    """
    context = f"""
Cost History (last 30 days):
{json.dumps(cost_history[-30:] if len(cost_history) > 30 else cost_history, indent=2)}

Known Patterns:
- Deployment days typically show higher costs
- End of month often has batch processing spikes
- Weekend costs are typically 20% lower
"""
    
    prompt = f"""Analyze this AWS cost history and predict potential anomalies:

{context}

Return ONLY valid JSON:
{{
    "predicted_anomalies": [
        {{
            "date": "<YYYY-MM-DD>",
            "type": "<spike/drop/unusual_pattern>",
            "probability_percent": <number>,
            "estimated_impact": <dollar amount>,
            "reason": "<explanation>",
            "preventive_action": "<recommendation>"
        }}
    ],
    "risk_score": <0-100>,
    "pattern_insights": ["<insight1>", "<insight2>"],
    "next_7_day_forecast": [<day1_cost>, <day2_cost>, ...]
}}"""

    system = "You are an anomaly detection specialist. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 1500)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


def predict_commitment_timing(usage_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict optimal timing for Savings Plan / RI purchases
    """
    context = f"""
Current Commitment Status:
- Current SP coverage: {usage_data.get('sp_coverage', 0)}%
- Current RI coverage: {usage_data.get('ri_coverage', 0)}%
- On-demand spend: ${usage_data.get('on_demand_spend', 0):,.2f}/month
- Usage stability (30d): {usage_data.get('stability_score', 50)}%
- Expiring commitments: {json.dumps(usage_data.get('expiring', []))}

Usage Trends:
- 30-day trend: {usage_data.get('trend_30d', 'stable')}
- 90-day trend: {usage_data.get('trend_90d', 'stable')}
- Seasonal patterns: {usage_data.get('seasonal', 'none detected')}
"""
    
    prompt = f"""Analyze this AWS commitment data and recommend optimal purchase timing:

{context}

Return ONLY valid JSON:
{{
    "buy_now": <true/false>,
    "optimal_purchase_date": "<YYYY-MM-DD>",
    "wait_reason": "<reason if not buying now>",
    "recommended_commitment": {{
        "type": "<savings_plan/reserved_instance>",
        "term": "<1_year/3_year>",
        "payment": "<no_upfront/partial_upfront/all_upfront>",
        "hourly_commitment": <number>,
        "estimated_savings": <monthly savings>
    }},
    "expiration_alerts": [
        {{
            "type": "<SP/RI>",
            "expires": "<date>",
            "action": "<renew/let_expire/modify>",
            "reason": "<explanation>"
        }}
    ],
    "confidence_percent": <0-100>
}}"""

    system = "You are a cloud financial advisor. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 1500)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


# ==================== SECURITY PREDICTIONS ====================

def predict_security_risks(security_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict security risks and attack vectors
    """
    context = f"""
Current Security Posture:
- Critical findings: {security_data.get('critical', 0)}
- High findings: {security_data.get('high', 0)}
- Medium findings: {security_data.get('medium', 0)}
- Public resources: {security_data.get('public_resources', 0)}
- Unencrypted storage: {security_data.get('unencrypted', 0)}
- IAM issues: {security_data.get('iam_issues', 0)}
- Network exposure score: {security_data.get('network_score', 50)}/100

Recent Changes:
- New security groups: {security_data.get('new_sgs', 0)}
- IAM changes: {security_data.get('iam_changes', 0)}
- Public endpoint changes: {security_data.get('endpoint_changes', 0)}

Industry Context:
- Sector: {security_data.get('industry', 'Technology')}
- Current threat level: {security_data.get('threat_level', 'Medium')}
"""
    
    prompt = f"""Analyze this AWS security data and predict risks:

{context}

Return ONLY valid JSON:
{{
    "overall_risk_score": <0-100>,
    "risk_trajectory": "<increasing/decreasing/stable>",
    "predicted_threats": [
        {{
            "threat_type": "<e.g., data_breach, ransomware, cryptomining>",
            "probability_percent": <number>,
            "potential_impact": "<low/medium/high/critical>",
            "attack_vector": "<description>",
            "time_horizon": "<days/weeks/months>",
            "preventive_actions": ["<action1>", "<action2>"]
        }}
    ],
    "vulnerability_forecast": {{
        "expected_new_cves": <number>,
        "highest_risk_services": ["<service1>", "<service2>"],
        "patch_priority": ["<resource1>", "<resource2>"]
    }},
    "recommendations": [
        {{
            "priority": <1-5>,
            "action": "<description>",
            "impact": "<description>",
            "effort": "<low/medium/high>"
        }}
    ]
}}"""

    system = "You are a cybersecurity threat analyst. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


def predict_compliance_drift(compliance_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict compliance drift and violations
    """
    context = f"""
Current Compliance Status:
- Overall compliance: {compliance_data.get('compliance_percent', 0)}%
- Failed controls: {compliance_data.get('failed_controls', 0)}
- Accounts at risk: {compliance_data.get('at_risk_accounts', 0)}
- Recent changes: {compliance_data.get('recent_changes', 0)}

Compliance Frameworks:
- CIS Benchmark: {compliance_data.get('cis_score', 0)}%
- AWS Well-Architected: {compliance_data.get('wa_score', 0)}%
- SOC2 readiness: {compliance_data.get('soc2_score', 0)}%

Trend (last 30 days):
- New violations: {compliance_data.get('new_violations', 0)}
- Remediated: {compliance_data.get('remediated', 0)}
- Drift rate: {compliance_data.get('drift_rate', 0)}%/week
"""
    
    prompt = f"""Analyze this compliance data and predict drift:

{context}

Return ONLY valid JSON:
{{
    "drift_risk_score": <0-100>,
    "predicted_violations": [
        {{
            "control_id": "<e.g., CIS 2.1.4>",
            "description": "<what will fail>",
            "probability_percent": <number>,
            "expected_date": "<YYYY-MM-DD>",
            "affected_accounts": <number>,
            "root_cause": "<why this is likely>",
            "prevention": "<how to prevent>"
        }}
    ],
    "accounts_to_watch": [
        {{
            "account_id": "<account>",
            "risk_score": <0-100>,
            "likely_violations": ["<control1>", "<control2>"],
            "reason": "<why this account is risky>"
        }}
    ],
    "30_day_forecast": {{
        "expected_compliance": <percent>,
        "new_violations_predicted": <number>,
        "frameworks_at_risk": ["<framework1>"]
    }},
    "recommended_actions": ["<action1>", "<action2>", "<action3>"]
}}"""

    system = "You are a compliance risk analyst. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


# ==================== OPERATIONS PREDICTIONS ====================

def predict_capacity_needs(resource_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict capacity needs and resource scaling
    """
    context = f"""
Current Resource Utilization:
- EC2 instances: {resource_data.get('ec2_count', 0)} (avg CPU: {resource_data.get('ec2_cpu', 0)}%)
- RDS instances: {resource_data.get('rds_count', 0)} (avg CPU: {resource_data.get('rds_cpu', 0)}%)
- Lambda concurrent: {resource_data.get('lambda_concurrent', 0)} / {resource_data.get('lambda_limit', 1000)}
- S3 storage: {resource_data.get('s3_tb', 0)} TB
- Data transfer: {resource_data.get('data_transfer_gb', 0)} GB/month

Growth Trends:
- User growth: {resource_data.get('user_growth', 0)}%/month
- Transaction growth: {resource_data.get('txn_growth', 0)}%/month
- Data growth: {resource_data.get('data_growth', 0)}%/month

Upcoming Events:
- Planned launches: {resource_data.get('launches', 'None')}
- Marketing campaigns: {resource_data.get('campaigns', 'None')}
- Seasonal factors: {resource_data.get('seasonal', 'None')}
"""
    
    prompt = f"""Analyze this resource data and predict capacity needs:

{context}

Return ONLY valid JSON:
{{
    "capacity_risk_score": <0-100>,
    "predictions": [
        {{
            "resource_type": "<EC2/RDS/Lambda/S3/etc>",
            "current": "<current value>",
            "predicted_30d": "<30 day prediction>",
            "predicted_90d": "<90 day prediction>",
            "action_needed": "<none/scale_up/scale_out/optimize>",
            "urgency": "<low/medium/high/critical>",
            "recommendation": "<specific action>"
        }}
    ],
    "bottleneck_forecast": [
        {{
            "resource": "<what will bottleneck>",
            "when": "<YYYY-MM-DD>",
            "impact": "<description>",
            "prevention": "<action>"
        }}
    ],
    "cost_impact": {{
        "current_monthly": <number>,
        "predicted_monthly": <number>,
        "optimization_potential": <number>
    }},
    "recommended_architecture_changes": ["<change1>", "<change2>"]
}}"""

    system = "You are a cloud capacity planning expert. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


def predict_operational_risks(ops_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict operational failures and SLA risks
    """
    context = f"""
Current Operational Status:
- Service health: {ops_data.get('health_score', 100)}%
- Error rate: {ops_data.get('error_rate', 0)}%
- Latency p99: {ops_data.get('latency_p99', 0)}ms
- Failed deployments (30d): {ops_data.get('failed_deploys', 0)}
- Incidents (30d): {ops_data.get('incidents', 0)}

SLA Status:
- Uptime SLA: {ops_data.get('uptime_sla', 99.9)}%
- Current uptime: {ops_data.get('current_uptime', 100)}%
- SLA budget remaining: {ops_data.get('sla_budget_mins', 0)} minutes

Resource Health:
- Unhealthy targets: {ops_data.get('unhealthy_targets', 0)}
- Certificate expirations: {ops_data.get('cert_expirations', 0)}
- Deprecated resources: {ops_data.get('deprecated', 0)}
"""
    
    prompt = f"""Analyze this operational data and predict risks:

{context}

Return ONLY valid JSON:
{{
    "operational_risk_score": <0-100>,
    "sla_breach_probability": <0-100>,
    "predicted_incidents": [
        {{
            "type": "<outage/degradation/security/data_loss>",
            "probability_percent": <number>,
            "time_horizon": "<hours/days/weeks>",
            "affected_services": ["<service1>"],
            "potential_impact": "<description>",
            "early_indicators": ["<indicator1>"],
            "prevention": "<action>"
        }}
    ],
    "maintenance_predictions": [
        {{
            "resource": "<what needs maintenance>",
            "deadline": "<YYYY-MM-DD>",
            "type": "<certificate/patch/upgrade/replacement>",
            "risk_if_missed": "<description>"
        }}
    ],
    "reliability_forecast": {{
        "30_day_uptime": <percent>,
        "incident_probability": <percent>,
        "top_risks": ["<risk1>", "<risk2>"]
    }},
    "proactive_actions": [
        {{
            "priority": <1-5>,
            "action": "<description>",
            "prevents": "<what it prevents>",
            "deadline": "<YYYY-MM-DD>"
        }}
    ]
}}"""

    system = "You are a site reliability engineer. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


# ==================== EXECUTIVE SUMMARY ====================

def generate_executive_dashboard(all_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Generate executive AI dashboard with all predictions
    """
    context = f"""
ORGANIZATION OVERVIEW:
- Total AWS accounts: {all_data.get('account_count', 0)}
- Monthly spend: ${all_data.get('monthly_spend', 0):,.2f}
- Total resources: {all_data.get('resource_count', 0)}

CURRENT STATUS:
- Security score: {all_data.get('security_score', 0)}/100
- Compliance score: {all_data.get('compliance_score', 0)}/100
- Cost efficiency: {all_data.get('cost_efficiency', 0)}/100
- Operational health: {all_data.get('ops_health', 0)}/100

KEY METRICS:
- Critical security findings: {all_data.get('critical_findings', 0)}
- Compliance violations: {all_data.get('compliance_violations', 0)}
- Optimization opportunities: {all_data.get('optimization_count', 0)}
- Potential monthly savings: ${all_data.get('potential_savings', 0):,.2f}

TRENDS:
- Cost trend: {all_data.get('cost_trend', 'stable')}
- Security trend: {all_data.get('security_trend', 'stable')}
- Compliance trend: {all_data.get('compliance_trend', 'stable')}
"""
    
    prompt = f"""Generate an executive AI dashboard summary:

{context}

Return ONLY valid JSON:
{{
    "overall_health_score": <0-100>,
    "health_trajectory": "<improving/declining/stable>",
    "executive_summary": "<2-3 sentence overview>",
    "top_5_priorities": [
        {{
            "rank": <1-5>,
            "category": "<security/cost/compliance/operations>",
            "issue": "<description>",
            "impact": "<business impact>",
            "action": "<recommended action>",
            "deadline": "<urgency>"
        }}
    ],
    "risk_matrix": {{
        "security": {{"score": <0-100>, "trend": "<up/down/stable>", "top_risk": "<description>"}},
        "cost": {{"score": <0-100>, "trend": "<up/down/stable>", "top_risk": "<description>"}},
        "compliance": {{"score": <0-100>, "trend": "<up/down/stable>", "top_risk": "<description>"}},
        "operations": {{"score": <0-100>, "trend": "<up/down/stable>", "top_risk": "<description>"}}
    }},
    "30_day_outlook": {{
        "predicted_spend": <number>,
        "predicted_incidents": <number>,
        "predicted_violations": <number>,
        "key_events": ["<event1>", "<event2>"]
    }},
    "quick_wins": [
        {{
            "action": "<description>",
            "savings_or_impact": "<description>",
            "effort": "<hours/days>"
        }}
    ],
    "strategic_recommendations": ["<rec1>", "<rec2>", "<rec3>"]
}}"""

    system = "You are a cloud strategy executive advisor. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2500)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


# ==================== CHAT ASSISTANT ====================

def chat_with_claude(
    user_message: str, 
    context_data: Dict[str, Any] = None,
    chat_history: List[Dict] = None
) -> Optional[str]:
    """
    Natural language chat assistant for cloud operations
    """
    system_prompt = """You are an expert AWS cloud operations assistant with deep knowledge of:
- FinOps and cost optimization
- Security and compliance
- Infrastructure and operations
- Best practices and architecture

You have access to the user's AWS environment data. Be helpful, specific, and actionable.
When you don't have enough data, say so clearly.
Format responses with markdown for readability.
"""
    
    context_section = ""
    if context_data:
        context_section = f"""

CURRENT ENVIRONMENT DATA:
```json
{json.dumps(context_data, indent=2, default=str)}
```
"""
    
    # Build conversation
    messages = []
    
    if chat_history:
        for msg in chat_history[-10:]:  # Last 10 messages for context
            messages.append(msg)
    
    messages.append({
        "role": "user",
        "content": f"{context_section}\n\nUser Question: {user_message}"
    })
    
    client = get_predictions_claude_client()
    if not client:
        return None
    
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=system_prompt,
            messages=messages
        )
        return response.content[0].text
    except Exception as e:
        print(f"Chat error: {e}")
        return None


# ==================== PROACTIVE ALERTS ====================

def generate_proactive_alerts(all_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Generate proactive alerts based on predictions
    """
    context = f"""
Current Status:
- Monthly spend: ${all_data.get('monthly_spend', 0):,.2f}
- Budget: ${all_data.get('budget', 0):,.2f}
- Days in month remaining: {all_data.get('days_remaining', 15)}
- Critical findings: {all_data.get('critical_findings', 0)}
- Expiring commitments: {all_data.get('expiring_commitments', 0)}
- Certificate expirations: {all_data.get('cert_expirations', 0)}
- Compliance violations: {all_data.get('compliance_violations', 0)}
- High CPU instances: {all_data.get('high_cpu_instances', 0)}
- Failed jobs: {all_data.get('failed_jobs', 0)}
"""
    
    prompt = f"""Based on this data, generate proactive alerts:

{context}

Return ONLY a JSON array of alerts:
[
    {{
        "severity": "<critical/warning/info>",
        "category": "<cost/security/compliance/operations>",
        "title": "<short title>",
        "message": "<detailed message>",
        "action": "<recommended action>",
        "deadline": "<when to act by>",
        "impact_if_ignored": "<what happens if ignored>"
    }}
]

Generate 3-7 relevant alerts based on the data. Prioritize by severity."""

    system = "You are an alert generation system. Return ONLY a valid JSON array."
    
    response = call_claude(prompt, system, 1500)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


# ==================== CONTAINER & CODE PREDICTIONS ====================

def predict_container_risks(container_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict container and supply chain risks
    """
    context = f"""
Container Environment:
- Total images: {container_data.get('image_count', 0)}
- Images with critical CVEs: {container_data.get('critical_cve_images', 0)}
- Images with high CVEs: {container_data.get('high_cve_images', 0)}
- Base images used: {json.dumps(container_data.get('base_images', []))}
- Average image age: {container_data.get('avg_image_age_days', 0)} days
- Images not scanned: {container_data.get('unscanned', 0)}

Recent Activity:
- New images (7d): {container_data.get('new_images_7d', 0)}
- Updated images (7d): {container_data.get('updated_images_7d', 0)}
- Deployments (7d): {container_data.get('deployments_7d', 0)}
"""
    
    prompt = f"""Analyze container security and predict risks:

{context}

Return ONLY valid JSON:
{{
    "supply_chain_risk_score": <0-100>,
    "image_health_score": <0-100>,
    "predicted_vulnerabilities": [
        {{
            "base_image": "<image name>",
            "expected_cves": <number>,
            "severity": "<critical/high/medium>",
            "timeframe": "<days/weeks>",
            "recommendation": "<action>"
        }}
    ],
    "drift_alerts": [
        {{
            "image": "<image name>",
            "drift_type": "<config/package/base>",
            "risk_level": "<low/medium/high>",
            "action": "<recommendation>"
        }}
    ],
    "recommended_updates": [
        {{
            "current_image": "<current>",
            "recommended": "<new version>",
            "reason": "<why update>",
            "urgency": "<low/medium/high/critical>"
        }}
    ],
    "30_day_forecast": {{
        "expected_new_cves": <number>,
        "images_needing_update": <number>,
        "supply_chain_events": ["<event1>"]
    }}
}}"""

    system = "You are a container security expert. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None


def predict_code_quality_trends(code_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Predict code quality and tech debt trends
    """
    context = f"""
Code Quality Metrics:
- Total repositories: {code_data.get('repo_count', 0)}
- Open security findings: {code_data.get('security_findings', 0)}
- Code coverage: {code_data.get('coverage_percent', 0)}%
- Technical debt hours: {code_data.get('tech_debt_hours', 0)}
- Dependency vulnerabilities: {code_data.get('dep_vulns', 0)}

Trends (30 days):
- New findings: {code_data.get('new_findings_30d', 0)}
- Resolved findings: {code_data.get('resolved_30d', 0)}
- Tech debt change: {code_data.get('tech_debt_change', 0)}%
- Coverage change: {code_data.get('coverage_change', 0)}%
"""
    
    prompt = f"""Analyze code quality data and predict trends:

{context}

Return ONLY valid JSON:
{{
    "code_health_score": <0-100>,
    "tech_debt_trajectory": "<increasing/decreasing/stable>",
    "predictions": {{
        "30_day_findings": <expected new findings>,
        "30_day_tech_debt": <expected tech debt hours>,
        "30_day_coverage": <expected coverage %>
    }},
    "hotspots": [
        {{
            "repository": "<repo name>",
            "risk_type": "<security/quality/debt>",
            "risk_score": <0-100>,
            "prediction": "<what will happen>",
            "recommendation": "<action>"
        }}
    ],
    "recommended_focus_areas": [
        {{
            "area": "<description>",
            "reason": "<why focus here>",
            "expected_impact": "<impact of fixing>"
        }}
    ],
    "dependency_alerts": [
        {{
            "package": "<package name>",
            "current_version": "<version>",
            "risk": "<description>",
            "action": "<update/replace/review>"
        }}
    ]
}}"""

    system = "You are a code quality analyst. Return ONLY valid JSON."
    
    response = call_claude(prompt, system, 2000)
    if not response:
        return None
    
    try:
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)
    except:
        return None
