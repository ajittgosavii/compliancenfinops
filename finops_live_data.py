"""
AWS FinOps Live Data Module
===========================

Provides Budget Tracking and Optimization dashboards using REAL AWS data.
Uses client getters from aws_finops_data.py which are proven to work.

Author: Cloud Compliance Canvas
Version: 1.1.0
"""

import streamlit as st
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd

# Import working client getters from aws_finops_data
try:
    from aws_finops_data import get_ce_client, get_org_client, get_date_range
    AWS_FINOPS_AVAILABLE = True
except ImportError:
    AWS_FINOPS_AVAILABLE = False
    print("Note: aws_finops_data.py not available")
    
    # Fallback implementations
    def get_ce_client():
        clients = st.session_state.get('aws_clients', {})
        return clients.get('ce')
    
    def get_org_client():
        clients = st.session_state.get('aws_clients', {})
        return clients.get('organizations')
    
    def get_date_range(days: int = 30):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        return start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')


def is_live_mode() -> bool:
    """Check if we're in live mode with valid AWS connection"""
    if st.session_state.get('demo_mode', False):
        return False
    
    # Check for AWS connection
    if st.session_state.get('aws_connected', False):
        return True
    if st.session_state.get('aws_clients'):
        return True
    if st.session_state.get('aws_account_id'):
        return True
    
    return False


# ============================================================================
# COST DATA FUNCTIONS - Using same pattern as working aws_finops_data.py
# ============================================================================

def fetch_real_cost_data(days: int = 30) -> Optional[Dict]:
    """Fetch cost data using the same pattern as aws_finops_data.py"""
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date, end_date = get_date_range(days)
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='DAILY',
            Metrics=['BlendedCost', 'UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        total_cost = 0
        service_costs = {}
        daily_costs = []
        
        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            day_total = 0
            
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                service_costs[service] = service_costs.get(service, 0) + cost
                day_total += cost
                total_cost += cost
            
            daily_costs.append({'date': date, 'cost': day_total})
        
        return {
            'total_cost': total_cost,
            'service_costs': service_costs,
            'daily_costs': daily_costs,
            'period_days': days,
            'source': 'AWS Cost Explorer'
        }
        
    except Exception as e:
        st.warning(f"Cost data: {e}")
        return None


def fetch_monthly_costs(months: int = 6) -> Optional[List[Dict]]:
    """Fetch monthly cost breakdown"""
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        end_date = datetime.now().replace(day=1)
        start_date = (end_date - timedelta(days=months * 31)).replace(day=1)
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost']
        )
        
        monthly_costs = []
        for result in response.get('ResultsByTime', []):
            month_start = result['TimePeriod']['Start']
            cost = float(result.get('Total', {}).get('BlendedCost', {}).get('Amount', 0))
            month_date = datetime.strptime(month_start, '%Y-%m-%d')
            
            monthly_costs.append({
                'month': month_date.strftime('%b'),
                'date': month_start,
                'cost': cost
            })
        
        return monthly_costs
        
    except Exception as e:
        st.warning(f"Monthly costs: {e}")
        return None


def fetch_real_forecast() -> Optional[Dict]:
    """Fetch cost forecast"""
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date = datetime.now() + timedelta(days=1)
        end_date = start_date + timedelta(days=30)
        
        response = ce_client.get_cost_forecast(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Metric='BLENDED_COST',
            Granularity='MONTHLY'
        )
        
        forecast_amount = float(response.get('Total', {}).get('Amount', 0))
        
        return {
            'forecast_amount': forecast_amount,
            'forecast_start': start_date.strftime('%Y-%m-%d'),
            'forecast_end': end_date.strftime('%Y-%m-%d')
        }
        
    except ClientError as e:
        if 'DataUnavailable' in str(e):
            return {'forecast_amount': None, 'error': 'Not enough historical data'}
        return None
    except Exception:
        return None


def fetch_real_budgets() -> Optional[List[Dict]]:
    """
    Fetch AWS Budgets data.
    Note: Budgets client is typically not pre-initialized, so this may not work.
    """
    # Try to get from aws_clients (unlikely to exist)
    clients = st.session_state.get('aws_clients', {})
    budgets_client = clients.get('budgets')
    
    if not budgets_client:
        # Budgets not available - return None silently
        return None
    
    try:
        account_id = st.session_state.get('aws_account_id')
        if not account_id:
            return None
        
        response = budgets_client.describe_budgets(AccountId=account_id)
        
        budgets = []
        for budget in response.get('Budgets', []):
            budget_limit = float(budget['BudgetLimit']['Amount'])
            actual_spend = float(budget.get('CalculatedSpend', {}).get('ActualSpend', {}).get('Amount', 0))
            forecasted_spend = float(budget.get('CalculatedSpend', {}).get('ForecastedSpend', {}).get('Amount', 0))
            utilization = (actual_spend / budget_limit * 100) if budget_limit > 0 else 0
            
            budgets.append({
                'name': budget['BudgetName'],
                'type': budget['BudgetType'],
                'limit': budget_limit,
                'actual': actual_spend,
                'forecasted': forecasted_spend,
                'utilization': utilization,
                'remaining': budget_limit - actual_spend
            })
        
        return budgets if budgets else None
        
    except Exception:
        return None


def fetch_real_recommendations() -> Optional[List[Dict]]:
    """Fetch Compute Optimizer recommendations"""
    clients = st.session_state.get('aws_clients', {})
    co = clients.get('compute_optimizer') or clients.get('compute-optimizer')
    
    if not co:
        return None
    
    recommendations = []
    
    try:
        ec2_response = co.get_ec2_instance_recommendations()
        
        for rec in ec2_response.get('instanceRecommendations', []):
            if rec.get('finding') != 'OPTIMIZED':
                rec_options = rec.get('recommendationOptions', [])
                if rec_options:
                    recommendations.append({
                        'type': 'EC2',
                        'resource_id': rec.get('instanceArn', '').split('/')[-1],
                        'finding': rec.get('finding'),
                        'current': rec.get('currentInstanceType', 'Unknown'),
                        'recommended': rec_options[0].get('instanceType', 'Unknown'),
                        'category': 'Compute'
                    })
        
    except Exception:
        pass
    
    try:
        if co:
            ebs_response = co.get_ebs_volume_recommendations()
            
            for rec in ebs_response.get('volumeRecommendations', []):
                if rec.get('finding') != 'OPTIMIZED':
                    recommendations.append({
                        'type': 'EBS',
                        'resource_id': rec.get('volumeArn', '').split('/')[-1],
                        'finding': rec.get('finding'),
                        'current': rec.get('currentConfiguration', {}).get('volumeType'),
                        'recommended': rec.get('volumeRecommendationOptions', [{}])[0].get('configuration', {}).get('volumeType'),
                        'category': 'Storage'
                    })
    except Exception:
        pass
    
    return recommendations if recommendations else None


# ============================================================================
# RENDER FUNCTIONS
# ============================================================================

def render_real_budget_tracking():
    """Render budget tracking with REAL AWS data"""
    
    st.subheader("📈 Budget Tracking & Forecasting")
    
    # Debug info
    with st.expander("🔧 Debug Info", expanded=False):
        st.write(f"demo_mode: {st.session_state.get('demo_mode', 'not set')}")
        st.write(f"aws_connected: {st.session_state.get('aws_connected', 'not set')}")
        st.write(f"aws_account_id: {st.session_state.get('aws_account_id', 'not set')}")
        clients = st.session_state.get('aws_clients', {})
        st.write(f"aws_clients keys: {list(clients.keys())}")
        st.write(f"has 'ce' client: {'ce' in clients and clients.get('ce') is not None}")
        st.write(f"is_live_mode(): {is_live_mode()}")
        st.write(f"AWS_FINOPS_AVAILABLE: {AWS_FINOPS_AVAILABLE}")
        ce = get_ce_client()
        st.write(f"get_ce_client() returned: {type(ce).__name__ if ce else None}")
    
    if not is_live_mode():
        st.warning("⚠️ Enable Live Mode and connect to AWS to see real budget data")
        return
    
    # Check CE client
    ce_client = get_ce_client()
    if not ce_client:
        st.error("❌ Cost Explorer client not available")
        return
    
    st.success("✅ Connected to AWS Cost Explorer")
    
    # Fetch data
    with st.spinner("Loading cost data..."):
        costs = fetch_real_cost_data(30)
        forecast = fetch_real_forecast()
        monthly_costs = fetch_monthly_costs(6)
        budgets = fetch_real_budgets()
    
    if not costs:
        st.warning("No cost data available. Cost Explorer may not be enabled or there's no historical data.")
        return
    
    # Display cost overview
    st.markdown("### 💰 Cost Overview (Last 30 Days)")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Spend", f"${costs['total_cost']:,.2f}")
    with col2:
        daily_avg = costs['total_cost'] / max(costs['period_days'], 1)
        st.metric("Daily Average", f"${daily_avg:,.2f}")
    with col3:
        if forecast and forecast.get('forecast_amount'):
            st.metric("Forecasted", f"${forecast['forecast_amount']:,.2f}")
        else:
            st.metric("Forecast", "N/A")
    with col4:
        if costs['service_costs']:
            top_service = max(costs['service_costs'], key=costs['service_costs'].get)
            display_name = top_service[:18] + "..." if len(top_service) > 18 else top_service
            st.metric("Top Service", display_name)
    
    st.markdown("---")
    
    # Budget status if available
    if budgets:
        st.markdown("### 📊 Budget Status")
        main_budget = budgets[0]
        for b in budgets:
            if 'total' in b['name'].lower() or 'monthly' in b['name'].lower():
                main_budget = b
                break
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Budget", f"${main_budget['limit']:,.0f}", 
                     delta=f"{main_budget['utilization']:.1f}% used")
        with col2:
            st.metric("Spent", f"${main_budget['actual']:,.0f}")
        with col3:
            st.metric("Forecasted", f"${main_budget['forecasted']:,.0f}")
        with col4:
            st.metric("Remaining", f"${main_budget['remaining']:,.0f}")
    else:
        st.info("💡 No AWS Budgets configured. Create a budget in AWS Console for budget tracking.")
    
    # Monthly trend chart
    if monthly_costs:
        st.markdown("---")
        st.markdown("### 📈 Monthly Cost Trend")
        
        import plotly.graph_objects as go
        
        months = [m['month'] for m in monthly_costs]
        month_costs_values = [m['cost'] for m in monthly_costs]
        
        fig = go.Figure()
        fig.add_trace(go.Bar(x=months, y=month_costs_values, name='Actual Spend', marker_color='#88C0D0'))
        
        if budgets:
            budget_line = [main_budget['limit']] * len(months)
            fig.add_trace(go.Scatter(x=months, y=budget_line, name='Budget',
                                    line=dict(color='#dc3545', width=3, dash='dash')))
        
        fig.update_layout(height=350, yaxis_title='Cost ($)',
                         legend=dict(orientation='h', yanchor='bottom', y=1.02))
        st.plotly_chart(fig, use_container_width=True)
    
    # Service breakdown
    if costs and costs.get('service_costs'):
        st.markdown("---")
        st.markdown("### 📋 Cost by Service (Top 10)")
        
        import plotly.express as px
        
        sorted_services = sorted(costs['service_costs'].items(), key=lambda x: x[1], reverse=True)[:10]
        
        col1, col2 = st.columns(2)
        
        with col1:
            service_data = [{'Service': s[0][:25], 'Cost': s[1]} for s in sorted_services]
            df = pd.DataFrame(service_data)
            fig = px.pie(df, values='Cost', names='Service', hole=0.4)
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            for service, cost in sorted_services[:7]:
                pct = (cost / costs['total_cost'] * 100) if costs['total_cost'] > 0 else 0
                st.write(f"**{service[:30]}**: ${cost:,.2f} ({pct:.1f}%)")


def render_real_optimization_recommendations():
    """Render optimization recommendations"""
    
    st.subheader("📊 Cost Optimization Recommendations")
    
    if not is_live_mode():
        st.warning("⚠️ Enable Live Mode to see recommendations")
        return
    
    # Check for Compute Optimizer
    clients = st.session_state.get('aws_clients', {})
    co = clients.get('compute_optimizer') or clients.get('compute-optimizer')
    
    if not co:
        st.info("""
        💡 **Compute Optimizer not available**
        
        Enable AWS Compute Optimizer to get right-sizing recommendations:
        1. Go to [AWS Compute Optimizer Console](https://console.aws.amazon.com/compute-optimizer)
        2. Click "Get started" to opt in
        3. Wait 12-24 hours for recommendations to generate
        """)
        return
    
    st.success("✅ Fetching recommendations from AWS Compute Optimizer...")
    
    with st.spinner("Loading..."):
        recommendations = fetch_real_recommendations()
    
    if not recommendations:
        st.success("✅ No optimization recommendations - your resources may already be well-optimized!")
        st.info("💡 Recommendations appear when resources are over-provisioned or under-utilized.")
        return
    
    # Summary
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Recommendations", len(recommendations))
    with col2:
        categories = set(r.get('category', 'Other') for r in recommendations)
        st.metric("Categories", len(categories))
    
    st.markdown("---")
    
    # Recommendations list
    for i, rec in enumerate(recommendations[:10]):
        with st.expander(f"**{rec['type']}**: {rec['resource_id'][:20]}..."):
            st.write(f"**Finding:** {rec.get('finding', 'N/A')}")
            st.write(f"**Current:** {rec.get('current', 'N/A')}")
            st.write(f"**Recommended:** {rec.get('recommended', 'N/A')}")
            st.write(f"**Category:** {rec.get('category', 'N/A')}")


def render_live_finops_dashboard():
    """Main entry point for live FinOps dashboard"""
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); 
                padding: 1rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>💰 FinOps Live Dashboard</h2>
        <p style='color: #fef3c7; margin: 0.5rem 0 0 0;'>Real-time AWS cost data</p>
    </div>
    """, unsafe_allow_html=True)
    
    if is_live_mode():
        st.success("✅ **LIVE MODE** - Using real AWS data")
    else:
        st.warning("⚠️ **DEMO MODE** - Enable Live Mode for real data")
    
    tabs = st.tabs(["📊 Cost Dashboard", "📈 Budget Tracking", "🎯 Optimization"])
    
    with tabs[0]:
        render_real_budget_tracking()
    
    with tabs[1]:
        render_real_budget_tracking()
    
    with tabs[2]:
        render_real_optimization_recommendations()


# Export
__all__ = [
    'render_real_budget_tracking',
    'render_real_optimization_recommendations', 
    'render_live_finops_dashboard',
    'fetch_real_cost_data',
    'fetch_real_budgets',
    'fetch_monthly_costs',
    'is_live_mode'
]