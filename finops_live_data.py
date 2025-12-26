"""
AWS FinOps Live Data Module
===========================

Fetches REAL data from AWS services:
- AWS Cost Explorer (costs, forecasts)
- AWS Budgets (budget tracking)
- AWS Compute Optimizer (recommendations)
- AWS Cost Optimization Hub (savings opportunities)

Replace hardcoded demo data with actual AWS API calls.

Author: Cloud Compliance Canvas
Version: 1.0.0
"""

import streamlit as st
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd


# ============================================================================
# AWS CLIENT HELPERS
# ============================================================================

def get_aws_client(service_name: str):
    """Get boto3 client from session state or create new one"""
    try:
        session = st.session_state.get('boto3_session')
        if session:
            return session.client(service_name)
        else:
            return boto3.client(service_name)
    except Exception as e:
        st.warning(f"Cannot create {service_name} client: {e}")
        return None


def is_live_mode() -> bool:
    """Check if we're in live mode with valid AWS connection"""
    if st.session_state.get('demo_mode', False):
        return False
    
    # Check if we have a valid session
    session = st.session_state.get('boto3_session')
    if not session:
        # Try to create one
        try:
            sts = boto3.client('sts')
            sts.get_caller_identity()
            return True
        except Exception:
            return False
    
    return True


# ============================================================================
# AWS COST EXPLORER - REAL DATA
# ============================================================================

def fetch_real_cost_data(days: int = 30) -> Dict:
    """
    Fetch REAL cost data from AWS Cost Explorer
    
    Returns:
        Dictionary with actual cost breakdown by service
    """
    if not is_live_mode():
        return None
    
    ce = get_aws_client('ce')
    if not ce:
        return None
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    try:
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost', 'UsageQuantity'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
        )
        
        # Process results
        total_cost = 0
        service_costs = {}
        daily_costs = []
        
        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            day_total = 0
            
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                
                if service not in service_costs:
                    service_costs[service] = 0
                service_costs[service] += cost
                day_total += cost
                total_cost += cost
            
            daily_costs.append({
                'date': date,
                'cost': day_total
            })
        
        return {
            'total_cost': total_cost,
            'service_costs': service_costs,
            'daily_costs': daily_costs,
            'period_days': days,
            'source': 'AWS Cost Explorer'
        }
        
    except ClientError as e:
        st.error(f"Cost Explorer error: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        st.error(f"Error fetching cost data: {e}")
        return None


def fetch_real_forecast() -> Dict:
    """
    Fetch REAL cost forecast from AWS Cost Explorer
    
    Returns:
        Dictionary with forecast data
    """
    if not is_live_mode():
        return None
    
    ce = get_aws_client('ce')
    if not ce:
        return None
    
    start_date = datetime.now() + timedelta(days=1)
    end_date = start_date + timedelta(days=30)
    
    try:
        response = ce.get_cost_forecast(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Metric='UNBLENDED_COST',
            Granularity='MONTHLY'
        )
        
        forecast_amount = float(response.get('Total', {}).get('Amount', 0))
        
        return {
            'forecast_amount': forecast_amount,
            'forecast_start': start_date.strftime('%Y-%m-%d'),
            'forecast_end': end_date.strftime('%Y-%m-%d'),
            'source': 'AWS Cost Explorer Forecast'
        }
        
    except ClientError as e:
        # Forecast may not be available if there's not enough historical data
        if 'DataUnavailable' in str(e):
            return {'forecast_amount': None, 'error': 'Not enough historical data'}
        st.error(f"Forecast error: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        st.error(f"Error fetching forecast: {e}")
        return None


def fetch_monthly_costs(months: int = 6) -> List[Dict]:
    """
    Fetch REAL monthly costs for the past N months
    
    Returns:
        List of monthly cost data
    """
    if not is_live_mode():
        return None
    
    ce = get_aws_client('ce')
    if not ce:
        return None
    
    end_date = datetime.now().replace(day=1)  # First of current month
    start_date = (end_date - timedelta(days=months * 31)).replace(day=1)
    
    try:
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        monthly_costs = []
        for result in response.get('ResultsByTime', []):
            month_start = result['TimePeriod']['Start']
            cost = float(result.get('Total', {}).get('UnblendedCost', {}).get('Amount', 0))
            
            # Parse month name
            month_date = datetime.strptime(month_start, '%Y-%m-%d')
            month_name = month_date.strftime('%b')
            
            monthly_costs.append({
                'month': month_name,
                'date': month_start,
                'cost': cost
            })
        
        return monthly_costs
        
    except Exception as e:
        st.error(f"Error fetching monthly costs: {e}")
        return None


# ============================================================================
# AWS BUDGETS - REAL DATA
# ============================================================================

def fetch_real_budgets() -> List[Dict]:
    """
    Fetch REAL budget data from AWS Budgets
    
    Returns:
        List of budgets with actual vs budgeted amounts
    """
    if not is_live_mode():
        return None
    
    budgets_client = get_aws_client('budgets')
    if not budgets_client:
        return None
    
    try:
        # Get account ID
        sts = get_aws_client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        response = budgets_client.describe_budgets(AccountId=account_id)
        
        budgets = []
        for budget in response.get('Budgets', []):
            budget_name = budget['BudgetName']
            budget_type = budget['BudgetType']
            
            # Get budget limit
            budget_limit = float(budget['BudgetLimit']['Amount'])
            
            # Get actual spend
            actual_spend = float(budget.get('CalculatedSpend', {}).get('ActualSpend', {}).get('Amount', 0))
            
            # Get forecasted spend
            forecasted_spend = float(budget.get('CalculatedSpend', {}).get('ForecastedSpend', {}).get('Amount', 0))
            
            utilization = (actual_spend / budget_limit * 100) if budget_limit > 0 else 0
            
            budgets.append({
                'name': budget_name,
                'type': budget_type,
                'limit': budget_limit,
                'actual': actual_spend,
                'forecasted': forecasted_spend,
                'utilization': utilization,
                'remaining': budget_limit - actual_spend
            })
        
        return budgets
        
    except ClientError as e:
        if 'AccessDenied' in str(e):
            st.warning("No permission to access AWS Budgets")
        else:
            st.error(f"Budgets error: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        st.error(f"Error fetching budgets: {e}")
        return None


# ============================================================================
# AWS COMPUTE OPTIMIZER - REAL DATA
# ============================================================================

def fetch_real_recommendations() -> List[Dict]:
    """
    Fetch REAL optimization recommendations from AWS Compute Optimizer
    
    Returns:
        List of optimization recommendations
    """
    if not is_live_mode():
        return None
    
    co = get_aws_client('compute-optimizer')
    if not co:
        return None
    
    recommendations = []
    
    try:
        # Get EC2 recommendations
        ec2_response = co.get_ec2_instance_recommendations()
        
        for rec in ec2_response.get('instanceRecommendations', []):
            if rec.get('finding') != 'OPTIMIZED':
                current_type = rec.get('currentInstanceType', 'Unknown')
                
                # Get recommended options
                rec_options = rec.get('recommendationOptions', [])
                if rec_options:
                    best_option = rec_options[0]
                    recommended_type = best_option.get('instanceType', 'Unknown')
                    
                    # Calculate savings
                    current_price = best_option.get('projectedUtilizationMetrics', [{}])
                    
                    recommendations.append({
                        'type': 'EC2',
                        'resource_id': rec.get('instanceArn', '').split('/')[-1],
                        'finding': rec.get('finding'),
                        'current': current_type,
                        'recommended': recommended_type,
                        'reason': rec.get('findingReasonCodes', []),
                        'category': 'Compute'
                    })
        
    except ClientError as e:
        if 'OptInRequired' in str(e):
            st.info("💡 Enable Compute Optimizer for EC2 recommendations")
        elif 'AccessDenied' not in str(e):
            st.warning(f"Compute Optimizer: {e.response['Error']['Message']}")
    except Exception as e:
        pass  # Silently fail for this optional service
    
    try:
        # Get EBS recommendations
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
        pass  # Silently fail
    
    return recommendations if recommendations else None


def fetch_cost_optimization_hub() -> List[Dict]:
    """
    Fetch recommendations from AWS Cost Optimization Hub
    
    Returns:
        List of cost optimization opportunities
    """
    if not is_live_mode():
        return None
    
    try:
        coh = get_aws_client('cost-optimization-hub')
        if not coh:
            return None
        
        response = coh.list_recommendations(maxResults=50)
        
        opportunities = []
        for rec in response.get('items', []):
            opportunities.append({
                'id': rec.get('recommendationId'),
                'type': rec.get('recommendationResourceType'),
                'action': rec.get('actionType'),
                'region': rec.get('region'),
                'estimated_savings': rec.get('estimatedMonthlySavings', 0),
                'implementation_effort': rec.get('implementationEffort', 'Unknown'),
                'source': rec.get('source')
            })
        
        return opportunities
        
    except ClientError as e:
        if 'NotEnabledException' in str(e):
            st.info("💡 Enable Cost Optimization Hub for centralized recommendations")
        return None
    except Exception:
        return None


# ============================================================================
# AWS COST ANOMALY DETECTION - REAL DATA
# ============================================================================

def fetch_real_anomalies() -> List[Dict]:
    """
    Fetch REAL cost anomalies from AWS Cost Anomaly Detection
    
    Returns:
        List of detected anomalies
    """
    if not is_live_mode():
        return None
    
    ce = get_aws_client('ce')
    if not ce:
        return None
    
    try:
        # Get anomaly monitors
        monitors_response = ce.get_anomaly_monitors()
        
        anomalies = []
        
        for monitor in monitors_response.get('AnomalyMonitors', []):
            monitor_arn = monitor['MonitorArn']
            
            # Get anomalies for this monitor
            anomaly_response = ce.get_anomalies(
                MonitorArn=monitor_arn,
                DateInterval={
                    'StartDate': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
                    'EndDate': datetime.now().strftime('%Y-%m-%d')
                }
            )
            
            for anomaly in anomaly_response.get('Anomalies', []):
                anomalies.append({
                    'id': anomaly.get('AnomalyId'),
                    'start_date': anomaly.get('AnomalyStartDate'),
                    'end_date': anomaly.get('AnomalyEndDate'),
                    'impact': anomaly.get('Impact', {}).get('MaxImpact', 0),
                    'total_impact': anomaly.get('Impact', {}).get('TotalImpact', 0),
                    'root_causes': anomaly.get('RootCauses', []),
                    'feedback': anomaly.get('Feedback')
                })
        
        return anomalies
        
    except ClientError as e:
        if 'ResourceNotFoundException' in str(e):
            st.info("💡 Set up Cost Anomaly Detection monitors for proactive alerts")
        return None
    except Exception:
        return None


# ============================================================================
# AGGREGATED DATA FUNCTIONS
# ============================================================================

def get_finops_summary() -> Dict:
    """
    Get a complete FinOps summary with real data
    
    Returns:
        Dictionary with all FinOps metrics
    """
    summary = {
        'mode': 'LIVE' if is_live_mode() else 'DEMO',
        'costs': None,
        'budgets': None,
        'forecast': None,
        'recommendations': None,
        'anomalies': None
    }
    
    if is_live_mode():
        with st.spinner("Fetching real AWS cost data..."):
            summary['costs'] = fetch_real_cost_data(30)
            summary['budgets'] = fetch_real_budgets()
            summary['forecast'] = fetch_real_forecast()
            summary['recommendations'] = fetch_real_recommendations()
            summary['monthly_costs'] = fetch_monthly_costs(6)
    
    return summary


# ============================================================================
# STREAMLIT RENDER FUNCTIONS (REAL DATA)
# ============================================================================

def render_real_budget_tracking():
    """Render budget tracking with REAL AWS data"""
    
    st.subheader("📈 Budget Tracking & Forecasting")
    
    if not is_live_mode():
        st.warning("⚠️ Enable Live Mode and connect to AWS to see real budget data")
        return
    
    # Fetch real data
    budgets = fetch_real_budgets()
    costs = fetch_real_cost_data(30)
    forecast = fetch_real_forecast()
    monthly_costs = fetch_monthly_costs(6)
    
    if not budgets and not costs:
        st.info("""
        💡 **No budget data found.** To enable budget tracking:
        1. Create a budget in AWS Budgets console
        2. Or view cost data without budgets below
        """)
        
        # Show costs without budget
        if costs:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Current Month Spend", f"${costs['total_cost']:,.2f}")
            with col2:
                if forecast and forecast.get('forecast_amount'):
                    st.metric("Forecasted Month-End", f"${forecast['forecast_amount']:,.2f}")
            with col3:
                st.metric("Top Service", max(costs['service_costs'], key=costs['service_costs'].get))
        return
    
    # Display budget data
    if budgets:
        # Find main/total budget or use first one
        main_budget = budgets[0]
        for b in budgets:
            if 'total' in b['name'].lower() or 'monthly' in b['name'].lower():
                main_budget = b
                break
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Monthly Budget", f"${main_budget['limit']:,.0f}", 
                     delta=f"{main_budget['utilization']:.1f}% utilized")
        with col2:
            st.metric("Current Spend", f"${main_budget['actual']:,.0f}")
        with col3:
            st.metric("Forecasted Total", f"${main_budget['forecasted']:,.0f}",
                     delta="Under budget" if main_budget['forecasted'] < main_budget['limit'] else "Over budget",
                     delta_color="normal" if main_budget['forecasted'] < main_budget['limit'] else "inverse")
        with col4:
            st.metric("Remaining", f"${main_budget['remaining']:,.0f}",
                     delta=f"{(main_budget['remaining']/main_budget['limit']*100):.1f}% remaining")
        
        # Show all budgets
        if len(budgets) > 1:
            st.markdown("---")
            st.markdown("### All Budgets")
            df = pd.DataFrame(budgets)
            df['limit'] = df['limit'].apply(lambda x: f"${x:,.0f}")
            df['actual'] = df['actual'].apply(lambda x: f"${x:,.0f}")
            df['utilization'] = df['utilization'].apply(lambda x: f"{x:.1f}%")
            st.dataframe(df[['name', 'type', 'limit', 'actual', 'utilization']], use_container_width=True, hide_index=True)
    
    # Monthly cost chart
    if monthly_costs:
        st.markdown("---")
        st.markdown("### Monthly Cost Trend")
        
        import plotly.graph_objects as go
        
        months = [m['month'] for m in monthly_costs]
        costs = [m['cost'] for m in monthly_costs]
        
        fig = go.Figure()
        fig.add_trace(go.Bar(x=months, y=costs, name='Actual Spend', marker_color='#88C0D0'))
        
        if budgets and main_budget:
            budget_line = [main_budget['limit']] * len(months)
            fig.add_trace(go.Scatter(x=months, y=budget_line, name='Budget Limit',
                                    line=dict(color='#dc3545', width=3, dash='dash')))
        
        fig.update_layout(
            height=350,
            yaxis_title='Cost ($)',
            legend=dict(orientation='h', yanchor='bottom', y=1.02)
        )
        st.plotly_chart(fig, use_container_width=True)


def render_real_optimization_recommendations():
    """Render optimization recommendations with REAL AWS data"""
    
    st.subheader("📊 Cost Optimization Recommendations")
    
    if not is_live_mode():
        st.warning("⚠️ Enable Live Mode and connect to AWS to see real recommendations")
        return
    
    # Fetch real recommendations
    compute_recs = fetch_real_recommendations()
    coh_recs = fetch_cost_optimization_hub()
    
    all_recs = []
    total_savings = 0
    
    if compute_recs:
        all_recs.extend(compute_recs)
    
    if coh_recs:
        for rec in coh_recs:
            savings = rec.get('estimated_savings', 0)
            total_savings += savings
            all_recs.append({
                'type': rec['type'],
                'resource_id': rec.get('id', 'N/A'),
                'finding': rec.get('action'),
                'category': rec['type'],
                'savings': savings
            })
    
    if not all_recs:
        st.info("""
        💡 **No optimization recommendations found.**
        
        This could mean:
        - Your resources are already optimized
        - Compute Optimizer is not enabled
        - Cost Optimization Hub is not enabled
        
        **Enable these services:**
        - [AWS Compute Optimizer](https://console.aws.amazon.com/compute-optimizer)
        - [Cost Optimization Hub](https://console.aws.amazon.com/cost-management/home#/cost-optimization-hub)
        """)
        return
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Potential Savings", f"${total_savings:,.0f}/month",
                 delta=f"~${total_savings*12:,.0f}/year")
    with col2:
        st.metric("Optimization Opportunities", len(all_recs))
    with col3:
        # Count by category
        categories = set(r.get('category', 'Other') for r in all_recs)
        st.metric("Categories", len(categories))
    
    st.markdown("---")
    
    # Show recommendations
    st.markdown("### Recommendations")
    
    for i, rec in enumerate(all_recs[:10]):  # Show top 10
        with st.expander(f"**{rec.get('type', 'Unknown')}** - {rec.get('resource_id', 'N/A')}"):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.write(f"**Finding:** {rec.get('finding', 'N/A')}")
                st.write(f"**Current:** {rec.get('current', 'N/A')}")
                st.write(f"**Recommended:** {rec.get('recommended', 'N/A')}")
            with col2:
                if rec.get('savings'):
                    st.metric("Est. Savings", f"${rec['savings']:,.0f}/mo")


def render_real_cost_dashboard():
    """Render cost dashboard with REAL AWS data"""
    
    st.subheader("💰 Real-Time Cost Dashboard")
    
    if not is_live_mode():
        st.warning("⚠️ Enable Live Mode and connect to AWS to see real cost data")
        return
    
    costs = fetch_real_cost_data(30)
    
    if not costs:
        st.error("Unable to fetch cost data. Check your AWS permissions.")
        return
    
    # Summary
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Last 30 Days", f"${costs['total_cost']:,.2f}")
    with col2:
        daily_avg = costs['total_cost'] / 30
        st.metric("Daily Average", f"${daily_avg:,.2f}")
    with col3:
        top_service = max(costs['service_costs'], key=costs['service_costs'].get)
        st.metric("Top Service", top_service[:20])
    
    st.markdown("---")
    
    # Cost by service chart
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Cost by Service")
        import plotly.express as px
        
        service_data = [{'Service': k[:25], 'Cost': v} for k, v in sorted(costs['service_costs'].items(), key=lambda x: x[1], reverse=True)[:10]]
        df = pd.DataFrame(service_data)
        
        fig = px.pie(df, values='Cost', names='Service', hole=0.4)
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Daily Cost Trend")
        import plotly.graph_objects as go
        
        daily_data = costs['daily_costs']
        dates = [d['date'] for d in daily_data]
        daily_costs = [d['cost'] for d in daily_data]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=dates, y=daily_costs, mode='lines+markers', fill='tozeroy'))
        fig.update_layout(height=350, yaxis_title='Cost ($)')
        st.plotly_chart(fig, use_container_width=True)
    
    # Service breakdown table
    st.markdown("### Service Breakdown")
    service_table = [{'Service': k, 'Cost': f"${v:,.2f}", 'Percentage': f"{v/costs['total_cost']*100:.1f}%"} 
                    for k, v in sorted(costs['service_costs'].items(), key=lambda x: x[1], reverse=True)]
    st.dataframe(pd.DataFrame(service_table), use_container_width=True, hide_index=True)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def render_live_finops_dashboard():
    """
    Main entry point - renders complete FinOps dashboard with real data
    """
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); 
                padding: 1rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>💰 FinOps & Cost Management</h2>
        <p style='color: #fef3c7; margin: 0.5rem 0 0 0;'>
            Real-time AWS cost data and optimization insights
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Mode indicator
    if is_live_mode():
        st.success("✅ **LIVE MODE** - Fetching real AWS data")
    else:
        st.warning("⚠️ **DEMO MODE** - Enable Live Mode in sidebar for real data")
    
    # Tabs
    tabs = st.tabs([
        "📊 Cost Dashboard",
        "📈 Budget Tracking", 
        "🎯 Optimization",
        "🔍 Anomalies"
    ])
    
    with tabs[0]:
        render_real_cost_dashboard()
    
    with tabs[1]:
        render_real_budget_tracking()
    
    with tabs[2]:
        render_real_optimization_recommendations()
    
    with tabs[3]:
        st.subheader("🔍 Cost Anomaly Detection")
        
        if not is_live_mode():
            st.warning("Enable Live Mode to view anomalies")
            return
        
        anomalies = fetch_real_anomalies()
        
        if anomalies:
            st.error(f"⚠️ {len(anomalies)} anomalies detected in the last 30 days")
            
            for anomaly in anomalies:
                with st.expander(f"Anomaly: {anomaly['id'][:20]}..."):
                    st.write(f"**Period:** {anomaly['start_date']} to {anomaly['end_date']}")
                    st.write(f"**Impact:** ${anomaly['total_impact']:,.2f}")
                    if anomaly['root_causes']:
                        st.write("**Root Causes:**")
                        for cause in anomaly['root_causes']:
                            st.write(f"- {cause.get('Service', 'Unknown')}: {cause.get('Region', '')}")
        else:
            st.success("✅ No cost anomalies detected in the last 30 days")
            st.info("💡 Set up Cost Anomaly Detection monitors in AWS Console for proactive alerts")


# Export
__all__ = [
    'render_live_finops_dashboard',
    'render_real_budget_tracking',
    'render_real_optimization_recommendations',
    'render_real_cost_dashboard',
    'fetch_real_cost_data',
    'fetch_real_budgets',
    'fetch_real_recommendations',
    'is_live_mode'
]
