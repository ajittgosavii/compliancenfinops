"""
Predictive FinOps - Complete Scene 7 Implementation
AWS re:Invent 2025 Video Script

Features for Scene 7:
1. Cost Anomaly Alert (predicted vs expected)
2. Root Cause Analysis
3. Time to Impact countdown
4. AI-Powered Recommendations
5. Savings Calculation
6. One-Click Remediation
7. Trend Visualization

Duration: Part of Act 4 (3:30 - 4:20)
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time


def get_real_cost_data():
    """Fetch real cost data from AWS Cost Explorer"""
    try:
        clients = st.session_state.get('aws_clients', {})
        ce_client = clients.get('ce')
        
        if not ce_client:
            return None
        
        # Get date range (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # Fetch cost and usage data
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='DAILY',
            Metrics=['BlendedCost', 'UnblendedCost'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
        )
        
        # Process results
        daily_costs = []
        service_costs = {}
        total_cost = 0
        
        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            day_total = 0
            
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                day_total += cost
                
                if service not in service_costs:
                    service_costs[service] = 0
                service_costs[service] += cost
            
            daily_costs.append({
                'date': date,
                'cost': day_total
            })
            total_cost += day_total
        
        # Get cost forecast
        forecast = None
        try:
            forecast_response = ce_client.get_cost_forecast(
                TimePeriod={
                    'Start': end_date.strftime('%Y-%m-%d'),
                    'End': (end_date + timedelta(days=30)).strftime('%Y-%m-%d')
                },
                Metric='BLENDED_COST',
                Granularity='MONTHLY'
            )
            forecast = float(forecast_response.get('Total', {}).get('Amount', 0))
        except Exception as e:
            print(f"Forecast not available: {e}")
        
        # Get cost anomalies
        anomalies = []
        try:
            anomaly_response = ce_client.get_anomalies(
                DateInterval={
                    'StartDate': start_date.strftime('%Y-%m-%d'),
                    'EndDate': end_date.strftime('%Y-%m-%d')
                },
                MaxResults=10
            )
            anomalies = anomaly_response.get('Anomalies', [])
        except Exception as e:
            print(f"Anomalies not available: {e}")
        
        # Sort services by cost
        top_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_cost': total_cost,
            'daily_costs': daily_costs,
            'service_costs': dict(top_services),
            'forecast': forecast,
            'anomalies': anomalies,
            'period': f"{start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}"
        }
        
    except Exception as e:
        st.error(f"Error fetching cost data: {str(e)}")
        return None


def render_live_finops_dashboard(cost_data):
    """Render FinOps dashboard with real AWS data"""
    
    st.success("✅ **Live Mode** - Displaying real AWS Cost Explorer data")
    st.caption(f"📅 Period: {cost_data.get('period', 'Last 30 days')}")
    
    st.markdown("---")
    
    # ============================================================================
    # COST OVERVIEW METRICS
    # ============================================================================
    
    total_cost = cost_data.get('total_cost', 0)
    forecast = cost_data.get('forecast', 0)
    daily_avg = total_cost / 30 if total_cost else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Cost (30 days)",
            f"${total_cost:,.2f}",
            delta=None
        )
    
    with col2:
        st.metric(
            "Daily Average",
            f"${daily_avg:,.2f}",
            delta=None
        )
    
    with col3:
        if forecast:
            st.metric(
                "Forecasted (Next Month)",
                f"${forecast:,.2f}",
                delta=f"{((forecast - total_cost) / total_cost * 100):+.1f}%" if total_cost else None
            )
        else:
            st.metric("Forecasted", "N/A")
    
    with col4:
        anomaly_count = len(cost_data.get('anomalies', []))
        st.metric(
            "Cost Anomalies",
            anomaly_count,
            delta="detected" if anomaly_count > 0 else "none"
        )
    
    st.markdown("---")
    
    # ============================================================================
    # COST TREND CHART
    # ============================================================================
    
    col_chart, col_services = st.columns([2, 1])
    
    with col_chart:
        st.markdown("### 📈 Daily Cost Trend")
        
        daily_costs = cost_data.get('daily_costs', [])
        if daily_costs:
            df = pd.DataFrame(daily_costs)
            df['date'] = pd.to_datetime(df['date'])
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=df['date'],
                y=df['cost'],
                mode='lines+markers',
                name='Daily Cost',
                line=dict(color='#FF9900', width=2),
                marker=dict(size=6)
            ))
            
            # Add average line
            avg_cost = df['cost'].mean()
            fig.add_hline(
                y=avg_cost,
                line_dash="dash",
                line_color="green",
                annotation_text=f"Avg: ${avg_cost:,.2f}"
            )
            
            fig.update_layout(
                xaxis_title="Date",
                yaxis_title="Cost ($)",
                hovermode='x unified',
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No daily cost data available")
    
    with col_services:
        st.markdown("### 🏷️ Top Services")
        
        service_costs = cost_data.get('service_costs', {})
        if service_costs:
            for service, cost in list(service_costs.items())[:7]:
                # Shorten service name
                short_name = service.replace('Amazon ', '').replace('AWS ', '')[:25]
                pct = (cost / total_cost * 100) if total_cost else 0
                
                st.markdown(f"""
                <div style='margin-bottom: 8px;'>
                    <div style='display: flex; justify-content: space-between; font-size: 13px;'>
                        <span>{short_name}</span>
                        <span style='font-weight: bold;'>${cost:,.2f}</span>
                    </div>
                    <div style='background: #eee; border-radius: 4px; height: 8px; margin-top: 3px;'>
                        <div style='background: #FF9900; height: 100%; border-radius: 4px; width: {min(pct, 100):.1f}%;'></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No service breakdown available")
    
    st.markdown("---")
    
    # ============================================================================
    # COST ANOMALIES
    # ============================================================================
    
    anomalies = cost_data.get('anomalies', [])
    if anomalies:
        st.markdown("### 🚨 Detected Cost Anomalies")
        
        for anomaly in anomalies[:5]:
            impact = anomaly.get('Impact', {})
            total_impact = float(impact.get('TotalImpact', 0))
            
            root_causes = anomaly.get('RootCauses', [])
            service = root_causes[0].get('Service', 'Unknown') if root_causes else 'Unknown'
            
            severity = "🔴 High" if total_impact > 100 else "🟡 Medium" if total_impact > 10 else "🟢 Low"
            
            with st.expander(f"{severity} - {service} (${total_impact:,.2f} impact)"):
                st.write(f"**Service:** {service}")
                st.write(f"**Impact:** ${total_impact:,.2f}")
                st.write(f"**Anomaly ID:** {anomaly.get('AnomalyId', 'N/A')}")
                
                if root_causes:
                    st.write("**Root Causes:**")
                    for cause in root_causes:
                        st.write(f"  - {cause.get('Service', 'Unknown')}: {cause.get('Region', 'Unknown')}")
    else:
        st.markdown("### ✅ No Cost Anomalies")
        st.success("No significant cost anomalies detected in the past 30 days.")
    
    st.markdown("---")
    
    # ============================================================================
    # SERVICE BREAKDOWN PIE CHART
    # ============================================================================
    
    st.markdown("### 📊 Cost Distribution by Service")
    
    service_costs = cost_data.get('service_costs', {})
    if service_costs:
        # Prepare data for pie chart
        services = list(service_costs.keys())[:8]
        costs = [service_costs[s] for s in services]
        
        # Add "Other" category
        other_cost = sum(v for k, v in service_costs.items() if k not in services)
        if other_cost > 0:
            services.append("Other")
            costs.append(other_cost)
        
        fig = go.Figure(data=[go.Pie(
            labels=[s.replace('Amazon ', '').replace('AWS ', '') for s in services],
            values=costs,
            hole=0.4,
            marker_colors=px.colors.qualitative.Set2
        )])
        
        fig.update_layout(
            height=400,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2)
        )
        
        st.plotly_chart(fig, use_container_width=True)

def render_predictive_finops_scene():
    """
    Complete Predictive FinOps scene matching video script Scene 7
    Now supports LIVE mode with real AWS Cost Explorer data
    """
    
    st.markdown("## 💰 Predictive FinOps Intelligence")
    st.markdown("*AI-powered cost forecasting and anomaly detection*")
    
    # Check if we're in demo mode or live mode
    is_demo = st.session_state.get('demo_mode', False)
    
    # Get real cost data if in live mode
    if not is_demo and st.session_state.get('aws_connected', False):
        cost_data = get_real_cost_data()
        if cost_data:
            render_live_finops_dashboard(cost_data)
            return
    
    # Fall back to demo mode display
    st.info("📊 **Demo Mode** - Showing sample FinOps data. Connect to AWS and disable Demo Mode to see real cost data.")
    
    st.markdown("---")
    
    # ============================================================================
    # COST ANOMALY ALERT (Demo)
    # ============================================================================
    
    st.markdown("### 🚨 Active Cost Anomaly Alerts")
    
    # Critical Cost Anomaly Card
    st.markdown("""
    <div style='
        background: linear-gradient(135deg, #FF9900 0%, #FF6600 100%);
        color: white;
        padding: 25px;
        border-radius: 10px;
        border: 3px solid #CC5500;
        margin: 20px 0;
        box-shadow: 0 4px 12px rgba(255,153,0,0.4);
        animation: alertPulse 2s infinite;
    '>
        <div style='display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;'>
            <div style='display: flex; align-items: center;'>
                <span style='font-size: 36px; margin-right: 15px;'>🚨</span>
                <div>
                    <h2 style='margin: 0; color: white;'>Predicted Cost Anomaly</h2>
                    <p style='margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;'>AI-detected spending pattern deviation</p>
                </div>
            </div>
            <div style='
                background: rgba(0,0,0,0.3);
                padding: 10px 20px;
                border-radius: 8px;
                text-align: center;
            '>
                <div style='font-size: 12px; opacity: 0.9;'>Confidence</div>
                <div style='font-size: 24px; font-weight: bold;'>94%</div>
            </div>
        </div>
    </div>
    
    <style>
        @keyframes alertPulse {
            0%, 100% { box-shadow: 0 4px 12px rgba(255,153,0,0.4); }
            50% { box-shadow: 0 4px 20px rgba(255,153,0,0.7); }
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Cost Comparison Metrics
    col_cost1, col_cost2, col_cost3, col_cost4 = st.columns(4)
    
    with col_cost1:
        st.markdown("""
        <div style='
            background: white;
            border: 2px solid #00C851;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        '>
            <div style='color: #666; font-size: 14px; margin-bottom: 5px;'>Expected Cost</div>
            <div style='color: #00C851; font-size: 36px; font-weight: bold;'>$67K</div>
            <div style='color: #999; font-size: 12px;'>Normal pattern</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_cost2:
        st.markdown("""
        <div style='
            background: white;
            border: 2px solid #FF6600;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        '>
            <div style='color: #666; font-size: 14px; margin-bottom: 5px;'>Predicted Cost</div>
            <div style='color: #FF6600; font-size: 36px; font-weight: bold;'>$94K</div>
            <div style='color: #FF6600; font-size: 12px; font-weight: bold;'>+$27K (+40%)</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_cost3:
        st.markdown("""
        <div style='
            background: white;
            border: 2px solid #D13212;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        '>
            <div style='color: #666; font-size: 14px; margin-bottom: 5px;'>Time to Impact</div>
            <div style='color: #D13212; font-size: 36px; font-weight: bold;'>4</div>
            <div style='color: #999; font-size: 12px;'>Days remaining</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_cost4:
        st.markdown("""
        <div style='
            background: white;
            border: 2px solid #00A8E1;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        '>
            <div style='color: #666; font-size: 14px; margin-bottom: 5px;'>Potential Savings</div>
            <div style='color: #00A8E1; font-size: 36px; font-weight: bold;'>$18K</div>
            <div style='color: #999; font-size: 12px;'>Per month</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # ============================================================================
    # ROOT CAUSE ANALYSIS
    # ============================================================================
    
    st.markdown("### 🔍 Root Cause Analysis")
    
    col_analysis1, col_analysis2 = st.columns([2, 1])
    
    with col_analysis1:
        # Root cause details
        st.markdown("""
        <div style='
            background: linear-gradient(135deg, #FFF8DC 0%, #FFEAA7 100%);
            border-left: 5px solid #FF9900;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        '>
            <h4 style='margin: 0 0 15px 0; color: #232F3E;'>🎯 Identified Issue</h4>
            <div style='background: white; padding: 15px; border-radius: 5px; margin-bottom: 15px;'>
                <strong style='color: #FF6600; font-size: 16px;'>Misconfigured Auto-Scaling Policy</strong><br>
                <span style='color: #666; font-size: 14px;'>
                    Auto Scaling Group: <code>prod-api-asg-01</code><br>
                    Current Target Utilization: <strong>50%</strong> (too aggressive)<br>
                    Instance Type: c5.4xlarge<br>
                    Average Utilization: 28% (significantly underutilized)
                </span>
            </div>
            
            <h4 style='margin: 15px 0 10px 0; color: #232F3E;'>📊 Impact Analysis</h4>
            <ul style='color: #666; font-size: 14px; margin: 0; padding-left: 20px;'>
                <li><strong>Over-provisioning:</strong> 72% of instances idle during off-peak</li>
                <li><strong>Wasteful scaling:</strong> 12 unnecessary scale-out events/day</li>
                <li><strong>Cost impact:</strong> $27,000/month in excess capacity</li>
                <li><strong>Efficiency:</strong> Only 28% resource utilization vs 70% target</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Historical pattern
        st.markdown("#### 📈 Historical Cost Pattern")
        
        # Create cost trend chart
        dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
        expected_costs = [67000 + (i * 200) + (500 * (i % 7 == 0)) for i in range(30)]
        predicted_costs = expected_costs[:26] + [72000, 78000, 85000, 94000]
        
        fig_trend = go.Figure()
        
        # Expected trend line
        fig_trend.add_trace(go.Scatter(
            x=dates,
            y=expected_costs,
            mode='lines',
            name='Expected Pattern',
            line=dict(color='#00C851', width=2, dash='dash'),
            hovertemplate='Date: %{x}<br>Expected: $%{y:,.0f}<extra></extra>'
        ))
        
        # Predicted trend line (diverges at end)
        fig_trend.add_trace(go.Scatter(
            x=dates,
            y=predicted_costs,
            mode='lines',
            name='Predicted Pattern',
            line=dict(color='#FF6600', width=3),
            fill='tonexty',
            fillcolor='rgba(255,102,0,0.1)',
            hovertemplate='Date: %{x}<br>Predicted: $%{y:,.0f}<extra></extra>'
        ))
        
        # Anomaly zone
        fig_trend.add_vrect(
            x0=dates[26], x1=dates[29],
            fillcolor="rgba(255,0,0,0.1)",
            layer="below", line_width=0,
            annotation_text="Anomaly Zone",
            annotation_position="top left"
        )
        
        fig_trend.update_layout(
            title="30-Day Cost Forecast with Anomaly Detection",
            xaxis_title="Date",
            yaxis_title="Daily Cost (USD)",
            hovermode='x unified',
            height=350,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig_trend, width="stretch")
    
    with col_analysis2:
        # AI Insights Box
        st.markdown("""
        <div style='
            background: linear-gradient(135deg, #E8F4F8 0%, #D5E8F0 100%);
            border: 2px solid #00A8E1;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        '>
            <div style='display: flex; align-items: center; margin-bottom: 15px;'>
                <span style='font-size: 28px; margin-right: 10px;'>🤖</span>
                <h4 style='margin: 0; color: #232F3E;'>AI Insights</h4>
            </div>
            <div style='background: white; padding: 15px; border-radius: 8px; color: #666; font-size: 13px; line-height: 1.6;'>
                <strong style='color: #232F3E;'>Machine Learning Analysis:</strong><br><br>
                • Detected 94% confidence anomaly<br>
                • Pattern started 3 days ago<br>
                • Similar to incident #1247 (Q2 2024)<br>
                • 87% of peers use 65-75% target<br>
                • Predicted escalation in 4 days<br><br>
                <strong style='color: #00A8E1;'>Recommendation confidence: HIGH</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Service breakdown
        st.markdown("""
        <div style='
            background: white;
            border: 2px solid #E1E4E8;
            border-radius: 10px;
            padding: 15px;
        '>
            <h5 style='margin: 0 0 10px 0; color: #232F3E;'>💸 Cost Breakdown</h5>
            <div style='font-size: 13px; color: #666;'>
                <div style='display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #E1E4E8;'>
                    <span>EC2 Instances</span>
                    <strong>$21,400</strong>
                </div>
                <div style='display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #E1E4E8;'>
                    <span>Load Balancer</span>
                    <strong>$3,200</strong>
                </div>
                <div style='display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #E1E4E8;'>
                    <span>Data Transfer</span>
                    <strong>$2,400</strong>
                </div>
                <div style='display: flex; justify-content: space-between; padding: 8px 0; font-weight: bold; color: #FF6600;'>
                    <span>Total Excess</span>
                    <strong>$27,000</strong>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # ============================================================================
    # AI RECOMMENDATION
    # ============================================================================
    
    st.markdown("### 💡 AI-Powered Recommendation")
    
    # Recommendation card
    st.markdown("""
    <div style='
        background: linear-gradient(135deg, #E8F8F5 0%, #D4F1E8 100%);
        border-left: 5px solid #00C851;
        padding: 25px;
        border-radius: 10px;
        margin: 20px 0;
        box-shadow: 0 4px 8px rgba(0,200,81,0.2);
    '>
        <h3 style='margin: 0 0 20px 0; color: #232F3E;'>🎯 Recommended Action</h3>
        
        <div style='
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid #00C851;
            margin-bottom: 15px;
        '>
            <div style='display: flex; align-items: center; justify-content: space-between;'>
                <div>
                    <h4 style='margin: 0 0 10px 0; color: #00C851;'>Adjust Auto-Scaling Target Utilization</h4>
                    <p style='color: #666; font-size: 16px; margin: 0;'>
                        <strong>Change:</strong> 50% → 70% CPU target utilization<br>
                        <strong>Impact:</strong> Reduce instance count by ~35%<br>
                        <strong>Maintains:</strong> Performance SLA (p99 < 200ms)
                    </p>
                </div>
                <div style='text-align: center; padding-left: 20px;'>
                    <div style='font-size: 14px; color: #666;'>Monthly Savings</div>
                    <div style='font-size: 42px; font-weight: bold; color: #00C851;'>$18K</div>
                </div>
            </div>
        </div>
        
        <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 15px;'>
            <div style='background: white; padding: 15px; border-radius: 8px;'>
                <strong style='color: #232F3E;'>✅ Benefits</strong>
                <ul style='color: #666; font-size: 13px; margin: 10px 0 0 0; padding-left: 20px;'>
                    <li>$18,000/month cost reduction</li>
                    <li>Better resource utilization (70% vs 28%)</li>
                    <li>Maintains performance SLAs</li>
                    <li>Reduces carbon footprint by 35%</li>
                </ul>
            </div>
            <div style='background: white; padding: 15px; border-radius: 8px;'>
                <strong style='color: #232F3E;'>⚠️ Considerations</strong>
                <ul style='color: #666; font-size: 13px; margin: 10px 0 0 0; padding-left: 20px;'>
                    <li>Implement during low-traffic window</li>
                    <li>Monitor closely for 48 hours</li>
                    <li>Rollback plan available</li>
                    <li>CloudWatch alarms updated</li>
                </ul>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.info("💡 **Proactive, not reactive.** AI predicts issues before they become budget disasters.")
    
    # Action buttons
    col_action1, col_action2, col_action3, col_action4 = st.columns(4)
    
    with col_action1:
        if st.button("🚀 Apply Recommendation", type="primary", width="stretch", key="apply_finops_rec"):
            st.session_state.finops_remediation_started = True
    
    with col_action2:
        if st.button("📊 View Details", width="stretch", key="view_finops_details"):
            st.info("Opening detailed cost analysis...")
    
    with col_action3:
        if st.button("📅 Schedule Change", width="stretch", key="schedule_finops"):
            st.info("Scheduling during maintenance window...")
    
    with col_action4:
        if st.button("📧 Notify Team", width="stretch", key="notify_finops_team"):
            st.success("Team notification sent!")
    
    # ============================================================================
    # AUTOMATED REMEDIATION
    # ============================================================================
    
    if st.session_state.get('finops_remediation_started', False):
        
        st.markdown("---")
        st.markdown("### 🔄 Applying Cost Optimization")
        
        # Progress bar
        progress_bar = st.progress(0)
        status_container = st.container()
        
        remediation_steps = [
            ("⏳ Validating current configuration...", "Reading Auto Scaling Group settings", 15),
            ("✅ Configuration validated", "Current: 50% CPU target, Min: 4, Max: 20", 25),
            ("⏳ Calculating optimal parameters...", "AI analyzing traffic patterns and performance metrics", 40),
            ("✅ Parameters calculated", "New target: 70% CPU, Min: 3, Max: 14", 55),
            ("⏳ Updating Auto Scaling policy...", "Applying new configuration to prod-api-asg-01", 70),
            ("✅ Policy updated", "Target utilization changed to 70%", 85),
            ("⏳ Updating CloudWatch alarms...", "Adjusting alarm thresholds", 95),
            ("✅ Alarms updated", "New thresholds: Warning: 75%, Critical: 85%", 100),
        ]
        
        # Execute remediation steps
        completed_steps = []
        
        for step, detail, progress in remediation_steps:
            time.sleep(0.7)
            progress_bar.progress(progress)
            
            if step.startswith("⏳"):
                color = "#FF9900"
                bg_color = "#FFF8DC"
            else:
                color = "#00C851"
                bg_color = "#E8F8F5"
            
            completed_steps.append((step, detail, color, bg_color))
            
            with status_container:
                for s, d, c, bc in completed_steps:
                    st.markdown(f"""
                    <div style='
                        background: {bc};
                        border-left: 4px solid {c};
                        padding: 12px 20px;
                        margin: 8px 0;
                        border-radius: 5px;
                    '>
                        <strong style='color: {c}; font-size: 16px;'>{s}</strong><br>
                        <span style='color: #666; font-size: 13px;'>{d}</span>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Success
        st.balloons()
        
        st.success("### ✅ Cost Optimization Applied!")
        
        # Success summary
        st.markdown("""
        <div style='
            background: linear-gradient(135deg, #00C851 0%, #007E33 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin: 20px 0;
            box-shadow: 0 4px 12px rgba(0,200,81,0.3);
        '>
            <h2 style='margin: 0 0 20px 0; color: white; text-align: center;'>
                💰 Cost Anomaly Prevented!
            </h2>
            <div style='
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-top: 20px;
                padding-top: 20px;
                border-top: 1px solid rgba(255,255,255,0.3);
            '>
                <div style='text-align: center;'>
                    <div style='font-size: 14px; opacity: 0.9;'>Monthly Savings</div>
                    <div style='font-size: 32px; font-weight: bold; margin: 10px 0;'>$18,000</div>
                    <div style='font-size: 12px; opacity: 0.8;'>Immediate impact</div>
                </div>
                <div style='text-align: center;'>
                    <div style='font-size: 14px; opacity: 0.9;'>Annual Savings</div>
                    <div style='font-size: 32px; font-weight: bold; margin: 10px 0;'>$216K</div>
                    <div style='font-size: 12px; opacity: 0.8;'>Projected</div>
                </div>
                <div style='text-align: center;'>
                    <div style='font-size: 14px; opacity: 0.9;'>Utilization</div>
                    <div style='font-size: 32px; font-weight: bold; margin: 10px 0;'>70%</div>
                    <div style='font-size: 12px; opacity: 0.8;'>Target achieved</div>
                </div>
                <div style='text-align: center;'>
                    <div style='font-size: 14px; opacity: 0.9;'>Time to Fix</div>
                    <div style='font-size: 32px; font-weight: bold; margin: 10px 0;'>42s</div>
                    <div style='font-size: 12px; opacity: 0.8;'>Fully automated</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Before/After comparison
        st.markdown("#### 📊 Before vs After Comparison")
        
        col_compare1, col_compare2 = st.columns(2)
        
        with col_compare1:
            st.markdown("""
            **❌ Before Optimization:**
            - Daily Cost: $3,133 (projected)
            - Monthly Cost: $94,000
            - CPU Utilization: 28%
            - Wasted Capacity: 72%
            - Instance Count: 18 (avg)
            """)
        
        with col_compare2:
            st.markdown("""
            **✅ After Optimization:**
            - Daily Cost: $2,533
            - Monthly Cost: $76,000
            - CPU Utilization: 70%
            - Wasted Capacity: 30%
            - Instance Count: 12 (avg)
            """)
        
        # Monitoring
        st.markdown("---")
        st.markdown("#### 📡 Continuous Monitoring Active")
        
        st.info("""
        **AI monitoring enabled for next 7 days:**
        - Performance metrics tracked (p50, p95, p99 latency)
        - Auto-scaling behavior monitored
        - Rollback triggers configured
        - Daily cost reports scheduled
        - Alert if utilization exceeds 80% for >15 min
        """)


def render_finops_dashboard_summary():
    """
    Summary dashboard showing multiple cost optimizations
    """
    
    st.markdown("### 💰 FinOps Optimization Summary")
    
    # Summary metrics
    col_sum1, col_sum2, col_sum3, col_sum4 = st.columns(4)
    
    with col_sum1:
        st.metric("Active Anomalies", "3", "-2 from last week")
    
    with col_sum2:
        st.metric("Monthly Savings", "$42K", "+$18K this month")
    
    with col_sum3:
        st.metric("Predictions Made", "147", "94% accuracy")
    
    with col_sum4:
        st.metric("Auto-Optimizations", "23", "This month")
    
    st.markdown("---")
    
    # Recent optimizations table
    st.markdown("#### 📋 Recent Cost Optimizations")
    
    optimizations = [
        {"Date": "2025-11-25", "Type": "Auto-Scaling", "Savings": "$18,000", "Status": "Applied", "Confidence": "94%"},
        {"Date": "2025-11-22", "Type": "Reserved Instances", "Savings": "$12,400", "Status": "Applied", "Confidence": "98%"},
        {"Date": "2025-11-20", "Type": "Storage Tiering", "Savings": "$8,200", "Status": "Applied", "Confidence": "91%"},
        {"Date": "2025-11-18", "Type": "Idle Resources", "Savings": "$3,600", "Status": "Applied", "Confidence": "100%"},
    ]
    
    df_opt = pd.DataFrame(optimizations)
    st.dataframe(df_opt, width="stretch", hide_index=True)


# ============================================================================
# INTEGRATION INSTRUCTIONS
# ============================================================================

"""
TO ADD TO YOUR STREAMLIT APP:

1. Import this module:
   from finops_scene_7_complete import render_predictive_finops_scene

2. Add to your FinOps tab:
   
   with tabs[8]:  # FinOps & Cost Management tab
       st.markdown("## 💰 FinOps & Cost Management")
       
       finops_tabs = st.tabs([
           "🔮 Predictive Analytics",  # NEW TAB
           "Cost Dashboard",
           "Budget Tracking",
           "Optimization Recommendations"
       ])
       
       with finops_tabs[0]:
           render_predictive_finops_scene()

3. Add session state:
   'finops_remediation_started': False,

4. For summary view:
   render_finops_dashboard_summary()

VIDEO RECORDING TIPS:
- Show cost anomaly alert (0:00-0:05)
- Highlight metrics: Expected $67K, Predicted $94K, +40% (0:05-0:10)
- Show root cause analysis (0:10-0:15)
- Display AI recommendation (0:15-0:20)
- Click "Apply Recommendation" (0:20)
- Watch automated remediation (0:20-0:30)
- Total scene: ~30 seconds

KEY FEATURES:
✅ Cost anomaly alert with prediction
✅ Expected vs Predicted comparison ($67K vs $94K, +40%)
✅ Root cause: Misconfigured auto-scaling
✅ Time to impact: 4 days
✅ AI recommendation: Adjust 50%→70% utilization
✅ Savings calculation: $18,000/month
✅ One-click automated fix
✅ Before/After comparison
✅ 42-second resolution time

CUSTOMIZATION:
- Change cost values (lines 64-119)
- Adjust remediation timing (line 403)
- Modify savings amount (line 245)
- Change confidence percentage (line 38)
"""
