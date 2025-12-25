"""
AWS FinOps Data Module
======================
Fetches real cost and usage data from AWS Cost Explorer for all organization accounts.

Features:
- Multi-account cost aggregation
- Service-level breakdown
- AI/ML specific cost tracking
- Cost anomaly detection
- Budget tracking
- Savings recommendations
- Sustainability metrics
- Data pipeline monitoring (Glue, Step Functions, EventBridge, Lambda)

Version: 1.1.0 (2024-12-25)
"""

import streamlit as st
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd


def get_ce_client():
    """Get Cost Explorer client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('ce')


def get_org_client():
    """Get Organizations client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('organizations')


def get_ec2_client():
    """Get EC2 client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('ec2')


def get_cloudwatch_client():
    """Get CloudWatch client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('cloudwatch')


def get_date_range(days: int = 30) -> Tuple[str, str]:
    """Get date range for queries"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    return start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')


def format_cost(cost: float) -> str:
    """Format cost for display"""
    if cost >= 1000000:
        return f"${cost/1000000:.2f}M"
    elif cost >= 1000:
        return f"${cost/1000:.1f}K"
    else:
        return f"${cost:.2f}"


# @st.cache_data - disabled for session state compatibility  # Cache for 1 hour
def fetch_cost_overview(days: int = 30) -> Optional[Dict[str, Any]]:
    """
    Fetch overall cost overview across all accounts
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date, end_date = get_date_range(days)
        
        # Get cost by service
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='DAILY',
            Metrics=['BlendedCost', 'UnblendedCost', 'UsageQuantity'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
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
                service_costs[service] = service_costs.get(service, 0) + cost
            
            daily_costs.append({'date': date, 'cost': day_total})
            total_cost += day_total
        
        # Get cost by account
        account_response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}]
        )
        
        account_costs = {}
        for result in account_response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                account_id = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                account_costs[account_id] = account_costs.get(account_id, 0) + cost
        
        # Sort services by cost
        sorted_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_cost': total_cost,
            'daily_costs': daily_costs,
            'service_costs': dict(sorted_services[:15]),
            'account_costs': account_costs,
            'period_days': days,
            'start_date': start_date,
            'end_date': end_date
        }
        
    except Exception as e:
        st.error(f"Error fetching cost overview: {str(e)}")
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_aiml_costs(days: int = 30) -> Optional[Dict[str, Any]]:
    """
    Fetch AI/ML specific costs (SageMaker, Bedrock, Comprehend, etc.)
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date, end_date = get_date_range(days)
        
        # AI/ML services to track
        aiml_services = [
            'Amazon SageMaker',
            'Amazon Bedrock', 
            'Amazon Comprehend',
            'Amazon Rekognition',
            'Amazon Textract',
            'Amazon Transcribe',
            'Amazon Translate',
            'Amazon Polly',
            'Amazon Lex',
            'Amazon Personalize',
            'Amazon Forecast',
            'Amazon Kendra',
            'AWS DeepLens',
            'AWS DeepRacer'
        ]
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='DAILY',
            Metrics=['BlendedCost'],
            Filter={
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': aiml_services
                }
            },
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        daily_costs = []
        service_costs = {}
        total_cost = 0
        
        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            day_total = 0
            
            for group in result.get('Groups', []):
                service = group['Keys'][0].replace('Amazon ', '').replace('AWS ', '')
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                day_total += cost
                service_costs[service] = service_costs.get(service, 0) + cost
            
            daily_costs.append({'date': date, 'cost': day_total})
            total_cost += day_total
        
        # Also get GPU instance costs (p3, p4, g4, g5 instances)
        gpu_response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            Filter={
                'And': [
                    {'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Compute Cloud - Compute']}},
                    {'Dimensions': {'Key': 'INSTANCE_TYPE_FAMILY', 'Values': ['p3', 'p4', 'p4d', 'p5', 'g4', 'g4dn', 'g5', 'inf1', 'inf2', 'trn1']}}
                ]
            }
        )
        
        gpu_cost = 0
        for result in gpu_response.get('ResultsByTime', []):
            gpu_cost += float(result.get('Total', {}).get('BlendedCost', {}).get('Amount', 0))
        
        return {
            'total_cost': total_cost,
            'daily_costs': daily_costs,
            'service_costs': service_costs,
            'gpu_cost': gpu_cost,
            'period_days': days
        }
        
    except Exception as e:
        # Return partial data if GPU query fails
        return {
            'total_cost': total_cost if 'total_cost' in locals() else 0,
            'daily_costs': daily_costs if 'daily_costs' in locals() else [],
            'service_costs': service_costs if 'service_costs' in locals() else {},
            'gpu_cost': 0,
            'period_days': days,
            'error': str(e)
        }


# @st.cache_data - disabled for session state compatibility  # Cache for 30 minutes
def fetch_cost_anomalies(days: int = 90) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch cost anomalies from AWS Cost Anomaly Detection
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date, end_date = get_date_range(days)
        
        response = ce_client.get_anomalies(
            DateInterval={
                'StartDate': start_date,
                'EndDate': end_date
            },
            MaxResults=50
        )
        
        anomalies = []
        for anomaly in response.get('Anomalies', []):
            impact = anomaly.get('Impact', {})
            root_causes = anomaly.get('RootCauses', [])
            
            anomalies.append({
                'id': anomaly.get('AnomalyId'),
                'start_date': anomaly.get('AnomalyStartDate'),
                'end_date': anomaly.get('AnomalyEndDate'),
                'total_impact': float(impact.get('TotalImpact', 0)),
                'total_actual_spend': float(impact.get('TotalActualSpend', 0)),
                'total_expected_spend': float(impact.get('TotalExpectedSpend', 0)),
                'service': root_causes[0].get('Service', 'Unknown') if root_causes else 'Unknown',
                'region': root_causes[0].get('Region', 'Unknown') if root_causes else 'Unknown',
                'account': root_causes[0].get('LinkedAccount', 'Unknown') if root_causes else 'Unknown',
                'root_causes': root_causes
            })
        
        return sorted(anomalies, key=lambda x: x['total_impact'], reverse=True)
        
    except Exception as e:
        st.warning(f"Cost Anomaly Detection not available: {str(e)}")
        return []


# @st.cache_data - disabled for session state compatibility
def fetch_savings_recommendations() -> Optional[Dict[str, Any]]:
    """
    Fetch savings recommendations from Cost Explorer
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        recommendations = {
            'reserved_instances': [],
            'savings_plans': [],
            'rightsizing': [],
            'total_monthly_savings': 0
        }
        
        # Get RI recommendations
        try:
            ri_response = ce_client.get_reservation_purchase_recommendation(
                Service='Amazon Elastic Compute Cloud - Compute',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            for rec in ri_response.get('Recommendations', []):
                for detail in rec.get('RecommendationDetails', []):
                    savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
                    recommendations['reserved_instances'].append({
                        'instance_type': detail.get('InstanceDetails', {}).get('EC2InstanceDetails', {}).get('InstanceType', 'Unknown'),
                        'recommended_count': detail.get('RecommendedNumberOfInstancesToPurchase', 0),
                        'monthly_savings': savings,
                        'upfront_cost': float(detail.get('UpfrontCost', 0))
                    })
                    recommendations['total_monthly_savings'] += savings
        except:
            pass
        
        # Get Savings Plans recommendations
        try:
            sp_response = ce_client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            for rec in sp_response.get('SavingsPlansPurchaseRecommendation', {}).get('SavingsPlansPurchaseRecommendationDetails', []):
                savings = float(rec.get('EstimatedMonthlySavingsAmount', 0))
                recommendations['savings_plans'].append({
                    'hourly_commitment': float(rec.get('HourlyCommitmentToPurchase', 0)),
                    'monthly_savings': savings,
                    'coverage': float(rec.get('CurrentAverageHourlyOnDemandSpend', 0))
                })
                recommendations['total_monthly_savings'] += savings
        except:
            pass
        
        # Get rightsizing recommendations
        try:
            rs_response = ce_client.get_rightsizing_recommendation(
                Service='AmazonEC2'
            )
            
            for rec in rs_response.get('RightsizingRecommendations', [])[:20]:
                action = rec.get('RightsizingType', 'Unknown')
                current = rec.get('CurrentInstance', {})
                target = rec.get('ModifyRecommendationDetail', {}).get('TargetInstances', [{}])[0] if action == 'Modify' else {}
                savings = float(rec.get('RightsizingRecommendation', {}).get('SavingsPercentage', 0))
                
                recommendations['rightsizing'].append({
                    'action': action,
                    'resource_id': current.get('ResourceId', 'Unknown'),
                    'current_type': current.get('InstanceType', 'Unknown'),
                    'target_type': target.get('ExpectedResourceUtilization', {}).get('EC2ResourceUtilization', {}).get('MaxCpuUtilizationPercentage', 'N/A'),
                    'savings_percentage': savings
                })
        except:
            pass
        
        return recommendations
        
    except Exception as e:
        st.warning(f"Savings recommendations not available: {str(e)}")
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_budget_status() -> Optional[List[Dict[str, Any]]]:
    """
    Fetch AWS Budgets status
    """
    try:
        clients = st.session_state.get('aws_clients', {})
        # Need to create budgets client
        session = st.session_state.get('aws_session')
        if not session:
            return None
        
        budgets_client = session.client('budgets')
        account_id = st.session_state.get('aws_account_id')
        
        response = budgets_client.describe_budgets(AccountId=account_id)
        
        budgets = []
        for budget in response.get('Budgets', []):
            budgets.append({
                'name': budget.get('BudgetName'),
                'type': budget.get('BudgetType'),
                'limit': float(budget.get('BudgetLimit', {}).get('Amount', 0)),
                'actual': float(budget.get('CalculatedSpend', {}).get('ActualSpend', {}).get('Amount', 0)),
                'forecasted': float(budget.get('CalculatedSpend', {}).get('ForecastedSpend', {}).get('Amount', 0)),
                'time_unit': budget.get('TimeUnit')
            })
        
        return budgets
        
    except Exception as e:
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_cost_by_account(days: int = 30) -> Optional[Dict[str, Any]]:
    """
    Fetch cost breakdown by linked account (for chargeback)
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        start_date, end_date = get_date_range(days)
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['BlendedCost', 'UnblendedCost'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'},
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
        )
        
        account_costs = {}
        account_services = {}
        
        for result in response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                account_id = group['Keys'][0]
                service = group['Keys'][1]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                
                account_costs[account_id] = account_costs.get(account_id, 0) + cost
                
                if account_id not in account_services:
                    account_services[account_id] = {}
                account_services[account_id][service] = account_services[account_id].get(service, 0) + cost
        
        # Try to get account names from Organizations
        account_names = {}
        try:
            org_client = get_org_client()
            if org_client:
                paginator = org_client.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for account in page.get('Accounts', []):
                        account_names[account['Id']] = account.get('Name', account['Id'])
        except:
            pass
        
        return {
            'account_costs': account_costs,
            'account_services': account_services,
            'account_names': account_names,
            'total_cost': sum(account_costs.values())
        }
        
    except Exception as e:
        st.error(f"Error fetching account costs: {str(e)}")
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_cost_forecast(days: int = 30) -> Optional[Dict[str, Any]]:
    """
    Fetch cost forecast
    """
    ce_client = get_ce_client()
    if not ce_client:
        return None
    
    try:
        end_date = datetime.now()
        forecast_end = end_date + timedelta(days=days)
        
        response = ce_client.get_cost_forecast(
            TimePeriod={
                'Start': end_date.strftime('%Y-%m-%d'),
                'End': forecast_end.strftime('%Y-%m-%d')
            },
            Metric='BLENDED_COST',
            Granularity='DAILY'
        )
        
        daily_forecast = []
        for item in response.get('ForecastResultsByTime', []):
            daily_forecast.append({
                'date': item['TimePeriod']['Start'],
                'mean': float(item.get('MeanValue', 0)),
                'lower': float(item.get('PredictionIntervalLowerBound', 0)),
                'upper': float(item.get('PredictionIntervalUpperBound', 0))
            })
        
        return {
            'total_forecast': float(response.get('Total', {}).get('Amount', 0)),
            'daily_forecast': daily_forecast
        }
        
    except Exception as e:
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_compute_optimizer_recommendations() -> Optional[Dict[str, Any]]:
    """
    Fetch AWS Compute Optimizer recommendations
    """
    try:
        session = st.session_state.get('aws_session')
        if not session:
            return None
        
        co_client = session.client('compute-optimizer')
        
        recommendations = {
            'ec2': [],
            'ebs': [],
            'lambda': [],
            'total_savings': 0
        }
        
        # EC2 recommendations
        try:
            ec2_response = co_client.get_ec2_instance_recommendations(maxResults=50)
            for rec in ec2_response.get('instanceRecommendations', []):
                finding = rec.get('finding', 'Unknown')
                if finding in ['OVER_PROVISIONED', 'UNDER_PROVISIONED']:
                    current = rec.get('currentInstanceType', 'Unknown')
                    options = rec.get('recommendationOptions', [])
                    if options:
                        best = options[0]
                        savings = float(best.get('projectedUtilizationMetrics', [{}])[0].get('value', 0))
                        recommendations['ec2'].append({
                            'instance_id': rec.get('instanceArn', '').split('/')[-1],
                            'finding': finding,
                            'current_type': current,
                            'recommended_type': best.get('instanceType', 'Unknown'),
                            'savings_opportunity': savings
                        })
        except:
            pass
        
        # Lambda recommendations
        try:
            lambda_response = co_client.get_lambda_function_recommendations(maxResults=50)
            for rec in lambda_response.get('lambdaFunctionRecommendations', []):
                finding = rec.get('finding', 'Unknown')
                if finding != 'Optimized':
                    recommendations['lambda'].append({
                        'function_arn': rec.get('functionArn', 'Unknown'),
                        'finding': finding,
                        'current_memory': rec.get('currentMemorySize', 0),
                        'memory_recommendations': [opt.get('memorySize', 0) for opt in rec.get('memorySizeRecommendationOptions', [])]
                    })
        except:
            pass
        
        return recommendations
        
    except Exception as e:
        return None


def get_finops_data_summary() -> Dict[str, Any]:
    """
    Get a summary of all FinOps data for the dashboard
    """
    is_demo = st.session_state.get('demo_mode', False)
    is_connected = st.session_state.get('aws_connected', False)
    
    if is_demo or not is_connected:
        return {'mode': 'demo'}
    
    summary = {
        'mode': 'live',
        'cost_overview': fetch_cost_overview(30),
        'aiml_costs': fetch_aiml_costs(30),
        'anomalies': fetch_cost_anomalies(90),
        'forecast': fetch_cost_forecast(30),
        'account_costs': fetch_cost_by_account(30)
    }
    
    return summary


# @st.cache_data - disabled for session state compatibility
def fetch_waste_detection() -> Optional[Dict[str, Any]]:
    """
    Detect cloud waste: idle resources, unattached volumes, unused EIPs, etc.
    """
    try:
        ec2 = get_ec2_client()
        if not ec2:
            return None
        
        waste = {
            'unattached_ebs': [],
            'unused_eips': [],
            'idle_rds': [],
            'old_snapshots': [],
            'total_waste': 0
        }
        
        # Unattached EBS volumes
        try:
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )
            
            for vol in volumes.get('Volumes', [])[:50]:
                size = vol.get('Size', 0)
                # Estimate cost: ~$0.10/GB/month for gp2/gp3
                monthly_cost = size * 0.10
                waste['unattached_ebs'].append({
                    'volume_id': vol.get('VolumeId'),
                    'size_gb': size,
                    'volume_type': vol.get('VolumeType'),
                    'created': vol.get('CreateTime'),
                    'monthly_cost': monthly_cost
                })
                waste['total_waste'] += monthly_cost
        except Exception as e:
            print(f"EBS check failed: {e}")
        
        # Unused Elastic IPs
        try:
            addresses = ec2.describe_addresses()
            for addr in addresses.get('Addresses', []):
                if not addr.get('InstanceId') and not addr.get('NetworkInterfaceId'):
                    # Unattached EIP costs ~$3.60/month
                    waste['unused_eips'].append({
                        'allocation_id': addr.get('AllocationId'),
                        'public_ip': addr.get('PublicIp'),
                        'monthly_cost': 3.60
                    })
                    waste['total_waste'] += 3.60
        except Exception as e:
            print(f"EIP check failed: {e}")
        
        # Old snapshots (>90 days)
        try:
            from datetime import timezone
            now = datetime.now(timezone.utc)
            snapshots = ec2.describe_snapshots(OwnerIds=['self'])
            
            for snap in snapshots.get('Snapshots', [])[:100]:
                start_time = snap.get('StartTime')
                if start_time:
                    age_days = (now - start_time).days
                    if age_days > 90:
                        size = snap.get('VolumeSize', 0)
                        # Snapshot cost ~$0.05/GB/month
                        monthly_cost = size * 0.05
                        waste['old_snapshots'].append({
                            'snapshot_id': snap.get('SnapshotId'),
                            'size_gb': size,
                            'age_days': age_days,
                            'description': snap.get('Description', '')[:50],
                            'monthly_cost': monthly_cost
                        })
                        waste['total_waste'] += monthly_cost
        except Exception as e:
            print(f"Snapshot check failed: {e}")
        
        return waste
        
    except Exception as e:
        st.warning(f"Waste detection error: {str(e)}")
        return None


# @st.cache_data - disabled for session state compatibility
def fetch_unit_economics() -> Optional[Dict[str, Any]]:
    """
    Calculate unit economics: cost per request, cost per invocation
    """
    try:
        ce_client = get_ce_client()
        if not ce_client:
            return None
        
        cloudwatch = get_cloudwatch_client()
        if not cloudwatch:
            return None
        
        start_date, end_date = get_date_range(30)
        
        economics = {
            'services': {},
            'total_cost': 0,
            'total_requests': 0
        }
        
        # Get costs by service
        cost_response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        service_costs = {}
        for result in cost_response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                service_costs[service] = cost
                economics['total_cost'] += cost
        
        # Get Lambda invocations
        try:
            lambda_cost = service_costs.get('AWS Lambda', 0)
            
            lambda_invocations = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                StartTime=datetime.strptime(start_date, '%Y-%m-%d'),
                EndTime=datetime.strptime(end_date, '%Y-%m-%d'),
                Period=86400 * 30,  # 30 days
                Statistics=['Sum']
            )
            
            total_invocations = sum(dp.get('Sum', 0) for dp in lambda_invocations.get('Datapoints', []))
            
            if total_invocations > 0:
                economics['services']['Lambda'] = {
                    'cost': lambda_cost,
                    'requests': int(total_invocations),
                    'cost_per_request': lambda_cost / total_invocations if total_invocations else 0,
                    'unit': 'invocations'
                }
                economics['total_requests'] += total_invocations
        except Exception as e:
            print(f"Lambda metrics failed: {e}")
        
        # Get API Gateway requests
        try:
            apigw_cost = service_costs.get('Amazon API Gateway', 0)
            
            apigw_requests = cloudwatch.get_metric_statistics(
                Namespace='AWS/ApiGateway',
                MetricName='Count',
                StartTime=datetime.strptime(start_date, '%Y-%m-%d'),
                EndTime=datetime.strptime(end_date, '%Y-%m-%d'),
                Period=86400 * 30,
                Statistics=['Sum']
            )
            
            total_requests = sum(dp.get('Sum', 0) for dp in apigw_requests.get('Datapoints', []))
            
            if total_requests > 0:
                economics['services']['API Gateway'] = {
                    'cost': apigw_cost,
                    'requests': int(total_requests),
                    'cost_per_request': apigw_cost / total_requests if total_requests else 0,
                    'unit': 'requests'
                }
                economics['total_requests'] += total_requests
        except Exception as e:
            print(f"API Gateway metrics failed: {e}")
        
        # Get S3 requests
        try:
            s3_cost = service_costs.get('Amazon Simple Storage Service', 0)
            
            # S3 doesn't have easy request metrics at account level
            # Estimate based on cost breakdown if available
            economics['services']['S3'] = {
                'cost': s3_cost,
                'requests': 'N/A',
                'cost_per_request': 'N/A',
                'unit': 'storage'
            }
        except:
            pass
        
        return economics
        
    except Exception as e:
        st.warning(f"Unit economics error: {str(e)}")
        return None


# @st.cache_data - disabled for session state compatibility  # Cache for 24 hours
def fetch_sustainability_data() -> Optional[Dict[str, Any]]:
    """
    Estimate carbon footprint based on AWS usage and regional emission factors.
    AWS emission factors: https://sustainability.aboutamazon.com/
    """
    try:
        ce_client = get_ce_client()
        if not ce_client:
            return None
        
        start_date, end_date = get_date_range(30)
        
        # Get cost by region
        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'REGION'}]
        )
        
        # AWS emission factors (kg CO2e per $ spent, estimated)
        # Regions with more renewable energy have lower factors
        emission_factors = {
            'us-east-1': 0.35,      # N. Virginia (high renewables)
            'us-east-2': 0.38,      # Ohio
            'us-west-1': 0.32,      # N. California (high renewables)
            'us-west-2': 0.28,      # Oregon (very high renewables)
            'eu-west-1': 0.30,      # Ireland (high renewables)
            'eu-central-1': 0.40,   # Frankfurt
            'eu-north-1': 0.15,     # Stockholm (very high renewables)
            'ap-southeast-1': 0.50, # Singapore
            'ap-northeast-1': 0.45, # Tokyo
            'default': 0.40
        }
        
        sustainability = {
            'total_emissions': 0,  # kg CO2e
            'by_region': {},
            'total_cost': 0,
            'carbon_intensity': 0,  # kg CO2e per $
            'renewable_percentage': 0
        }
        
        renewable_spend = 0
        total_spend = 0
        
        for result in response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                region = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                
                factor = emission_factors.get(region, emission_factors['default'])
                emissions = cost * factor
                
                sustainability['by_region'][region] = {
                    'cost': cost,
                    'emissions': emissions,
                    'factor': factor
                }
                
                sustainability['total_emissions'] += emissions
                sustainability['total_cost'] += cost
                total_spend += cost
                
                # Estimate renewable percentage based on region
                if region in ['us-west-2', 'eu-west-1', 'eu-north-1', 'us-west-1']:
                    renewable_spend += cost
        
        if sustainability['total_cost'] > 0:
            sustainability['carbon_intensity'] = sustainability['total_emissions'] / sustainability['total_cost']
        
        if total_spend > 0:
            sustainability['renewable_percentage'] = (renewable_spend / total_spend) * 100
        
        return sustainability
        
    except Exception as e:
        st.warning(f"Sustainability data error: {str(e)}")
        return None


def fetch_trusted_advisor_checks() -> Optional[Dict[str, Any]]:
    """
    Fetch AWS Trusted Advisor cost optimization checks
    """
    try:
        session = st.session_state.get('aws_session')
        if not session:
            return None
        
        # Trusted Advisor requires Business or Enterprise support
        support = session.client('support', region_name='us-east-1')
        
        checks = support.describe_trusted_advisor_checks(language='en')
        
        cost_checks = []
        for check in checks.get('checks', []):
            if check.get('category') == 'cost_optimizing':
                cost_checks.append({
                    'id': check.get('id'),
                    'name': check.get('name'),
                    'description': check.get('description')
                })
        
        # Get check results
        results = []
        for check in cost_checks[:10]:  # Limit to 10 checks
            try:
                result = support.describe_trusted_advisor_check_result(
                    checkId=check['id']
                )
                
                status = result.get('result', {}).get('status', 'unknown')
                flagged = len(result.get('result', {}).get('flaggedResources', []))
                
                results.append({
                    'name': check['name'],
                    'status': status,
                    'flagged_resources': flagged
                })
            except:
                pass
        
        return {'checks': results}
        
    except Exception as e:
        # Trusted Advisor requires Business/Enterprise support
        return None


# ==================== DATA PIPELINE FUNCTIONS ====================

def get_glue_client():
    """Get Glue client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('glue')


def get_stepfunctions_client():
    """Get Step Functions client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('stepfunctions')


def get_eventbridge_client():
    """Get EventBridge client from session state"""
    clients = st.session_state.get('aws_clients', {})
    return clients.get('eventbridge')


def fetch_glue_jobs() -> Optional[Dict[str, Any]]:
    """
    Fetch AWS Glue jobs and their recent runs
    """
    try:
        glue = get_glue_client()
        if not glue:
            return None
        
        # Get all jobs
        jobs_response = glue.get_jobs(MaxResults=50)
        jobs = jobs_response.get('Jobs', [])
        
        job_details = []
        total_runs = 0
        succeeded = 0
        failed = 0
        running = 0
        
        for job in jobs[:20]:  # Limit to 20 jobs for performance
            job_name = job.get('Name')
            
            # Get recent runs for this job
            try:
                runs_response = glue.get_job_runs(JobName=job_name, MaxResults=10)
                runs = runs_response.get('JobRuns', [])
                
                job_succeeded = sum(1 for r in runs if r.get('JobRunState') == 'SUCCEEDED')
                job_failed = sum(1 for r in runs if r.get('JobRunState') == 'FAILED')
                job_running = sum(1 for r in runs if r.get('JobRunState') == 'RUNNING')
                
                total_runs += len(runs)
                succeeded += job_succeeded
                failed += job_failed
                running += job_running
                
                last_run = runs[0] if runs else None
                
                job_details.append({
                    'name': job_name,
                    'type': job.get('Command', {}).get('Name', 'glueetl'),
                    'last_run_state': last_run.get('JobRunState', 'N/A') if last_run else 'Never Run',
                    'last_run_time': last_run.get('StartedOn').strftime('%Y-%m-%d %H:%M') if last_run and last_run.get('StartedOn') else 'N/A',
                    'execution_time': last_run.get('ExecutionTime', 0) if last_run else 0,
                    'dpu_seconds': last_run.get('DPUSeconds', 0) if last_run else 0,
                    'recent_runs': len(runs),
                    'success_rate': f"{(job_succeeded/len(runs)*100):.0f}%" if runs else "N/A"
                })
            except Exception as e:
                job_details.append({
                    'name': job_name,
                    'type': job.get('Command', {}).get('Name', 'glueetl'),
                    'last_run_state': 'Unknown',
                    'last_run_time': 'N/A',
                    'execution_time': 0,
                    'dpu_seconds': 0,
                    'recent_runs': 0,
                    'success_rate': 'N/A'
                })
        
        return {
            'total_jobs': len(jobs),
            'jobs': job_details,
            'total_runs': total_runs,
            'succeeded': succeeded,
            'failed': failed,
            'running': running
        }
        
    except Exception as e:
        print(f"Glue fetch error: {e}")
        return None


def fetch_step_functions() -> Optional[Dict[str, Any]]:
    """
    Fetch Step Functions state machines and executions
    """
    try:
        sfn = get_stepfunctions_client()
        if not sfn:
            return None
        
        # List state machines
        machines_response = sfn.list_state_machines(maxResults=50)
        machines = machines_response.get('stateMachines', [])
        
        machine_details = []
        total_executions = 0
        succeeded = 0
        failed = 0
        running = 0
        
        for machine in machines[:15]:  # Limit for performance
            machine_arn = machine.get('stateMachineArn')
            machine_name = machine.get('name')
            
            try:
                # Get recent executions
                exec_response = sfn.list_executions(
                    stateMachineArn=machine_arn,
                    maxResults=20
                )
                executions = exec_response.get('executions', [])
                
                machine_succeeded = sum(1 for e in executions if e.get('status') == 'SUCCEEDED')
                machine_failed = sum(1 for e in executions if e.get('status') == 'FAILED')
                machine_running = sum(1 for e in executions if e.get('status') == 'RUNNING')
                
                total_executions += len(executions)
                succeeded += machine_succeeded
                failed += machine_failed
                running += machine_running
                
                last_exec = executions[0] if executions else None
                
                machine_details.append({
                    'name': machine_name,
                    'type': machine.get('type', 'STANDARD'),
                    'status': 'ACTIVE',
                    'last_execution': last_exec.get('status', 'N/A') if last_exec else 'Never Run',
                    'last_exec_time': last_exec.get('startDate').strftime('%Y-%m-%d %H:%M') if last_exec and last_exec.get('startDate') else 'N/A',
                    'recent_executions': len(executions),
                    'success_rate': f"{(machine_succeeded/len(executions)*100):.0f}%" if executions else "N/A"
                })
            except Exception as e:
                machine_details.append({
                    'name': machine_name,
                    'type': machine.get('type', 'STANDARD'),
                    'status': 'ACTIVE',
                    'last_execution': 'Unknown',
                    'last_exec_time': 'N/A',
                    'recent_executions': 0,
                    'success_rate': 'N/A'
                })
        
        return {
            'total_machines': len(machines),
            'machines': machine_details,
            'total_executions': total_executions,
            'succeeded': succeeded,
            'failed': failed,
            'running': running
        }
        
    except Exception as e:
        print(f"Step Functions fetch error: {e}")
        return None


def fetch_eventbridge_rules() -> Optional[Dict[str, Any]]:
    """
    Fetch EventBridge rules for scheduled automation
    """
    try:
        events = get_eventbridge_client()
        if not events:
            return None
        
        # List rules
        rules_response = events.list_rules(Limit=50)
        rules = rules_response.get('Rules', [])
        
        rule_details = []
        enabled_count = 0
        scheduled_count = 0
        
        for rule in rules:
            is_enabled = rule.get('State') == 'ENABLED'
            is_scheduled = rule.get('ScheduleExpression') is not None
            
            if is_enabled:
                enabled_count += 1
            if is_scheduled:
                scheduled_count += 1
            
            rule_details.append({
                'name': rule.get('Name'),
                'state': rule.get('State', 'UNKNOWN'),
                'schedule': rule.get('ScheduleExpression', 'Event Pattern'),
                'description': rule.get('Description', '')[:50] if rule.get('Description') else 'No description',
                'event_bus': rule.get('EventBusName', 'default')
            })
        
        return {
            'total_rules': len(rules),
            'enabled': enabled_count,
            'scheduled': scheduled_count,
            'rules': rule_details
        }
        
    except Exception as e:
        print(f"EventBridge fetch error: {e}")
        return None


def fetch_lambda_functions() -> Optional[Dict[str, Any]]:
    """
    Fetch Lambda functions summary
    """
    try:
        clients = st.session_state.get('aws_clients', {})
        lambda_client = clients.get('lambda')
        if not lambda_client:
            return None
        
        # List functions
        functions_response = lambda_client.list_functions(MaxItems=50)
        functions = functions_response.get('Functions', [])
        
        function_details = []
        total_code_size = 0
        
        for func in functions[:30]:
            code_size = func.get('CodeSize', 0)
            total_code_size += code_size
            
            function_details.append({
                'name': func.get('FunctionName'),
                'runtime': func.get('Runtime', 'N/A'),
                'memory': func.get('MemorySize', 0),
                'timeout': func.get('Timeout', 0),
                'code_size_mb': round(code_size / (1024 * 1024), 2),
                'last_modified': func.get('LastModified', 'N/A')[:19] if func.get('LastModified') else 'N/A'
            })
        
        return {
            'total_functions': len(functions),
            'functions': function_details,
            'total_code_size_mb': round(total_code_size / (1024 * 1024), 1)
        }
        
    except Exception as e:
        print(f"Lambda fetch error: {e}")
        return None

