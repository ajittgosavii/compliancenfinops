"""Harness script driven by tests/test_anomaly_page_render.py via AppTest."""

import os
import sys
from datetime import datetime, timedelta

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_detect as det
import finops_anomaly_page as page

SCENARIO = os.environ.get('ANOMALY_SCENARIO', 'findings')


def series_for(service, spike=True):
    values = [100.0 + (i % 5 - 2) * 5.0 for i in range(40)]
    if spike:
        values += [900.0]
    end = datetime.now() - timedelta(days=1)
    start = end - timedelta(days=len(values) - 1)
    return {service: {(start + timedelta(days=i)).strftime('%Y-%m-%d'): v
                      for i, v in enumerate(values)}}


def build(scenario):
    base = {'aws': [], 'baseline': [], 'series': {}, 'confirmed_count': 0,
            'total_impact': 0.0, 'baseline_status': det.STATUS_OK,
            'baseline_message': '3 service(s) over 90 days.', 'anomalies': []}

    if scenario == 'denied':
        base['health'] = {'status': det.STATUS_ACCESS_DENIED, 'monitors': [],
                          'message': 'IAM denied the call (AccessDeniedException).',
                          'verdict': 'Detector status unknown'}
        base['baseline_status'] = det.STATUS_ACCESS_DENIED
        return base

    if scenario == 'no_monitor':
        base['health'] = {'status': det.STATUS_NO_MONITOR, 'monitors': [],
                          'message': 'No Cost Anomaly Detection monitor exists.',
                          'verdict': 'No detector configured'}
        return base

    if scenario == 'clean':
        base['health'] = {'status': det.STATUS_OK,
                          'monitors': [{'name': 'm1', 'type': 'DIMENSIONAL',
                                        'dimension': 'SERVICE', 'age_days': 40,
                                        'last_evaluated': datetime.now()}],
                          'message': '1 monitor(s) active.',
                          'verdict': 'No anomalies detected'}
        return base

    anomaly = {'id': 'baseline:AmazonEC2:2026-09-20', 'source': 'baseline',
               'service': 'AmazonEC2', 'region': 'all', 'account': 'all',
               'start_date': '2026-09-20', 'end_date': '2026-09-21',
               'total_impact': 1800.0, 'total_actual_spend': 2000.0,
               'total_expected_spend': 200.0, 'max_impact': 900.0,
               'score': 120.0, 'confirmed': True, 'days': 2,
               'root_causes': [{'Service': 'AmazonEC2', 'Region': 'us-east-1'}]}
    base['health'] = {'status': det.STATUS_OK,
                      'monitors': [{'name': 'm1', 'type': 'DIMENSIONAL',
                                    'dimension': 'SERVICE', 'age_days': 40,
                                    'last_evaluated': datetime.now()}],
                      'message': '1 monitor(s) active.',
                      'verdict': '1 anomaly/anomalies detected'}
    base['anomalies'] = [anomaly]
    base['confirmed_count'] = 1
    base['total_impact'] = 1800.0
    base['series'] = series_for('AmazonEC2')
    return base


result = build(SCENARIO)

page.render_verdict(result)
page.render_detector_health(result)
if result['anomalies']:
    page.render_anomaly_table(result, {})
    for item in result['anomalies']:
        page.render_anomaly_detail(item, result['series'], {})
