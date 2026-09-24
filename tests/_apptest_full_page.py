"""Harness: drives the real render_anomaly_page() with detection stubbed out."""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_detect as det
import finops_anomaly_page as page

SCENARIO = os.environ.get('ANOMALY_SCENARIO', 'findings')


def series():
    values = [100.0 + (i % 5 - 2) * 5.0 for i in range(40)] + [900.0, 900.0]
    end = datetime.now() - timedelta(days=1)
    start = end - timedelta(days=len(values) - 1)
    return {'AmazonEC2': {(start + timedelta(days=i)).strftime('%Y-%m-%d'): v
                          for i, v in enumerate(values)}}


def fake_detect_all(days=90, ce_client=None, sensitivity=3.5, min_impact=25.0):
    if SCENARIO == 'no_monitor':
        return {'anomalies': [], 'aws': [], 'baseline': [], 'series': {},
                'confirmed_count': 0, 'total_impact': 0.0,
                'baseline_status': det.STATUS_OK,
                'baseline_message': '4 service(s) over 90 days.',
                'health': {'status': det.STATUS_NO_MONITOR, 'monitors': [],
                           'message': 'No monitor exists.',
                           'verdict': 'No detector configured'}}

    data = series()
    dates = sorted(data['AmazonEC2'])
    anomaly = {'id': 'baseline:AmazonEC2:' + dates[-2], 'source': 'baseline',
               'service': 'AmazonEC2', 'region': 'all', 'account': '111111111111',
               'start_date': dates[-2], 'end_date': dates[-1],
               'total_impact': 1600.0, 'total_actual_spend': 1800.0,
               'total_expected_spend': 200.0, 'max_impact': 800.0,
               'score': 108.0, 'confirmed': True, 'days': 2, 'root_causes': []}
    return {'anomalies': [anomaly], 'aws': [], 'baseline': [anomaly],
            'series': data, 'confirmed_count': 1, 'total_impact': 1600.0,
            'baseline_status': det.STATUS_OK,
            'baseline_message': '4 service(s) over 90 days.',
            'health': {'status': det.STATUS_OK,
                       'monitors': [{'name': 'finops-service-monitor',
                                     'type': 'DIMENSIONAL', 'dimension': 'SERVICE',
                                     'age_days': 40,
                                     'last_evaluated': datetime.now()}],
                       'message': '1 monitor(s) active.',
                       'verdict': '1 anomaly/anomalies detected'}}


det.detect_all = fake_detect_all
page.render_anomaly_page()
