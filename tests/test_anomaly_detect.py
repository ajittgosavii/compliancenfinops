"""
Tests for finops_anomaly_detect.

The point of these is the distinction the old code lost: "we looked and found
nothing" must never be reported the same way as "we were not allowed to look"
or "nothing is watching in the first place".

Run:  python -m pytest tests/test_anomaly_detect.py -q
"""

import os
import sys
from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_detect as det  # noqa: E402


def denied(operation='GetAnomalies'):
    return ClientError(
        {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, operation)


class FakeCE:
    """Minimal stand-in for a boto3 Cost Explorer client."""

    def __init__(self, monitors=None, anomaly_pages=None,
                 monitors_raise=None, anomalies_raise=None):
        self._monitors = monitors if monitors is not None else []
        self._anomaly_pages = anomaly_pages or [{'Anomalies': []}]
        self._monitors_raise = monitors_raise
        self._anomalies_raise = anomalies_raise
        self.calls = []

    def get_anomaly_monitors(self, **kwargs):
        self.calls.append(('monitors', kwargs))
        if self._monitors_raise:
            raise self._monitors_raise
        return {'AnomalyMonitors': self._monitors}

    def get_anomalies(self, **kwargs):
        self.calls.append(('anomalies', kwargs))
        if self._anomalies_raise:
            raise self._anomalies_raise
        index = 0
        if kwargs.get('NextPageToken'):
            index = int(kwargs['NextPageToken'])
        return self._anomaly_pages[index]


def monitor(age_days=30, name='m1'):
    return {
        'MonitorArn': 'arn:aws:ce::1:anomalymonitor/' + name,
        'MonitorName': name,
        'MonitorType': 'DIMENSIONAL',
        'MonitorDimension': 'SERVICE',
        'CreationDate': (datetime.now() - timedelta(days=age_days)).strftime(
            '%Y-%m-%dT%H:%M:%S'),
    }


def anomaly(impact, service='AmazonEC2', anomaly_id='a1'):
    return {
        'AnomalyId': anomaly_id,
        'AnomalyStartDate': '2026-09-01',
        'AnomalyEndDate': '2026-09-02',
        'Impact': {'TotalImpact': impact, 'TotalActualSpend': impact * 2,
                   'TotalExpectedSpend': impact, 'MaxImpact': impact},
        'RootCauses': [{'Service': service, 'Region': 'us-east-1',
                        'LinkedAccount': '111111111111'}],
    }


# --- The regression this module exists to prevent --------------------------

def test_access_denied_is_not_an_all_clear():
    """The old code turned AccessDenied into [] and rendered 'No anomalies'."""
    result = det.fetch_anomalies(90, ce_client=FakeCE(anomalies_raise=denied()))
    assert result['status'] == det.STATUS_ACCESS_DENIED
    assert result['anomalies'] == []
    assert 'not an all-clear' in result['message']


def test_denied_health_reports_unknown_not_zero():
    health = det.detector_health(
        90, ce_client=FakeCE(monitors_raise=denied('GetAnomalyMonitors')))
    assert health['status'] == det.STATUS_ACCESS_DENIED
    assert health['trustworthy'] is False
    assert health['anomaly_count'] is None       # unknown, never 0
    assert health['verdict'] == 'Detector status unknown'


def test_no_monitor_is_reported_as_no_detector():
    health = det.detector_health(90, ce_client=FakeCE(monitors=[]))
    assert health['status'] == det.STATUS_NO_MONITOR
    assert health['trustworthy'] is False
    assert health['anomaly_count'] is None
    assert health['verdict'] == 'No detector configured'


def test_no_monitor_does_not_even_query_anomalies():
    """Pointless call - and its empty result is what produced the false all-clear."""
    fake = FakeCE(monitors=[])
    det.detector_health(90, ce_client=fake)
    assert [c[0] for c in fake.calls] == ['monitors']


def test_warming_up_monitor_is_not_trustworthy():
    fake = FakeCE(monitors=[monitor(age_days=3)])
    health = det.detector_health(90, ce_client=fake)
    assert health['status'] == det.STATUS_WARMING_UP
    assert health['trustworthy'] is False
    assert health['verdict'] == 'Baseline still forming'


def test_not_connected_is_distinct_from_empty():
    result = det.fetch_anomalies(90, ce_client=None)
    # No session state in a bare test process, so this exercises the no-client path
    assert result['status'] == det.STATUS_NO_CLIENT


# --- The happy path still has to work --------------------------------------

def test_healthy_detector_reports_count_and_sorts_by_impact():
    fake = FakeCE(
        monitors=[monitor(age_days=45)],
        anomaly_pages=[{'Anomalies': [anomaly(50, 'AmazonS3', 'small'),
                                      anomaly(900, 'AmazonEC2', 'big')]}],
    )
    health = det.detector_health(90, ce_client=fake)
    assert health['status'] == det.STATUS_OK
    assert health['trustworthy'] is True
    assert health['anomaly_count'] == 2
    assert [a['id'] for a in health['anomalies']] == ['big', 'small']
    assert health['anomalies'][0]['service'] == 'AmazonEC2'


def test_clean_account_says_no_anomalies_only_when_it_can_prove_it():
    fake = FakeCE(monitors=[monitor(age_days=45)], anomaly_pages=[{'Anomalies': []}])
    health = det.detector_health(90, ce_client=fake)
    assert health['trustworthy'] is True
    assert health['anomaly_count'] == 0
    assert health['verdict'] == 'No anomalies detected'


def test_pagination_collects_every_page():
    """The old code passed MaxResults=50 and ignored NextPageToken."""
    fake = FakeCE(
        monitors=[monitor(age_days=45)],
        anomaly_pages=[
            {'Anomalies': [anomaly(10, anomaly_id='p1')], 'NextPageToken': '1'},
            {'Anomalies': [anomaly(20, anomaly_id='p2')]},
        ],
    )
    result = det.fetch_anomalies(90, ce_client=fake)
    assert {a['id'] for a in result['anomalies']} == {'p1', 'p2'}


def test_min_impact_filter():
    fake = FakeCE(anomaly_pages=[{'Anomalies': [anomaly(5, anomaly_id='tiny'),
                                                anomaly(500, anomaly_id='real')]}])
    result = det.fetch_anomalies(90, ce_client=fake, min_impact=100)
    assert [a['id'] for a in result['anomalies']] == ['real']


# --- Writes -----------------------------------------------------------------

def test_create_monitor_sends_service_dimension():
    captured = {}

    class Writer(FakeCE):
        def create_anomaly_monitor(self, **kwargs):
            captured.update(kwargs)
            return {'MonitorArn': 'arn:new'}

    result = det.create_anomaly_monitor('my-monitor', ce_client=Writer())
    assert result['status'] == det.STATUS_OK
    assert result['arn'] == 'arn:new'
    assert captured['AnomalyMonitor']['MonitorType'] == 'DIMENSIONAL'
    assert captured['AnomalyMonitor']['MonitorDimension'] == 'SERVICE'


def test_create_subscription_uses_threshold_expression_not_deprecated_field():
    captured = {}

    class Writer(FakeCE):
        def create_anomaly_subscription(self, **kwargs):
            captured.update(kwargs)
            return {'SubscriptionArn': 'arn:sub'}

    det.create_anomaly_subscription('arn:mon', 'a@b.com', 250.0, ce_client=Writer())
    sub = captured['AnomalySubscription']
    assert 'Threshold' not in sub                      # deprecated flat field
    assert sub['ThresholdExpression']['Dimensions']['Values'] == ['250.0']
    assert sub['Frequency'] == 'DAILY'                 # EMAIL cannot use IMMEDIATE
    assert sub['Subscribers'][0]['Type'] == 'EMAIL'


def test_write_failures_come_back_as_status_not_exceptions():
    class Writer(FakeCE):
        def create_anomaly_monitor(self, **kwargs):
            raise denied('CreateAnomalyMonitor')

    result = det.create_anomaly_monitor(ce_client=Writer())
    assert result['status'] == det.STATUS_ACCESS_DENIED
