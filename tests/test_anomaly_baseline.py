"""
Tests for the independent baseline detector (median + MAD).

Run:  python -m pytest tests/test_anomaly_baseline.py -q
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_detect as det  # noqa: E402


def build_series(values, service='AmazonEC2', end_offset=1):
    """Turn a list of daily costs into {service: {date: cost}}, ending yesterday."""
    end = datetime.now() - timedelta(days=end_offset)
    start = end - timedelta(days=len(values) - 1)
    return {service: {
        (start + timedelta(days=i)).strftime('%Y-%m-%d'): value
        for i, value in enumerate(values)
    }}


def wobble(n, base=100.0):
    """Steady spend with realistic day-to-day noise, median == base."""
    return [base + (i % 5 - 2) * 5.0 for i in range(n)]


# --- It has to catch what matters ------------------------------------------

def test_catches_a_sustained_spike():
    series = build_series(wobble(40) + [1000.0] * 4)
    found = det.detect_statistical_anomalies(series)
    assert len(found) == 1
    assert found[0]['service'] == 'AmazonEC2'
    assert found[0]['days'] == 4
    assert found[0]['total_impact'] == pytest.approx(3600, abs=60)


def test_mad_catches_a_spike_that_mean_plus_stddev_misses():
    """
    The reason this detector uses median+MAD. Four spike days inflate the
    standard deviation enough to pull their own z-score under a 3.5 threshold;
    the median absolute deviation is unmoved.
    """
    values = wobble(40) + [1000.0] * 4
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    stddev = variance ** 0.5
    classic_z = (1000.0 - mean) / stddev
    assert classic_z < 3.5, 'precondition: mean+stddev should miss this'

    found = det.detect_statistical_anomalies(build_series(values))
    assert len(found) == 1, 'median+MAD must still catch it'
    assert found[0]['score'] > 3.5


def test_merges_consecutive_days_into_one_finding():
    series = build_series(wobble(40) + [900.0, 900.0, 900.0])
    found = det.detect_statistical_anomalies(series)
    assert len(found) == 1
    assert found[0]['days'] == 3
    assert found[0]['start_date'] < found[0]['end_date']


def test_separate_spikes_stay_separate():
    series = build_series(wobble(30) + [900.0] + wobble(5) + [900.0])
    found = det.detect_statistical_anomalies(series)
    assert len(found) == 2


def test_flat_series_still_catches_a_jump_without_dividing_by_zero():
    """A perfectly flat service has MAD == 0; the ratio fallback must engage."""
    series = build_series([100.0] * 40 + [500.0])
    found = det.detect_statistical_anomalies(series)
    assert len(found) == 1
    assert found[0]['total_impact'] == pytest.approx(400)


# --- It has to stay quiet otherwise ----------------------------------------

def test_steady_spend_produces_nothing():
    assert det.detect_statistical_anomalies(build_series(wobble(60))) == []


def test_small_dollar_spikes_are_ignored():
    """A 10x jump on a $2/day service is noise, not a finding."""
    series = build_series([2.0 + (i % 3) for i in range(40)] + [20.0])
    assert det.detect_statistical_anomalies(series) == []


def test_cost_drops_are_not_flagged_as_spikes():
    series = build_series(wobble(40) + [5.0, 5.0])
    assert det.detect_statistical_anomalies(series) == []


def test_short_history_is_skipped_not_guessed_at():
    series = build_series(wobble(5) + [900.0])
    assert det.detect_statistical_anomalies(series) == []


def test_old_spikes_outside_the_eval_window_are_not_re_reported():
    """A spike 60 days ago is history, not today's alert."""
    series = build_series([100.0] * 20 + [900.0] * 2 + wobble(60))
    assert det.detect_statistical_anomalies(series) == []


# --- Fetching --------------------------------------------------------------

class FakeCE:
    def __init__(self, pages):
        self.pages = pages

    def get_cost_and_usage(self, **kwargs):
        index = int(kwargs.get('NextPageToken') or 0)
        return self.pages[index]


def day(date, groups):
    return {'TimePeriod': {'Start': date, 'End': date},
            'Groups': [{'Keys': [s], 'Metrics': {'UnblendedCost': {'Amount': str(v)}}}
                       for s, v in groups]}


def test_todays_partial_day_is_excluded():
    """Cost Explorer returns a partial figure for today; including it reads as a crash."""
    today = datetime.now().strftime('%Y-%m-%d')
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    fake = FakeCE([{'ResultsByTime': [day(yesterday, [('AmazonEC2', 100)]),
                                      day(today, [('AmazonEC2', 3)])]}])
    result = det.fetch_daily_service_costs(30, ce_client=fake)
    assert result['status'] == det.STATUS_OK
    assert today not in result['series']['AmazonEC2']
    assert result['series']['AmazonEC2'][yesterday] == 100.0


def test_cost_fetch_paginates():
    d1 = (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d')
    d2 = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    fake = FakeCE([
        {'ResultsByTime': [day(d1, [('AmazonEC2', 10)])], 'NextPageToken': '1'},
        {'ResultsByTime': [day(d2, [('AmazonEC2', 20)])]},
    ])
    result = det.fetch_daily_service_costs(30, ce_client=fake)
    assert result['series']['AmazonEC2'] == {d1: 10.0, d2: 20.0}


def test_cost_fetch_access_denied_is_not_an_empty_estate():
    from botocore.exceptions import ClientError

    class Denied:
        def get_cost_and_usage(self, **kwargs):
            raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'x')

    result = det.fetch_daily_service_costs(30, ce_client=Denied())
    assert result['status'] == det.STATUS_ACCESS_DENIED
    assert result['series'] == {}


# --- Cross-referencing the two detectors -----------------------------------

def test_agreement_between_detectors_is_marked_confirmed():
    spike_day = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')

    class Both:
        def get_anomaly_monitors(self, **kwargs):
            return {'AnomalyMonitors': [{
                'MonitorArn': 'arn:m', 'MonitorName': 'm',
                'MonitorType': 'DIMENSIONAL', 'MonitorDimension': 'SERVICE',
                'CreationDate': (datetime.now() - timedelta(days=60)).strftime(
                    '%Y-%m-%dT%H:%M:%S')}]}

        def get_anomalies(self, **kwargs):
            return {'Anomalies': [{
                'AnomalyId': 'aws-1',
                'AnomalyStartDate': spike_day, 'AnomalyEndDate': spike_day,
                'Impact': {'TotalImpact': 800, 'TotalActualSpend': 900,
                           'TotalExpectedSpend': 100},
                'RootCauses': [{'Service': 'AmazonEC2', 'Region': 'us-east-1'}]}]}

        def get_cost_and_usage(self, **kwargs):
            values = wobble(40) + [900.0]
            end = datetime.now() - timedelta(days=2)
            start = end - timedelta(days=len(values) - 1)
            return {'ResultsByTime': [
                day((start + timedelta(days=i)).strftime('%Y-%m-%d'),
                    [('AmazonEC2', v)])
                for i, v in enumerate(values)]}

    result = det.detect_all(90, ce_client=Both())
    assert result['confirmed_count'] == 2          # both sides marked
    assert all(a['confirmed'] for a in result['anomalies'])
    assert result['anomalies'][0]['confirmed'] is True   # confirmed sort first


def test_baseline_runs_even_when_no_monitor_exists():
    """The whole point: useful output on day one, before AWS has a baseline."""
    class NoMonitor:
        def get_anomaly_monitors(self, **kwargs):
            return {'AnomalyMonitors': []}

        def get_cost_and_usage(self, **kwargs):
            values = wobble(40) + [900.0]
            end = datetime.now() - timedelta(days=2)
            start = end - timedelta(days=len(values) - 1)
            return {'ResultsByTime': [
                day((start + timedelta(days=i)).strftime('%Y-%m-%d'),
                    [('AmazonEC2', v)])
                for i, v in enumerate(values)]}

    result = det.detect_all(90, ce_client=NoMonitor())
    assert result['health']['status'] == det.STATUS_NO_MONITOR
    assert len(result['baseline']) == 1
    assert result['aws'] == []
    assert result['total_impact'] > 0
