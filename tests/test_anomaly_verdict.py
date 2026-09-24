"""
Tests for the page verdict.

One rule under test above all others: the page must never render a green
all-clear unless both detectors actually looked and actually found nothing.

Run:  python -m pytest tests/test_anomaly_verdict.py -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_detect as det  # noqa: E402
import finops_anomaly_page as page  # noqa: E402


def result(health_status, anomalies=None, baseline_status=det.STATUS_OK,
           confirmed=0, message=''):
    anomalies = anomalies or []
    return {
        'anomalies': anomalies,
        'aws': [], 'baseline': [],
        'health': {'status': health_status, 'message': message,
                   'verdict': '', 'monitors': []},
        'baseline_status': baseline_status,
        'baseline_message': message,
        'confirmed_count': confirmed,
        'total_impact': sum(a.get('total_impact', 0) for a in anomalies),
        'series': {},
    }


def anomaly(impact=500.0, service='AmazonEC2', confirmed=False):
    return {'id': 'x', 'service': service, 'total_impact': impact,
            'total_expected_spend': 100.0, 'total_actual_spend': 100.0 + impact,
            'start_date': '2026-09-01', 'end_date': '2026-09-02',
            'source': 'aws_cad', 'confirmed': confirmed}


# --- The rule --------------------------------------------------------------

def test_access_denied_never_renders_as_clear():
    level, headline, _ = page.verdict_for(result(det.STATUS_ACCESS_DENIED))
    assert level == 'unknown'
    assert 'denied' in headline.lower()


def test_no_monitor_and_no_baseline_is_not_clear():
    level, headline, detail = page.verdict_for(
        result(det.STATUS_NO_MONITOR, baseline_status=det.STATUS_ACCESS_DENIED))
    assert level == 'unknown'
    assert 'Nothing is watching' in headline
    assert 'not an all-clear' in detail


def test_not_connected_is_not_clear():
    level, headline, _ = page.verdict_for(result(det.STATUS_NO_CLIENT))
    assert level == 'unknown'
    assert 'Not connected' in headline


def test_error_is_not_clear():
    level, _, _ = page.verdict_for(result(det.STATUS_ERROR, message='boom'))
    assert level == 'unknown'


def test_warming_up_is_not_clear():
    level, headline, _ = page.verdict_for(result(det.STATUS_WARMING_UP))
    assert level == 'warning'
    assert 'baseline' in headline.lower()


def test_no_monitor_but_baseline_ran_is_a_warning_not_clear():
    level, headline, _ = page.verdict_for(result(det.STATUS_NO_MONITOR))
    assert level == 'warning'
    assert 'No AWS monitor' in headline


def test_aws_clean_but_baseline_unavailable_is_a_warning():
    level, _, _ = page.verdict_for(
        result(det.STATUS_OK, baseline_status=det.STATUS_ERROR))
    assert level == 'warning'


def test_only_a_genuine_double_clean_is_green():
    level, headline, detail = page.verdict_for(result(det.STATUS_OK))
    assert level == 'clear'
    assert headline == 'No cost anomalies detected'
    assert 'agree' in detail


def test_every_non_ok_status_avoids_the_clear_level():
    """Exhaustive guard - a new status must not silently default to green."""
    for status in (det.STATUS_NO_CLIENT, det.STATUS_NO_MONITOR,
                   det.STATUS_ACCESS_DENIED, det.STATUS_ERROR,
                   det.STATUS_WARMING_UP):
        level, _, _ = page.verdict_for(result(status))
        assert level != 'clear', '{0} rendered as an all-clear'.format(status)


# --- Findings --------------------------------------------------------------

def test_findings_are_reported_with_total_impact():
    level, headline, _ = page.verdict_for(
        result(det.STATUS_OK, [anomaly(1500), anomaly(600)]))
    assert level == 'critical'
    assert '2 cost anomalies' in headline
    assert '$2.1K' in headline


def test_single_anomaly_is_grammatical():
    _, headline, _ = page.verdict_for(result(det.STATUS_OK, [anomaly(200)]))
    assert '1 cost anomaly,' in headline


def test_small_single_finding_is_a_warning_not_critical():
    level, _, _ = page.verdict_for(result(det.STATUS_OK, [anomaly(200)]))
    assert level == 'warning'


def test_confirmation_by_both_detectors_escalates_and_is_stated():
    level, _, detail = page.verdict_for(
        result(det.STATUS_OK, [anomaly(200, confirmed=True)], confirmed=1))
    assert level == 'critical'
    assert 'confirmed by both' in detail


def test_findings_without_a_monitor_say_where_they_came_from():
    _, _, detail = page.verdict_for(result(det.STATUS_NO_MONITOR, [anomaly(900)]))
    assert 'AWS has no monitor' in detail


def test_findings_are_reported_even_while_aws_is_warming_up():
    level, headline, detail = page.verdict_for(
        result(det.STATUS_WARMING_UP, [anomaly(900)]))
    assert level in ('warning', 'critical')
    assert '1 cost anomaly' in headline
    assert 'still forming' in detail


# --- Formatting ------------------------------------------------------------

def test_cost_formatting():
    assert page.format_cost(12.5) == '$12.50'
    assert page.format_cost(2500) == '$2.5K'
    assert page.format_cost(3_400_000) == '$3.40M'
