"""
FinOps Anomaly Detection - detection substrate
==============================================
Talks to AWS Cost Anomaly Detection and computes an independent statistical
baseline from Cost Explorer.

Design rules for this module:
  * Pure functions. Nothing here renders Streamlit UI or raises on AWS errors.
    Every entry point returns a dict with an explicit 'status', so the caller
    can tell "no anomalies" apart from "we were not allowed to look".
  * No silent all-clear. An AccessDenied is STATUS_ACCESS_DENIED, never [].

AWS Cost Anomaly Detection only reports anomalies for monitors you have
created, and only from the monitor's creation date forward (it needs roughly
10 days to establish a baseline). An account with no monitor returns an empty
list forever, which is why detector_health() reports the monitor state first.

Version: 1.0.0
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import streamlit as st

try:
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:  # boto3 always ships botocore, but keep the module importable
    ClientError = BotoCoreError = Exception


# --- Status vocabulary -----------------------------------------------------

STATUS_OK = 'ok'                        # the call worked, data is trustworthy
STATUS_NO_CLIENT = 'no_client'          # not connected to AWS
STATUS_NO_MONITOR = 'no_monitor'        # connected, but nothing is being watched
STATUS_WARMING_UP = 'warming_up'        # monitor exists but has no baseline yet
STATUS_ACCESS_DENIED = 'access_denied'  # IAM said no - NOT the same as "none found"
STATUS_ERROR = 'error'                  # anything else

# AWS needs roughly this long after monitor creation before it reports anything
BASELINE_DAYS = 10

_DENIED_CODES = {
    'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
    'AuthFailure', 'UnrecognizedClientException',
}


def get_ce_client(ce_client=None):
    """Cost Explorer client - passed in (testable) or from session state."""
    if ce_client is not None:
        return ce_client
    clients = st.session_state.get('aws_clients') or {}
    return clients.get('ce')


def _classify(exc: Exception) -> Dict[str, str]:
    """Turn a boto exception into a status + a message a human can act on."""
    code = ''
    if isinstance(exc, ClientError):
        code = (getattr(exc, 'response', None) or {}).get('Error', {}).get('Code', '')
    if code in _DENIED_CODES:
        return {
            'status': STATUS_ACCESS_DENIED,
            'message': (
                "IAM denied the call ({0}). This is not an all-clear - add "
                "ce:GetAnomalies / ce:GetAnomalyMonitors to the role."
            ).format(code),
        }
    return {
        'status': STATUS_ERROR,
        'message': "{0}: {1}".format(code or type(exc).__name__, exc),
    }


def _window(days: int) -> tuple:
    end = datetime.now()
    start = end - timedelta(days=days)
    return start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d')


def _date_range(days: int) -> Dict[str, str]:
    """DateInterval for get_anomalies - StartDate/EndDate."""
    start, end = _window(days)
    return {'StartDate': start, 'EndDate': end}


def _time_period(days: int) -> Dict[str, str]:
    """
    TimePeriod for get_cost_and_usage - Start/End.

    Cost Explorer uses two different shapes for what is the same idea, and
    sending the anomaly shape here fails validation outright.
    """
    start, end = _window(days)
    return {'Start': start, 'End': end}


def _as_date(value: Any) -> Optional[datetime]:
    """Cost Explorer returns dates as strings; be tolerant about the shape."""
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).replace('Z', '')
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(text[:26], fmt)
        except ValueError:
            continue
    return None


# --- Monitors --------------------------------------------------------------

def get_anomaly_monitors(ce_client=None) -> Dict[str, Any]:
    """
    List the Cost Anomaly Detection monitors on this account.

    Returns {'status', 'monitors': [...], 'message'}. An empty monitor list is
    reported as STATUS_NO_MONITOR, because that is the single most common
    reason an anomaly page looks perfect while seeing nothing.
    """
    client = get_ce_client(ce_client)
    if client is None:
        return {'status': STATUS_NO_CLIENT, 'monitors': [],
                'message': 'Not connected to AWS.'}

    monitors = []
    token = None
    try:
        while True:
            kwargs = {'MaxResults': 100}
            if token:
                kwargs['NextPageToken'] = token
            response = client.get_anomaly_monitors(**kwargs)
            for monitor in response.get('AnomalyMonitors', []):
                created = _as_date(monitor.get('CreationDate'))
                age_days = (datetime.now() - created).days if created else None
                monitors.append({
                    'arn': monitor.get('MonitorArn'),
                    'name': monitor.get('MonitorName', 'Unnamed'),
                    'type': monitor.get('MonitorType', 'Unknown'),
                    'dimension': monitor.get('MonitorDimension'),
                    'created': created,
                    'age_days': age_days,
                    'last_evaluated': _as_date(monitor.get('LastEvaluatedDate')),
                    'dimensional_value_count': monitor.get('DimensionalValueCount'),
                    'warming_up': age_days is not None and age_days < BASELINE_DAYS,
                })
            token = response.get('NextPageToken')
            if not token:
                break
    except Exception as exc:
        result = _classify(exc)
        result['monitors'] = []
        return result

    if not monitors:
        return {
            'status': STATUS_NO_MONITOR, 'monitors': [],
            'message': 'No Cost Anomaly Detection monitor exists on this account. '
                       'AWS is not watching anything, so get_anomalies() returns an '
                       'empty list no matter what your spend does.',
        }

    if all(m['warming_up'] for m in monitors):
        youngest = min((m['age_days'] for m in monitors if m['age_days'] is not None),
                       default=0)
        return {
            'status': STATUS_WARMING_UP, 'monitors': monitors,
            'message': 'Monitor exists but is {0} day(s) old. AWS needs about {1} days '
                       'to build a baseline before it reports anomalies.'.format(
                           youngest, BASELINE_DAYS),
        }

    return {'status': STATUS_OK, 'monitors': monitors,
            'message': '{0} monitor(s) active.'.format(len(monitors))}


# --- Anomalies -------------------------------------------------------------

def fetch_anomalies(days: int = 90, ce_client=None,
                    min_impact: float = 0.0) -> Dict[str, Any]:
    """
    Fetch anomalies AWS has already detected, paginated (the old code capped at 50).

    Returns {'status', 'anomalies': [...], 'message'}.
    """
    client = get_ce_client(ce_client)
    if client is None:
        return {'status': STATUS_NO_CLIENT, 'anomalies': [],
                'message': 'Not connected to AWS.'}

    anomalies = []
    token = None
    try:
        while True:
            kwargs = {'DateInterval': _date_range(days), 'MaxResults': 100}
            if token:
                kwargs['NextPageToken'] = token
            response = client.get_anomalies(**kwargs)

            for raw in response.get('Anomalies', []):
                impact = raw.get('Impact', {}) or {}
                causes = raw.get('RootCauses', []) or []
                first = causes[0] if causes else {}
                total_impact = float(impact.get('TotalImpact', 0) or 0)
                if total_impact < min_impact:
                    continue
                anomalies.append({
                    'id': raw.get('AnomalyId'),
                    'source': 'aws_cad',
                    'start_date': raw.get('AnomalyStartDate'),
                    'end_date': raw.get('AnomalyEndDate'),
                    'total_impact': total_impact,
                    'total_actual_spend': float(impact.get('TotalActualSpend', 0) or 0),
                    'total_expected_spend': float(impact.get('TotalExpectedSpend', 0) or 0),
                    'max_impact': float(impact.get('MaxImpact', 0) or 0),
                    'service': first.get('Service', 'Unknown'),
                    'region': first.get('Region', 'Unknown'),
                    'account': first.get('LinkedAccount', 'Unknown'),
                    'usage_type': first.get('UsageType'),
                    'root_causes': causes,
                    'feedback': raw.get('Feedback'),
                    'monitor_arn': raw.get('MonitorArn'),
                })
            token = response.get('NextPageToken')
            if not token:
                break
    except Exception as exc:
        result = _classify(exc)
        result['anomalies'] = []
        return result

    anomalies.sort(key=lambda a: a['total_impact'], reverse=True)
    return {'status': STATUS_OK, 'anomalies': anomalies,
            'message': '{0} anomaly/anomalies in the last {1} days.'.format(
                len(anomalies), days)}


def detector_health(days: int = 90, ce_client=None) -> Dict[str, Any]:
    """
    The honest answer to "is anything watching my spend, and what did it see?"

    Never reports an all-clear it cannot justify: if the monitor is missing, the
    permissions are wrong, or the baseline has not formed, that is the verdict -
    the anomaly count comes back as None (unknown), not 0.
    """
    monitors = get_anomaly_monitors(ce_client)

    if monitors['status'] in (STATUS_NO_CLIENT, STATUS_ACCESS_DENIED, STATUS_ERROR):
        return {
            'status': monitors['status'],
            'trustworthy': False,
            'monitors': monitors.get('monitors', []),
            'anomalies': [],
            'anomaly_count': None,
            'message': monitors['message'],
            'verdict': 'Detector status unknown',
        }

    if monitors['status'] == STATUS_NO_MONITOR:
        return {
            'status': STATUS_NO_MONITOR,
            'trustworthy': False,
            'monitors': [],
            'anomalies': [],
            'anomaly_count': None,
            'message': monitors['message'],
            'verdict': 'No detector configured',
        }

    found = fetch_anomalies(days, ce_client)
    if found['status'] != STATUS_OK:
        return {
            'status': found['status'],
            'trustworthy': False,
            'monitors': monitors['monitors'],
            'anomalies': [],
            'anomaly_count': None,
            'message': found['message'],
            'verdict': 'Detector status unknown',
        }

    warming = monitors['status'] == STATUS_WARMING_UP
    count = len(found['anomalies'])
    return {
        'status': STATUS_WARMING_UP if warming else STATUS_OK,
        'trustworthy': not warming,
        'monitors': monitors['monitors'],
        'anomalies': found['anomalies'],
        'anomaly_count': count,
        'message': monitors['message'] if warming else found['message'],
        'verdict': ('{0} anomaly/anomalies detected'.format(count) if count
                    else ('Baseline still forming' if warming
                          else 'No anomalies detected')),
    }


# --- Writes (guarded - the caller must confirm before calling these) --------

def create_anomaly_monitor(name: str = 'finops-service-monitor',
                           ce_client=None) -> Dict[str, Any]:
    """
    Create a SERVICE-dimension monitor covering every service in the account.

    This WRITES to AWS. The caller is responsible for an explicit confirmation
    step; nothing in this module calls it on its own.
    """
    client = get_ce_client(ce_client)
    if client is None:
        return {'status': STATUS_NO_CLIENT, 'message': 'Not connected to AWS.'}
    try:
        response = client.create_anomaly_monitor(
            AnomalyMonitor={
                'MonitorName': name,
                'MonitorType': 'DIMENSIONAL',
                'MonitorDimension': 'SERVICE',
            }
        )
        return {
            'status': STATUS_OK,
            'arn': response.get('MonitorArn'),
            'message': 'Monitor created. AWS needs about {0} days to build a baseline '
                       'before it reports anomalies.'.format(BASELINE_DAYS),
        }
    except Exception as exc:
        return _classify(exc)


def create_anomaly_subscription(monitor_arn: str, email: str,
                                threshold_usd: float = 100.0,
                                name: str = 'finops-anomaly-alerts',
                                ce_client=None) -> Dict[str, Any]:
    """
    Subscribe an email address to a monitor. WRITES to AWS - confirm first.

    Uses ThresholdExpression (the flat Threshold field is deprecated) and DAILY
    frequency, which is what EMAIL subscribers support; IMMEDIATE needs SNS.
    """
    client = get_ce_client(ce_client)
    if client is None:
        return {'status': STATUS_NO_CLIENT, 'message': 'Not connected to AWS.'}
    try:
        response = client.create_anomaly_subscription(
            AnomalySubscription={
                'MonitorArnList': [monitor_arn],
                'Subscribers': [{'Address': email, 'Type': 'EMAIL'}],
                'Frequency': 'DAILY',
                'SubscriptionName': name,
                'ThresholdExpression': {
                    'Dimensions': {
                        'Key': 'ANOMALY_TOTAL_IMPACT_ABSOLUTE',
                        'Values': [str(threshold_usd)],
                        'MatchOptions': ['GREATER_THAN_OR_EQUAL'],
                    }
                },
            }
        )
        return {'status': STATUS_OK, 'arn': response.get('SubscriptionArn'),
                'message': 'Alerts will go to {0} daily above ${1:,.0f}.'.format(
                    email, threshold_usd)}
    except Exception as exc:
        return _classify(exc)


# ===========================================================================
# Independent baseline detection
# ===========================================================================
# AWS only reports anomalies once a monitor has existed for ~10 days. Cost
# Explorer's daily history, however, is available immediately - so we can run
# our own detector over it and have something to show on day one, in accounts
# with no monitor, and as a second opinion where a monitor does exist.
#
# The statistic is median + MAD, not mean + standard deviation: a spike inflates
# its own standard deviation and can hide itself, whereas the median absolute
# deviation is unmoved by a handful of outliers.
# ===========================================================================

# Defaults chosen to keep noise down on real estates
DEFAULT_SENSITIVITY = 3.5      # modified z-score threshold
DEFAULT_MIN_IMPACT = 25.0      # USD/day - below this, nobody cares
DEFAULT_MIN_HISTORY = 14       # days of baseline required before we judge a service
DEFAULT_EVAL_WINDOW = 21       # how many recent days we test


def fetch_daily_service_costs(days: int = 90, ce_client=None) -> Dict[str, Any]:
    """
    Daily unblended cost per service from Cost Explorer.

    Returns {'status', 'series': {service: {'YYYY-MM-DD': cost}}, 'days', 'message'}.
    Today is excluded - the current day's figure is partial and would read as a
    collapse in spend.
    """
    client = get_ce_client(ce_client)
    if client is None:
        return {'status': STATUS_NO_CLIENT, 'series': {},
                'message': 'Not connected to AWS.'}

    today = datetime.now().strftime('%Y-%m-%d')
    series: Dict[str, Dict[str, float]] = {}
    token = None
    try:
        while True:
            kwargs = {
                'TimePeriod': _time_period(days),
                'Granularity': 'DAILY',
                'Metrics': ['UnblendedCost'],
                'GroupBy': [{'Type': 'DIMENSION', 'Key': 'SERVICE'}],
            }
            if token:
                kwargs['NextPageToken'] = token
            response = client.get_cost_and_usage(**kwargs)

            for period in response.get('ResultsByTime', []):
                date = (period.get('TimePeriod', {}) or {}).get('Start')
                if not date or date >= today:
                    continue  # partial day
                for group in period.get('Groups', []) or []:
                    keys = group.get('Keys') or ['Unknown']
                    service = keys[0]
                    amount = float(
                        ((group.get('Metrics') or {}).get('UnblendedCost') or {})
                        .get('Amount', 0) or 0)
                    series.setdefault(service, {})[date] = amount

            token = response.get('NextPageToken')
            if not token:
                break
    except Exception as exc:
        result = _classify(exc)
        result['series'] = {}
        return result

    return {'status': STATUS_OK, 'series': series, 'days': days,
            'message': '{0} service(s) over {1} days.'.format(len(series), days)}


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _modified_z(value: float, baseline: List[float]) -> Optional[float]:
    """
    Modified z-score (Iglewicz-Hoaglin). Returns None when the baseline is flat
    and no scale can be estimated - the caller falls back to a ratio test rather
    than dividing by zero.
    """
    median = _median(baseline)
    mad = _median([abs(x - median) for x in baseline])
    if mad == 0:
        return None
    return 0.6745 * (value - median) / mad


def detect_statistical_anomalies(series: Dict[str, Dict[str, float]],
                                 sensitivity: float = DEFAULT_SENSITIVITY,
                                 min_impact: float = DEFAULT_MIN_IMPACT,
                                 min_history: int = DEFAULT_MIN_HISTORY,
                                 eval_window: int = DEFAULT_EVAL_WINDOW
                                 ) -> List[Dict[str, Any]]:
    """
    Flag per-service daily spikes against each service's own trailing history.

    Consecutive flagged days for one service are merged into a single anomaly,
    so a three-day spike is one finding, not three.
    """
    findings: List[Dict[str, Any]] = []

    for service, by_date in series.items():
        dates = sorted(by_date)
        if len(dates) < min_history + 1:
            continue

        flagged = []
        for index in range(len(dates)):
            # only judge the recent window; earlier days are baseline material
            if index < min_history or index < len(dates) - eval_window:
                continue
            date = dates[index]
            value = by_date[date]
            baseline = [by_date[d] for d in dates[:index]]
            median = _median(baseline)
            delta = value - median

            if delta < min_impact:
                continue

            score = _modified_z(value, baseline)
            if score is None:
                # Flat baseline (often a brand-new or steady-state service):
                # fall back to a ratio test so a genuine jump still registers.
                if median <= 0 or value < median * 2:
                    continue
                score = float('inf')
            elif score < sensitivity:
                continue

            flagged.append({'date': date, 'actual': value, 'expected': median,
                            'delta': delta, 'score': score})

        # merge consecutive days into one window
        for group in _group_consecutive(flagged):
            total_delta = sum(d['delta'] for d in group)
            findings.append({
                'id': 'baseline:{0}:{1}'.format(service, group[0]['date']),
                'source': 'baseline',
                'service': service,
                'region': 'all',
                'account': 'all',
                'start_date': group[0]['date'],
                'end_date': group[-1]['date'],
                'total_impact': total_delta,
                'total_actual_spend': sum(d['actual'] for d in group),
                'total_expected_spend': sum(d['expected'] for d in group),
                'max_impact': max(d['delta'] for d in group),
                'score': max(d['score'] for d in group),
                'method': 'median+MAD',
                'days': len(group),
                'daily': group,
                'root_causes': [],
            })

    findings.sort(key=lambda f: f['total_impact'], reverse=True)
    return findings


def _group_consecutive(flagged: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Group flagged days that sit on consecutive calendar dates."""
    groups: List[List[Dict[str, Any]]] = []
    for day in flagged:
        current = datetime.strptime(day['date'], '%Y-%m-%d')
        if groups:
            previous = datetime.strptime(groups[-1][-1]['date'], '%Y-%m-%d')
            if (current - previous).days == 1:
                groups[-1].append(day)
                continue
        groups.append([day])
    return groups


def _overlaps(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Do two anomalies cover the same service and overlapping dates?"""
    if (a.get('service') or '').lower() != (b.get('service') or '').lower():
        return False
    a_start, a_end = str(a.get('start_date') or '')[:10], str(a.get('end_date') or '')[:10]
    b_start, b_end = str(b.get('start_date') or '')[:10], str(b.get('end_date') or '')[:10]
    if not (a_start and b_start):
        return False
    return a_start <= (b_end or b_start) and b_start <= (a_end or a_start)


def detect_all(days: int = 90, ce_client=None,
               sensitivity: float = DEFAULT_SENSITIVITY,
               min_impact: float = DEFAULT_MIN_IMPACT) -> Dict[str, Any]:
    """
    Run both detectors and cross-reference them.

    Anomalies seen by AWS *and* by the baseline are marked confirmed=True - that
    agreement is the strongest signal on the page.
    """
    health = detector_health(days, ce_client)
    costs = fetch_daily_service_costs(days, ce_client)

    baseline: List[Dict[str, Any]] = []
    if costs['status'] == STATUS_OK:
        baseline = detect_statistical_anomalies(
            costs['series'], sensitivity=sensitivity, min_impact=min_impact)

    aws_found = health.get('anomalies') or []
    for item in aws_found:
        item['confirmed'] = any(_overlaps(item, b) for b in baseline)
    for item in baseline:
        item['confirmed'] = any(_overlaps(item, a) for a in aws_found)

    combined = sorted(aws_found + baseline,
                      key=lambda a: (not a.get('confirmed'), -a['total_impact']))

    return {
        'anomalies': combined,
        'aws': aws_found,
        'baseline': baseline,
        'health': health,
        'baseline_status': costs['status'],
        'baseline_message': costs.get('message', ''),
        'series': costs.get('series', {}),
        'confirmed_count': sum(1 for a in combined if a.get('confirmed')),
        'total_impact': sum(a['total_impact'] for a in combined),
    }
