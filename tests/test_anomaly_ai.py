"""
Tests for the AI explanation layer.

No real API calls - a fake client captures the request so we can assert on
what would be sent, and the response-handling paths are exercised directly.

Run:  python -m pytest tests/test_anomaly_ai.py -q
"""

import json
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import anthropic  # noqa: E402
import finops_anomaly_ai as ai  # noqa: E402


# --- Fixtures ---------------------------------------------------------------

def make_series(service, values, end_offset=1):
    end = datetime.now() - timedelta(days=end_offset)
    start = end - timedelta(days=len(values) - 1)
    return {service: {(start + timedelta(days=i)).strftime('%Y-%m-%d'): v
                      for i, v in enumerate(values)}}


@pytest.fixture
def anomaly():
    return {
        'id': 'baseline:AmazonEC2:2026-09-20', 'source': 'baseline',
        'service': 'AmazonEC2', 'account': '111111111111', 'region': 'us-east-1',
        'start_date': '2026-09-20', 'end_date': '2026-09-21',
        'total_impact': 1800.0, 'total_actual_spend': 2000.0,
        'total_expected_spend': 200.0, 'confirmed': True,
        'root_causes': [{'Service': 'AmazonEC2', 'Region': 'us-east-1'}],
    }


class TextBlock:
    type = 'text'

    def __init__(self, text):
        self.text = text


class FakeResponse:
    def __init__(self, payload, stop_reason='end_turn'):
        self.content = [TextBlock(json.dumps(payload))] if payload else []
        self.stop_reason = stop_reason
        self.usage = type('U', (), {'input_tokens': 900, 'output_tokens': 300,
                                    'cache_read_input_tokens': 0})()


class FakeClient:
    """Captures create() kwargs; returns a canned response or raises."""

    def __init__(self, payload=None, raises=None, stop_reason='end_turn'):
        self.captured = {}
        self._payload = payload if payload is not None else VALID_PAYLOAD
        self._raises = raises
        self._stop_reason = stop_reason
        self.messages = self

    def create(self, **kwargs):
        self.captured = kwargs
        if self._raises:
            raise self._raises
        return FakeResponse(self._payload, self._stop_reason)


VALID_PAYLOAD = {
    'probable_cause': 'Sixteen m5.2xlarge instances were launched on 2026-09-20 '
                      'and have not been terminated.',
    'pattern': 'new run rate',
    'confidence': 'high',
    'recurring_cost_risk': 'About $27,000/month if the instances stay up.',
    'recommended_actions': ['Identify the owner via CloudTrail RunInstances'],
    'investigation_steps': ['CloudTrail: RunInstances between 09-19 and 09-21'],
}


def use(monkeypatch, client):
    monkeypatch.setattr(ai, 'get_client', lambda: client)
    return client


# --- Prompt construction ----------------------------------------------------

def test_prompt_carries_the_numbers(anomaly):
    prompt = ai.build_prompt(anomaly, make_series('AmazonEC2', [100.0] * 30))
    assert 'AmazonEC2' in prompt
    assert '$2,000.00' in prompt      # actual
    assert '$200.00' in prompt        # expected
    assert '$1,800.00' in prompt      # excess
    assert '111111111111' in prompt


def test_prompt_states_when_both_detectors_agree(anomaly):
    prompt = ai.build_prompt(anomaly, {})
    assert 'they agree' in prompt


def test_prompt_states_a_single_source_honestly(anomaly):
    anomaly['confirmed'] = False
    anomaly['source'] = 'aws_cad'
    prompt = ai.build_prompt(anomaly, {})
    assert 'AWS Cost Anomaly Detection' in prompt
    assert 'they agree' not in prompt


def test_prompt_includes_the_daily_series(anomaly):
    series = make_series('AmazonEC2', [100.0, 110.0, 900.0])
    prompt = ai.build_prompt(anomaly, series)
    assert 'DAILY UNBLENDED COST' in prompt
    assert '$900.00' in prompt


def test_prompt_is_trimmed_to_the_recent_window(anomaly):
    series = make_series('AmazonEC2', [float(i) for i in range(200)])
    prompt = ai.build_prompt(anomaly, series)
    cost_lines = [l for l in prompt.splitlines() if l.strip().startswith('20')]
    assert len(cost_lines) <= ai.SERIES_DAYS


def test_co_movers_surface_a_shared_event():
    """A spike across several services points at an account or region event."""
    spike_day = '2026-09-20'
    series = {
        'AmazonEC2': {spike_day: 900.0},
        'AmazonRDS': {},
        'AWSDataTransfer': {},
    }
    base = datetime.strptime(spike_day, '%Y-%m-%d')
    for i in range(1, 15):
        day = (base - timedelta(days=i)).strftime('%Y-%m-%d')
        series['AmazonRDS'][day] = 50.0
        series['AWSDataTransfer'][day] = 10.0
    series['AmazonRDS'][spike_day] = 400.0          # also jumped
    series['AWSDataTransfer'][spike_day] = 10.5     # flat

    movers = ai._co_movers(series, 'AmazonEC2', spike_day)
    assert movers, 'RDS moved and should be reported'
    assert 'AmazonRDS' in movers[0]
    assert 'AWSDataTransfer' not in ' '.join(movers)


def test_prompt_says_so_when_nothing_else_moved(anomaly):
    series = make_series('AmazonEC2', [100.0] * 30)
    series['AmazonS3'] = dict(series['AmazonEC2'])
    prompt = ai.build_prompt(anomaly, series)
    assert ('No other service moved materially' in prompt
            or 'OTHER SERVICES THAT MOVED' in prompt)


# --- Request shape ----------------------------------------------------------

def test_request_uses_the_current_model(monkeypatch, anomaly):
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    assert client.captured['model'] == 'claude-opus-5'


def test_request_uses_adaptive_thinking(monkeypatch, anomaly):
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    assert client.captured['thinking'] == {'type': 'adaptive'}
    # budget_tokens is rejected on this model family
    assert 'budget_tokens' not in json.dumps(client.captured['thinking'])


def test_request_constrains_output_with_a_schema(monkeypatch, anomaly):
    """Replaces the old find('[')/rfind(']') scrape of free text."""
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    fmt = client.captured['output_config']['format']
    assert fmt['type'] == 'json_schema'
    assert fmt['schema']['additionalProperties'] is False
    assert set(fmt['schema']['required']) == {
        'probable_cause', 'pattern', 'confidence', 'recurring_cost_risk',
        'recommended_actions', 'investigation_steps'}


def test_request_does_not_use_the_deprecated_output_format(monkeypatch, anomaly):
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    assert 'output_format' not in client.captured


def test_system_prompt_is_marked_cacheable(monkeypatch, anomaly):
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    assert client.captured['system'][0]['cache_control'] == {'type': 'ephemeral'}


def test_system_prompt_forbids_invention(monkeypatch, anomaly):
    client = use(monkeypatch, FakeClient())
    ai.explain_anomaly(anomaly, {})
    system = client.captured['system'][0]['text']
    assert 'Never invent' in system
    assert 'explanation, not' in system


# --- Response handling ------------------------------------------------------

def test_valid_response_is_returned_parsed(monkeypatch, anomaly):
    use(monkeypatch, FakeClient())
    result = ai.explain_anomaly(anomaly, {})
    assert result['pattern'] == 'new run rate'
    assert result['confidence'] == 'high'
    assert result['model'] == 'claude-opus-5'
    assert result['usage']['input_tokens'] == 900
    assert 'error' not in result


def fake_http_response(status_code):
    """Minimal stand-in for the httpx2 response the SDK exceptions unwrap."""
    return type('R', (), {'status_code': status_code, 'headers': {},
                          'request': None})()


def test_a_revoked_key_gives_an_actionable_message(monkeypatch, anomaly):
    """The exact failure this app hit before: a key that is well-formed but dead."""
    error = anthropic.AuthenticationError(
        message='invalid x-api-key', response=fake_http_response(401), body=None)
    use(monkeypatch, FakeClient(raises=error))
    result = ai.explain_anomaly(anomaly, {})
    assert 'rejected' in result['error']
    assert 'revoked' in result['error']


def test_rate_limit_is_distinguished_from_a_bad_key(monkeypatch, anomaly):
    error = anthropic.RateLimitError(
        message='slow down', response=fake_http_response(429), body=None)
    use(monkeypatch, FakeClient(raises=error))
    assert 'Rate limited' in ai.explain_anomaly(anomaly, {})['error']


def test_connection_failure_is_reported_not_raised(monkeypatch, anomaly):
    error = anthropic.APIConnectionError(request=None)
    use(monkeypatch, FakeClient(raises=error))
    result = ai.explain_anomaly(anomaly, {})
    assert 'Could not reach' in result['error']


def test_unexpected_exception_never_escapes(monkeypatch, anomaly):
    use(monkeypatch, FakeClient(raises=RuntimeError('kaboom')))
    result = ai.explain_anomaly(anomaly, {})
    assert result['error'].startswith('RuntimeError')


def test_refusal_is_handled(monkeypatch, anomaly):
    use(monkeypatch, FakeClient(stop_reason='refusal'))
    assert 'declined' in ai.explain_anomaly(anomaly, {})['error']


def test_unparseable_response_is_an_error_not_a_crash(monkeypatch, anomaly):
    client = FakeClient()
    client.create = lambda **kw: FakeResponse(None)
    monkeypatch.setattr(ai, 'get_client', lambda: client)
    assert 'error' in ai.explain_anomaly(anomaly, {})


def test_missing_key_is_reported_before_any_call(monkeypatch, anomaly):
    monkeypatch.setattr(ai, 'get_client', lambda: None)
    monkeypatch.setattr(ai, '_resolve_api_key', lambda: None)
    result = ai.explain_anomaly(anomaly, {})
    assert 'No Anthropic API key' in result['error']


# --- Status -----------------------------------------------------------------

def test_status_without_a_key(monkeypatch):
    monkeypatch.setattr(ai, '_resolve_api_key', lambda: None)
    status = ai.ai_status()
    assert status['available'] is False
    assert 'secrets.toml' in status['message']


def test_status_with_a_key(monkeypatch):
    monkeypatch.setattr(ai, '_resolve_api_key', lambda: 'sk-ant-test')
    status = ai.ai_status()
    assert status['available'] is True
    assert status['model'] == 'claude-opus-5'


def test_env_var_is_a_valid_key_source(monkeypatch):
    """Isolated from any secrets.toml that happens to exist on this machine."""
    import types
    monkeypatch.setattr(ai, 'st', types.SimpleNamespace(session_state={}))
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-from-env')
    assert ai._resolve_api_key() == 'sk-ant-from-env'


def test_secrets_take_precedence_over_the_environment(monkeypatch):
    import types

    class Secrets(dict):
        pass

    monkeypatch.setattr(ai, 'st', types.SimpleNamespace(
        secrets=Secrets({'anthropic': {'api_key': 'sk-ant-from-secrets'}}),
        session_state={}))
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-from-env')
    assert ai._resolve_api_key() == 'sk-ant-from-secrets'
