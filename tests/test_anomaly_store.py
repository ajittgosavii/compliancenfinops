"""
Tests for anomaly state and recurrence history.

Covers both backends: the Firebase path (with a fake reference tree) and the
session-state fallback used when Firebase is not configured.

Run:  python -m pytest tests/test_anomaly_store.py -q
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finops_anomaly_store as store  # noqa: E402


@pytest.fixture(autouse=True)
def fake_session(monkeypatch):
    """Replace st.session_state with a plain dict for these tests."""
    monkeypatch.setattr(store, 'st', types.SimpleNamespace(session_state={}))
    return store.st.session_state


def anomaly(anomaly_id='baseline:AmazonEC2:2026-09-20', service='AmazonEC2',
            start='2026-09-20', impact=1800.0):
    return {'id': anomaly_id, 'service': service, 'account': '111111111111',
            'start_date': start, 'end_date': start, 'total_impact': impact,
            'source': 'baseline', 'confirmed': True}


# --- Fake Firebase ---------------------------------------------------------

class FakeRef:
    def __init__(self, tree, path):
        self.tree = tree
        self.path = path

    def get(self):
        node = self.tree
        for part in self.path.split('/'):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def set(self, value):
        parts = self.path.split('/')
        node = self.tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value


class FakeManager:
    def __init__(self):
        self.tree = {}
        self.db_ref = object()
        self.events = []

    def _get_reference(self, path):
        return FakeRef(self.tree, path)

    def log_event(self, user_id, event_type, payload):
        self.events.append((user_id, event_type, payload))


@pytest.fixture
def firebase(monkeypatch):
    manager = FakeManager()
    monkeypatch.setattr(store, '_manager', lambda: manager)
    return manager


# --- Honesty about persistence ---------------------------------------------

def test_without_firebase_the_backend_admits_it_is_not_persistent(monkeypatch):
    monkeypatch.setattr(store, '_manager', lambda: None)
    status = store.backend_status()
    assert status['persistent'] is False
    assert 'last only for this browser session' in status['message']


def test_with_firebase_the_backend_reports_persistent(firebase):
    assert store.backend_status()['persistent'] is True


def test_session_fallback_save_says_it_is_session_only(monkeypatch):
    monkeypatch.setattr(store, '_manager', lambda: None)
    outcome = store.save_state(anomaly(), 'known', 'migration cutover')
    assert outcome['ok'] is True
    assert outcome['persistent'] is False
    assert 'session only' in outcome['message']


# --- State round trip ------------------------------------------------------

def test_state_round_trips_through_firebase(firebase):
    store.save_state(anomaly(), 'known', 'expected - migration cutover')
    states = store.load_states()
    record = states['baseline:AmazonEC2:2026-09-20']
    assert record['status'] == 'known'
    assert record['note'] == 'expected - migration cutover'
    assert record['service'] == 'AmazonEC2'
    assert record['updated_at']


def test_state_round_trips_through_session_fallback(monkeypatch):
    monkeypatch.setattr(store, '_manager', lambda: None)
    store.save_state(anomaly(), 'investigating', 'checking CloudTrail')
    states = store.load_states()
    assert states['baseline:AmazonEC2:2026-09-20']['status'] == 'investigating'


def test_saving_again_overwrites_rather_than_duplicating(firebase):
    store.save_state(anomaly(), 'investigating', 'first')
    store.save_state(anomaly(), 'resolved', 'second')
    states = store.load_states()
    assert len(states) == 1
    assert states['baseline:AmazonEC2:2026-09-20']['status'] == 'resolved'


def test_unknown_status_is_rejected(firebase):
    outcome = store.save_state(anomaly(), 'banana')
    assert outcome['ok'] is False
    assert 'Unknown status' in outcome['message']


def test_saving_writes_an_audit_event(firebase):
    store.save_state(anomaly(), 'known', 'expected')
    assert firebase.events
    assert firebase.events[0][1] == 'anomaly_status_changed'


def test_audit_failure_does_not_fail_the_save(firebase):
    def boom(*args, **kwargs):
        raise RuntimeError('audit down')

    firebase.log_event = boom
    assert store.save_state(anomaly(), 'known')['ok'] is True


def test_write_failure_is_reported_not_raised(firebase, monkeypatch):
    def boom(path):
        raise RuntimeError('firebase down')

    monkeypatch.setattr(firebase, '_get_reference', boom)
    outcome = store.save_state(anomaly(), 'known')
    assert outcome['ok'] is False
    assert 'Could not save' in outcome['message']


# --- Key safety ------------------------------------------------------------

def test_unsafe_firebase_characters_are_hashed_not_mangled():
    """Anomaly ids contain ':' and service names contain '.' and '/'."""
    key = store._safe_key('baseline:Amazon EC2/Compute.v2')
    assert '/' not in key and '.' not in key
    assert key.startswith('k_')


def test_distinct_ids_do_not_collide():
    a = store._safe_key('baseline:AmazonEC2:2026-09-20')
    b = store._safe_key('baseline:AmazonEC2:2026-09-21')
    assert a != b


def test_safe_values_are_left_readable():
    assert store._safe_key('AmazonEC2') == 'AmazonEC2'


# --- Recurrence ------------------------------------------------------------

def test_sightings_are_recorded(firebase):
    result = store.record_sighting([anomaly()])
    assert result['recorded'] == 1
    assert len(store.sighting_history('AmazonEC2')) == 1


def test_recording_the_same_day_twice_does_not_inflate_the_count(firebase):
    """Detection re-runs on every page load; recurrence must stay meaningful."""
    store.record_sighting([anomaly()])
    store.record_sighting([anomaly()])
    store.record_sighting([anomaly()])
    assert len(store.sighting_history('AmazonEC2')) == 1


def test_separate_flare_ups_accumulate(firebase):
    store.record_sighting([anomaly(anomaly_id='a1', start='2026-07-01')])
    store.record_sighting([anomaly(anomaly_id='a2', start='2026-08-14')])
    store.record_sighting([anomaly(anomaly_id='a3', start='2026-09-20')])
    history = store.sighting_history('AmazonEC2')
    assert len(history) == 3
    assert [h['start_date'] for h in history] == [
        '2026-07-01', '2026-08-14', '2026-09-20']       # oldest first


def test_history_is_per_service(firebase):
    store.record_sighting([anomaly(service='AmazonEC2', start='2026-09-01'),
                           anomaly(service='AmazonRDS', start='2026-09-02')])
    assert len(store.sighting_history('AmazonEC2')) == 1
    assert len(store.sighting_history('AmazonRDS')) == 1
    assert store.sighting_history('AmazonS3') == []


def test_recurrence_summary_counts_per_service(firebase):
    store.record_sighting([anomaly(service='AmazonEC2', start='2026-07-01'),
                           anomaly(service='AmazonEC2', start='2026-08-01'),
                           anomaly(service='AmazonRDS', start='2026-08-01')])
    summary = store.recurrence_summary([anomaly(service='AmazonEC2'),
                                        anomaly(service='AmazonRDS')])
    assert summary == {'AmazonEC2': 2, 'AmazonRDS': 1}


def test_sightings_work_without_firebase(monkeypatch):
    monkeypatch.setattr(store, '_manager', lambda: None)
    store.record_sighting([anomaly(start='2026-09-01')])
    store.record_sighting([anomaly(start='2026-09-01')])
    store.record_sighting([anomaly(start='2026-09-15')])
    assert len(store.sighting_history('AmazonEC2')) == 2


def test_empty_input_is_a_no_op(firebase):
    assert store.record_sighting([])['recorded'] == 0
