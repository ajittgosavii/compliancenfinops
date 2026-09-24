"""
FinOps Anomaly - state and history
==================================
Without this, every page load starts from zero: the same spike shouts at you
every morning, nobody can mark one "known - it's the migration cutover", and
the app can never say "this service has spiked four times in 90 days" - which
is a far more useful finding than any single spike.

Two things are stored:
  * state    - per anomaly: status, note, owner, timestamps
  * sightings - per service: every time an anomaly was seen, so recurrence
                becomes visible over time

Backend is the Firebase Realtime Database the app already uses for users, under
a separate /finops_anomalies subtree. When Firebase is not configured it falls
back to session state and says so - a fallback that silently pretends to
persist would be worse than none.

Version: 1.0.0
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st

STATUSES = ['new', 'investigating', 'known', 'resolved', 'false positive']

STATE_PATH = 'finops_anomalies/state'
SIGHTING_PATH = 'finops_anomalies/sightings'

_SESSION_STATE_KEY = '_anomaly_state_fallback'
_SESSION_SIGHTING_KEY = '_anomaly_sighting_fallback'


def _safe_key(value: str) -> str:
    """
    Firebase keys cannot contain . $ # [ ] / - and anomaly ids and service
    names contain several of those. Hash anything unsafe rather than mangling
    it into a collision.
    """
    text = str(value)
    if any(character in text for character in './$#[]'):
        digest = hashlib.sha1(text.encode('utf-8')).hexdigest()[:16]
        return 'k_' + digest
    return text


def _manager():
    """
    The app's Firebase manager, or None when it is not configured.

    Checks for credentials before constructing the manager: the manager's own
    constructor renders Streamlit errors and a setup guide when secrets are
    missing, which would print a wall of Firebase instructions onto a cost
    page that works perfectly well without it.
    """
    try:
        if 'firebase' not in st.secrets:
            return None
    except Exception:
        return None          # no secrets file at all

    try:
        from auth_database_firebase import get_firebase_manager
    except Exception:
        return None
    try:
        manager = get_firebase_manager()
    except Exception:
        return None
    if manager is None or getattr(manager, 'db_ref', None) is None:
        return None
    return manager


def backend_status() -> Dict[str, Any]:
    """Where state is being kept, so the UI can be honest about it."""
    if _manager() is not None:
        return {'persistent': True, 'backend': 'firebase',
                'message': 'Anomaly state is saved to Firebase.'}
    return {'persistent': False, 'backend': 'session',
            'message': 'Firebase is not configured - anomaly status and notes '
                       'last only for this browser session.'}


# --- State -----------------------------------------------------------------

def load_states() -> Dict[str, Dict[str, Any]]:
    """Every stored anomaly state, keyed by anomaly id."""
    manager = _manager()
    if manager is None:
        return dict(st.session_state.get(_SESSION_STATE_KEY, {}))
    try:
        stored = manager._get_reference(STATE_PATH).get() or {}
    except Exception:
        return dict(st.session_state.get(_SESSION_STATE_KEY, {}))

    states = {}
    for record in stored.values():
        if isinstance(record, dict) and record.get('anomaly_id'):
            states[record['anomaly_id']] = record
    return states


def save_state(anomaly: Dict[str, Any], status: str,
               note: str = '', owner: Optional[str] = None) -> Dict[str, Any]:
    """Record what a human decided about one anomaly."""
    if status not in STATUSES:
        return {'ok': False, 'message': 'Unknown status: {0}'.format(status)}

    record = {
        'anomaly_id': anomaly.get('id'),
        'service': anomaly.get('service', 'Unknown'),
        'account': str(anomaly.get('account', 'all')),
        'status': status,
        'note': note or '',
        'owner': owner or st.session_state.get('username') or 'unknown',
        'total_impact': float(anomaly.get('total_impact', 0) or 0),
        'start_date': str(anomaly.get('start_date'))[:10],
        'updated_at': datetime.now().isoformat(timespec='seconds'),
    }

    manager = _manager()
    if manager is None:
        fallback = st.session_state.setdefault(_SESSION_STATE_KEY, {})
        fallback[record['anomaly_id']] = record
        return {'ok': True, 'persistent': False,
                'message': 'Saved for this session only - Firebase is not configured.'}

    try:
        path = '{0}/{1}'.format(STATE_PATH, _safe_key(record['anomaly_id']))
        manager._get_reference(path).set(record)
    except Exception as exc:
        return {'ok': False, 'message': 'Could not save: {0}'.format(exc)}

    _audit(manager, 'anomaly_status_changed', record)
    return {'ok': True, 'persistent': True, 'message': 'Saved.'}


def _audit(manager, event_type: str, payload: Dict[str, Any]) -> None:
    """Reuse the existing audit log; never let logging break the save."""
    try:
        manager.log_event(payload.get('owner', 'unknown'), event_type, payload)
    except Exception:
        pass


# --- Sightings / recurrence ------------------------------------------------

def record_sighting(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Note that these anomalies were seen today.

    Idempotent per (service, start_date): re-running detection on the same day
    does not inflate the recurrence count.
    """
    if not anomalies:
        return {'ok': True, 'recorded': 0}

    manager = _manager()
    recorded = 0

    for anomaly in anomalies:
        service = anomaly.get('service', 'Unknown')
        start = str(anomaly.get('start_date'))[:10]
        entry = {
            'service': service,
            'start_date': start,
            'total_impact': float(anomaly.get('total_impact', 0) or 0),
            'source': anomaly.get('source', 'unknown'),
            'confirmed': bool(anomaly.get('confirmed')),
            'first_recorded': datetime.now().isoformat(timespec='seconds'),
        }
        key = _safe_key('{0}|{1}'.format(service, start))

        if manager is None:
            store = st.session_state.setdefault(_SESSION_SIGHTING_KEY, {})
            bucket = store.setdefault(service, {})
            if key not in bucket:
                bucket[key] = entry
                recorded += 1
            continue

        try:
            path = '{0}/{1}/{2}'.format(SIGHTING_PATH, _safe_key(service), key)
            reference = manager._get_reference(path)
            if reference.get() is None:      # idempotent - do not double count
                reference.set(entry)
                recorded += 1
        except Exception:
            continue

    return {'ok': True, 'recorded': recorded}


def sighting_history(service: str) -> List[Dict[str, Any]]:
    """Every recorded flare-up for one service, oldest first."""
    manager = _manager()
    if manager is None:
        bucket = st.session_state.get(_SESSION_SIGHTING_KEY, {}).get(service, {})
        return sorted(bucket.values(), key=lambda e: e.get('start_date', ''))
    try:
        stored = manager._get_reference(
            '{0}/{1}'.format(SIGHTING_PATH, _safe_key(service))).get() or {}
    except Exception:
        return []
    return sorted([entry for entry in stored.values() if isinstance(entry, dict)],
                  key=lambda e: e.get('start_date', ''))


def recurrence_summary(anomalies: List[Dict[str, Any]]) -> Dict[str, int]:
    """How many times each service in this result set has flared up before."""
    return {service: len(sighting_history(service))
            for service in {a.get('service', 'Unknown') for a in anomalies}}
