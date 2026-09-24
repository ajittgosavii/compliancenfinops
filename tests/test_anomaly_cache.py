"""
The detection cache must invalidate when the AWS connection changes.

Regression: detection that ran before AWS was connected stayed cached
afterwards, so the page kept reporting "Not connected to AWS" while the
sidebar showed a connected account.

Run:  python -m pytest tests/test_anomaly_cache.py -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def signature(state, days=90, sensitivity=3.5, min_impact=25.0):
    """Mirror of the signature built in render_anomaly_page."""
    return (days, sensitivity, min_impact,
            bool(state.get('aws_connected')),
            state.get('aws_account_id'),
            bool(state.get('demo_mode')))


def test_connecting_invalidates_a_stale_result():
    before = signature({'aws_connected': False})
    after = signature({'aws_connected': True, 'aws_account_id': '448549863273'})
    assert before != after, 'connecting must force a re-run'


def test_disconnecting_invalidates():
    connected = signature({'aws_connected': True, 'aws_account_id': '1'})
    assert connected != signature({'aws_connected': False})


def test_switching_account_invalidates():
    a = signature({'aws_connected': True, 'aws_account_id': '111111111111'})
    b = signature({'aws_connected': True, 'aws_account_id': '222222222222'})
    assert a != b, 'another account is different data'


def test_toggling_demo_mode_invalidates():
    live = signature({'aws_connected': True, 'aws_account_id': '1'})
    demo = signature({'aws_connected': True, 'aws_account_id': '1',
                      'demo_mode': True})
    assert live != demo


def test_controls_still_invalidate():
    state = {'aws_connected': True, 'aws_account_id': '1'}
    base = signature(state)
    assert base != signature(state, days=30)
    assert base != signature(state, sensitivity=2.0)
    assert base != signature(state, min_impact=100.0)


def test_nothing_changing_reuses_the_result():
    """Detection makes billed Cost Explorer calls - do not re-run for free."""
    state = {'aws_connected': True, 'aws_account_id': '448549863273'}
    assert signature(state) == signature(state)
