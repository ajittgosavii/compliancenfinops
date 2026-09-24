"""
Render tests - the page must actually draw, not merely import.

Uses Streamlit's AppTest so an exception inside a render function fails here
rather than in front of a user.

Run:  python -m pytest tests/test_anomaly_page_render.py -q
"""

import os

import pytest
from streamlit.testing.v1 import AppTest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '_apptest_anomaly_page.py')


def run(scenario):
    os.environ['ANOMALY_SCENARIO'] = scenario
    app = AppTest.from_file(HARNESS, default_timeout=30)
    app.run()
    return app


def all_text(app):
    chunks = []
    for collection in (app.markdown, app.info, app.warning, app.error,
                       app.success, app.caption, app.metric):
        for element in collection:
            chunks.append(str(getattr(element, 'value', '')))
            chunks.append(str(getattr(element, 'label', '')))
    return ' '.join(chunks)


def test_findings_scenario_renders_without_exception():
    app = run('findings')
    assert not app.exception
    text = all_text(app)
    assert 'cost anomaly' in text or 'cost anomalies' in text
    assert 'AmazonEC2' in text


def test_findings_scenario_shows_impact_and_confirmation():
    app = run('findings')
    assert not app.exception
    text = all_text(app)
    assert '$1.8K' in text
    assert 'confirmed by both' in text


def test_denied_scenario_renders_and_does_not_say_all_clear():
    app = run('denied')
    assert not app.exception
    text = all_text(app)
    assert 'denied' in text.lower()
    assert 'No cost anomalies detected' not in text


def test_no_monitor_scenario_offers_setup():
    app = run('no_monitor')
    assert not app.exception
    text = all_text(app)
    assert 'No AWS monitor' in text or 'monitor' in text.lower()
    # the write is gated behind a confirmation checkbox
    assert any('creates a real resource' in (c.label or '') for c in app.checkbox)


def test_monitor_creation_button_is_disabled_until_confirmed():
    app = run('no_monitor')
    create = [b for b in app.button if b.label == 'Create monitor']
    assert create, 'setup button missing'
    assert create[0].disabled is True


def test_clean_scenario_is_the_only_one_that_says_no_anomalies():
    app = run('clean')
    assert not app.exception
    assert 'No cost anomalies detected' in all_text(app)


@pytest.mark.parametrize('scenario', ['findings', 'denied', 'no_monitor', 'clean'])
def test_every_scenario_renders_cleanly(scenario):
    app = run(scenario)
    assert not app.exception, '{0}: {1}'.format(scenario, app.exception)
