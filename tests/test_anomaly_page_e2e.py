"""
End-to-end render of the real entry point streamlit_app.py calls.

Run:  python -m pytest tests/test_anomaly_page_e2e.py -q
"""

import os

from streamlit.testing.v1 import AppTest

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '_apptest_full_page.py')


def run(scenario):
    os.environ['ANOMALY_SCENARIO'] = scenario
    app = AppTest.from_file(HARNESS, default_timeout=60)
    app.run()
    return app


def all_text(app):
    chunks = []
    for collection in (app.markdown, app.info, app.warning, app.error,
                       app.success, app.caption, app.metric, app.subheader):
        for element in collection:
            chunks.append(str(getattr(element, 'value', '')))
            chunks.append(str(getattr(element, 'label', '')))
    return ' '.join(chunks)


def test_full_page_renders():
    app = run('findings')
    assert not app.exception, app.exception
    text = all_text(app)
    assert 'independent baseline detector' in text
    assert '1 cost anomaly' in text


def test_page_does_not_render_its_own_title():
    """The host app supplies the page header; two headings looked broken."""
    app = run('findings')
    assert 'FinOps Cost Anomalies' not in all_text(app)


def test_full_page_shows_the_summary_metrics():
    app = run('findings')
    labels = {m.label for m in app.metric}
    assert {'Findings', 'Total impact', 'Confirmed by both',
            'Services affected'} <= labels


def test_controls_are_present():
    app = run('findings')
    assert any(s.label == 'Lookback' for s in app.selectbox)
    assert any(s.label == 'Sensitivity' for s in app.slider)
    assert any(b.label == '🔄 Run detection' for b in app.button)


def test_state_controls_appear_for_each_finding():
    app = run('findings')
    assert any(s.label == 'Status' for s in app.selectbox)
    assert any(b.label == 'Save' for b in app.button)


def test_no_monitor_scenario_renders_the_setup_path():
    app = run('no_monitor')
    assert not app.exception, app.exception
    text = all_text(app)
    assert 'No AWS monitor' in text
    assert any(b.label == 'Create monitor' for b in app.button)


def test_no_monitor_scenario_does_not_claim_all_clear():
    app = run('no_monitor')
    assert 'No cost anomalies detected' not in all_text(app)


def test_ai_section_renders_either_way():
    """
    With a key the page offers to explain; without one it says why it cannot.
    Either is correct - what must never happen is a crash or a silent gap.
    Written to tolerate whatever secrets exist on the machine running this.
    """
    app = run('findings')
    assert not app.exception
    text = all_text(app)
    has_button = any(b.label == 'Explain this anomaly' for b in app.button)
    says_why = 'API key' in text or 'unavailable' in text
    assert has_button or says_why, 'AI section rendered nothing at all'
