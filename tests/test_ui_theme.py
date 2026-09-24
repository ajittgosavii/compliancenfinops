"""
Tests for the design system and the sidebar navigation.

Run:  python -m pytest tests/test_ui_theme.py -q
"""

import os

import pytest
from streamlit.testing.v1 import AppTest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ui_theme  # noqa: E402

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '_apptest_theme.py')


def run():
    app = AppTest.from_file(HARNESS, default_timeout=30)
    app.run()
    return app


def markup(app):
    return ' '.join(str(m.value) for m in app.markdown)


# --- Renders at all --------------------------------------------------------

def test_theme_harness_renders():
    app = run()
    assert not app.exception, app.exception


def test_fonts_and_tokens_are_injected():
    text = markup(run())
    assert 'IBM+Plex+Sans' in text
    assert '--cc-primary: #0B4F6C' in text


def test_numbers_are_tabular():
    """Columns of dollars have to line up in a cost console."""
    assert 'tabular-nums' in markup(run())


def test_reduced_motion_is_respected():
    assert 'prefers-reduced-motion' in markup(run())


# --- Navigation ------------------------------------------------------------

def test_navigation_renders_every_item():
    app = run()
    labels = {b.label for b in app.button}
    assert {'Dashboard', 'AI insights', 'Cost & optimization',
            'Cost anomalies'} <= labels


def test_navigation_groups_are_sentence_case_not_shouted():
    """All-caps labels are a template tell; these are real group names."""
    text = markup(run())
    assert 'Overview' in text and 'OVERVIEW' not in text
    assert 'FinOps' in text


def test_current_section_is_the_primary_button():
    app = run()
    current = [b for b in app.button if b.label == 'Dashboard'][0]
    other = [b for b in app.button if b.label == 'Cost anomalies'][0]
    assert current.proto.type == 'primary'
    assert other.proto.type == 'secondary'


def test_clicking_a_nav_item_switches_section():
    app = run()
    [b for b in app.button if b.label == 'Cost anomalies'][0].click().run()
    assert not app.exception
    assert 'active_section=10' in ' '.join(str(m.value) for m in app.markdown)


def test_navigation_scales_past_a_tab_strip():
    """Eleven sections overflowed a tab row; a nav list does not."""
    app = run()
    nav_buttons = [b for b in app.button if b.key and b.key.startswith('nav_')]
    assert len(nav_buttons) == 4       # this harness declares four


# --- Credentials -----------------------------------------------------------

def test_optional_missing_credential_is_not_rendered_as_a_failure():
    """The bug in the screenshot: a red cross on config that is not required."""
    text = markup(run())
    assert 'Not needed while demo mode is on' in text
    # the optional rows use the neutral colour, not the critical one
    assert ui_theme.UNKNOWN in text


def test_required_missing_credential_is_still_critical():
    assert ui_theme.CRITICAL in markup(run())


def test_configured_credential_reads_as_connected():
    text = markup(run())
    assert 'AI analysis enabled' in text
    assert ui_theme.OK in text


# --- Status semantics ------------------------------------------------------

def test_healthy_status_is_green_not_amber():
    """Amber means degraded in an ops console; the old UI used it for ACTIVE."""
    text = markup(run())
    assert '.service-badge.active' in text
    active_rule = text.split('.service-badge.active')[1][:160]
    assert ui_theme.OK in active_rule
    assert '#FF9900' not in active_rule


def test_status_cards_carry_state_on_the_rail():
    text = markup(run())
    for state in ('ok', 'unknown', 'critical'):
        assert "data-state='{0}'".format(state) in text or \
               'data-state="{0}"'.format(state) in text


def test_every_state_has_a_distinct_colour():
    colours = {ui_theme.STATES[s][0] for s in ('ok', 'warn', 'critical', 'unknown')}
    assert len(colours) == 4


def test_unknown_is_a_first_class_state():
    """A console must be able to say "I could not check"."""
    assert 'unknown' in ui_theme.STATES
    assert ui_theme.STATES['unknown'][0] != ui_theme.STATES['ok'][0]


# --- Page header -----------------------------------------------------------

def test_page_header_states_what_the_page_answers():
    text = markup(run())
    assert 'Cost anomalies' in text
    assert 'whether anything is watching for it' in text
