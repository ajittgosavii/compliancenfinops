"""Harness: exercises every ui_theme component, driven by test_ui_theme.py."""

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ui_theme

ui_theme.inject_theme()

NAV_GROUPS = [
    ('Overview', [('Dashboard', 1), ('AI insights', 0)]),
    ('FinOps', [('Cost & optimization', 8), ('Cost anomalies', 10)]),
]

with st.sidebar:
    ui_theme.brand('Cloud Compliance Canvas', 'demo')
    active = ui_theme.render_navigation(NAV_GROUPS, default=1)
    st.markdown('---')
    st.markdown('#### Connections')
    ui_theme.credential_row('AWS account', False, required=False,
                            hint='Not needed while demo mode is on')
    ui_theme.credential_row('Claude API key', True, required=False,
                            detail='AI analysis enabled')
    ui_theme.credential_row('GitHub token', False, required=False,
                            hint='Only needed for repository scanning')
    ui_theme.credential_row('Broken thing', False, required=True,
                            hint='Required - not configured')

ui_theme.page_header('Cost anomalies',
                     'Unexpected spend, and whether anything is watching for it.')

st.write('active_section={0}'.format(active))

columns = st.columns(4)
with columns[0]:
    ui_theme.status_card('Cost Explorer', 'us-east-1', 'ok',
                         note='Region', chip='active')
with columns[1]:
    ui_theme.status_card('Cost Anomaly Detection', '2', 'ok',
                         note='Monitors', chip='active')
with columns[2]:
    ui_theme.status_card('Compute Optimizer', '0', 'unknown',
                         note='Recommendations', chip='inactive')
with columns[3]:
    ui_theme.status_card('Budget breach', '1', 'critical',
                         note='Accounts over budget', chip='action needed')

st.markdown(ui_theme.status_chip('degraded', 'warn'), unsafe_allow_html=True)
