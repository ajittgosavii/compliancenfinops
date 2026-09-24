"""
FinOps Anomaly - the page
=========================
A top-level page for cost anomalies, answer-first: the verdict is the first
thing on screen, and it never claims an all-clear the data cannot support.

Layout
  1. Verdict hero      - what is true right now, in one sentence
  2. Detector health   - is anything actually watching? (+ setup, behind a gate)
  3. Anomaly table     - every finding from both detectors, worst first
  4. Detail drawer     - the daily series, root causes, AI explanation, actions

The AI and persistence layers are optional imports: the page degrades to
"explanations unavailable" / "state not persisted" rather than breaking.

Version: 1.0.0
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

import finops_anomaly_detect as det

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    from finops_anomaly_ai import explain_anomaly, ai_status
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

try:
    from finops_anomaly_store import (
        load_states, save_state, record_sighting, sighting_history,
        backend_status, STATUSES)
    STORE_AVAILABLE = True
except ImportError:
    STORE_AVAILABLE = False
    STATUSES = ['new', 'investigating', 'known', 'resolved']


# --- Presentation helpers --------------------------------------------------

def format_cost(cost: float) -> str:
    # Cost Explorer returns tiny negative residuals for credits and refunds,
    # which render as "-$0.00" and read like a bug on screen.
    if abs(cost) < 0.005:
        return '$0.00'
    if cost >= 1_000_000:
        return '${0:.2f}M'.format(cost / 1_000_000)
    if cost >= 1_000:
        return '${0:.1f}K'.format(cost / 1_000)
    return '${0:.2f}'.format(cost)


# Level drives the colour of the hero; 'unknown' exists precisely so that a
# detector we cannot trust never renders in the same green as a clean estate.
LEVEL_STYLES = {
    'critical': ('#c0392b', '#fdedec', 'CRITICAL'),
    'warning': ('#d68910', '#fef5e7', 'ATTENTION'),
    'unknown': ('#5d6d7e', '#eaecee', 'UNKNOWN'),
    'clear': ('#1e8449', '#eafaf1', 'CLEAR'),
}


def verdict_for(result: Dict[str, Any], demo_mode: bool = False,
                connected: bool = False) -> Tuple[str, str, str]:
    """
    Reduce a detect_all() result to (level, headline, detail).

    Pure - no Streamlit - so the rule "an untrustworthy detector never renders
    as an all-clear" can be tested directly.
    """
    health = result.get('health') or {}
    status = health.get('status')

    # This page reads Cost Explorer directly and has no sample data. Saying
    # "not connected" under a banner promising sample figures is confusing, and
    # inventing demo anomalies would undermine the point of the page.
    if demo_mode and status == det.STATUS_NO_CLIENT:
        return ('unknown', 'No sample data on this page',
                'Anomaly detection reads AWS Cost Explorer directly, so it has '
                'nothing to show in demo mode. Connect an account to use it.')

    # Connected, but no Cost Explorer client - a different problem entirely
    # from "not connected", and telling the operator the wrong one sends them
    # to check credentials that are already working.
    if connected and status == det.STATUS_NO_CLIENT:
        return ('unknown', 'Cost Explorer is not available',
                'The AWS account is connected, but no Cost Explorer client was '
                'created. Cost Explorer must be enabled in the payer account, '
                'and the role needs ce:GetCostAndUsage and ce:GetAnomalies. '
                'Press Run detection after fixing it.')
    anomalies = result.get('anomalies') or []
    baseline_status = result.get('baseline_status')
    baseline_ran = baseline_status == det.STATUS_OK

    total = sum(a.get('total_impact', 0) for a in anomalies)
    confirmed = result.get('confirmed_count', 0)

    # Anomalies found - say so regardless of which detector found them
    if anomalies:
        headline = '{0} cost anomal{1}, {2} above expected'.format(
            len(anomalies), 'y' if len(anomalies) == 1 else 'ies', format_cost(total))
        bits = []
        if confirmed:
            bits.append('{0} confirmed by both detectors'.format(confirmed))
        if status == det.STATUS_NO_MONITOR:
            bits.append('found by the baseline detector - AWS has no monitor')
        elif status == det.STATUS_WARMING_UP:
            bits.append("AWS's own baseline is still forming")
        level = 'critical' if (confirmed or total >= 1000) else 'warning'
        return level, headline, '; '.join(bits) or 'Worst finding first below.'

    # Nothing found - now it matters a great deal WHY
    if status == det.STATUS_NO_CLIENT:
        return ('unknown', 'Not connected to AWS',
                'Connect an account to see anomalies. Nothing has been checked.')

    if status == det.STATUS_ACCESS_DENIED:
        return ('unknown', 'Cannot read anomaly data - access denied',
                health.get('message', 'The role lacks Cost Explorer anomaly permissions.'))

    if status == det.STATUS_ERROR:
        return ('unknown', 'Anomaly check failed', health.get('message', ''))

    if status == det.STATUS_NO_MONITOR and not baseline_ran:
        return ('unknown', 'Nothing is watching your spend',
                'No AWS anomaly monitor exists and the baseline detector could not '
                'read Cost Explorer. This is not an all-clear.')

    if status == det.STATUS_NO_MONITOR and baseline_ran:
        return ('warning', 'No AWS monitor - running on the baseline detector only',
                'The baseline detector found nothing in the window. Create a monitor '
                'below so AWS watches continuously too.')

    if status == det.STATUS_WARMING_UP:
        return ('warning', "AWS's detector is still building a baseline",
                health.get('message', ''))

    if not baseline_ran:
        return ('warning', 'AWS reports no anomalies; baseline detector unavailable',
                result.get('baseline_message', ''))

    return ('clear', 'No cost anomalies detected',
            'Both AWS Cost Anomaly Detection and the baseline detector agree.')


# --- Sections --------------------------------------------------------------

def render_verdict(result: Dict[str, Any]) -> None:
    level, headline, detail = verdict_for(
        result,
        demo_mode=st.session_state.get('demo_mode', False),
        connected=bool(st.session_state.get('aws_connected')))
    colour, background, label = LEVEL_STYLES[level]
    st.markdown(
        """<div style='background:{bg};border-left:6px solid {fg};padding:1.25rem 1.5rem;
        border-radius:10px;margin-bottom:1rem;'>
        <div style='color:{fg};font-size:0.75rem;font-weight:700;letter-spacing:0.08em;'>{label}</div>
        <div style='color:#1c2833;font-size:1.45rem;font-weight:700;margin:0.35rem 0;'>{headline}</div>
        <div style='color:#566573;font-size:0.92rem;'>{detail}</div>
        </div>""".format(bg=background, fg=colour, label=label,
                         headline=headline, detail=detail),
        unsafe_allow_html=True)


def render_detector_health(result: Dict[str, Any]) -> None:
    """Is anything watching? Plus the setup path when nothing is."""
    health = result.get('health') or {}
    status = health.get('status')
    monitors = health.get('monitors') or []

    icons = {
        det.STATUS_OK: '🟢', det.STATUS_WARMING_UP: '🟡',
        det.STATUS_NO_MONITOR: '🔴', det.STATUS_ACCESS_DENIED: '🔴',
        det.STATUS_NO_CLIENT: '⚪', det.STATUS_ERROR: '🔴',
    }
    baseline_ok = result.get('baseline_status') == det.STATUS_OK

    with st.expander('{0} Detector health - {1}'.format(
            icons.get(status, '⚪'), health.get('verdict', 'Unknown')),
            expanded=status in (det.STATUS_NO_MONITOR, det.STATUS_ACCESS_DENIED,
                                det.STATUS_ERROR)):
        left, right = st.columns(2)
        with left:
            st.markdown('**AWS Cost Anomaly Detection**')
            st.write(health.get('message', 'Unknown'))
            for monitor in monitors:
                st.caption('`{0}` - {1}, {2} day(s) old, last evaluated {3}'.format(
                    monitor['name'], monitor.get('dimension') or monitor['type'],
                    monitor.get('age_days', '?'),
                    monitor['last_evaluated'].strftime('%Y-%m-%d')
                    if monitor.get('last_evaluated') else 'never'))
        with right:
            st.markdown('**Baseline detector (this app)**')
            if baseline_ok:
                st.write('Running - {0}'.format(result.get('baseline_message', '')))
                st.caption('median + MAD over each service\'s own daily history')
            else:
                st.warning('Not running: {0}'.format(
                    result.get('baseline_message') or result.get('baseline_status')))

        if status == det.STATUS_ACCESS_DENIED:
            st.error('Missing IAM permissions. The role needs: `ce:GetAnomalies`, '
                     '`ce:GetAnomalyMonitors`, `ce:GetCostAndUsage`.')

        if status == det.STATUS_NO_MONITOR:
            _render_monitor_setup()


def _render_monitor_setup() -> None:
    """Creating a monitor writes to AWS, so it sits behind an explicit gate."""
    st.markdown('---')
    st.markdown('#### Create an AWS anomaly monitor')
    st.info('A SERVICE-dimension monitor watches every service in the account. '
            'AWS needs about {0} days to build a baseline before it reports '
            'anything - the baseline detector above covers you meanwhile.'
            .format(det.BASELINE_DAYS))

    name = st.text_input('Monitor name', value='finops-service-monitor',
                         key='anomaly_monitor_name')
    email = st.text_input('Alert email (optional)', key='anomaly_monitor_email',
                          placeholder='finops@example.com')
    threshold = st.number_input('Alert above (USD impact)', min_value=1.0,
                                value=100.0, step=10.0, key='anomaly_monitor_threshold')

    confirmed = st.checkbox(
        'I understand this creates a real resource in the connected AWS account',
        key='anomaly_monitor_confirm')

    if st.button('Create monitor', type='primary', disabled=not confirmed,
                 key='anomaly_monitor_create'):
        outcome = det.create_anomaly_monitor(name)
        if outcome['status'] != det.STATUS_OK:
            st.error(outcome['message'])
            return
        st.success(outcome['message'])
        if email:
            sub = det.create_anomaly_subscription(outcome['arn'], email, threshold)
            if sub['status'] == det.STATUS_OK:
                st.success(sub['message'])
            else:
                st.warning('Monitor created, but the email subscription failed: {0}'
                           .format(sub['message']))
        st.session_state.pop('anomaly_result', None)
        st.rerun()


def render_anomaly_table(result: Dict[str, Any], states: Dict[str, Any]) -> None:
    anomalies = result.get('anomalies') or []
    if not anomalies:
        return

    st.markdown('### Findings')
    rows = []
    for anomaly in anomalies:
        state = states.get(anomaly['id'], {})
        rows.append({
            'Status': state.get('status', 'new'),
            'Service': anomaly.get('service', 'Unknown'),
            'Impact': format_cost(anomaly.get('total_impact', 0)),
            'Expected': format_cost(anomaly.get('total_expected_spend', 0)),
            'Actual': format_cost(anomaly.get('total_actual_spend', 0)),
            'Window': '{0} → {1}'.format(str(anomaly.get('start_date'))[:10],
                                         str(anomaly.get('end_date'))[:10]),
            'Account': str(anomaly.get('account', 'all'))[:12],
            'Source': 'AWS + baseline' if anomaly.get('confirmed') else (
                'AWS CAD' if anomaly.get('source') == 'aws_cad' else 'Baseline'),
        })

    try:
        import pandas as pd
        st.dataframe(pd.DataFrame(rows), width='stretch', hide_index=True)
    except ImportError:
        st.table(rows)


def render_anomaly_detail(anomaly: Dict[str, Any], series: Dict[str, Dict[str, float]],
                          states: Dict[str, Any]) -> None:
    """One expandable finding: chart, causes, AI explanation, working state."""
    anomaly_id = anomaly['id']
    state = states.get(anomaly_id, {})
    badge = '✅' if anomaly.get('confirmed') else (
        '🔶' if anomaly.get('source') == 'aws_cad' else '🔷')
    title = '{0} {1} · {2} · {3} → {4}'.format(
        badge, anomaly.get('service', 'Unknown'),
        format_cost(anomaly.get('total_impact', 0)),
        str(anomaly.get('start_date'))[:10], str(anomaly.get('end_date'))[:10])
    if state.get('status') and state['status'] != 'new':
        title += '  [{0}]'.format(state['status'])

    with st.expander(title):
        columns = st.columns(4)
        columns[0].metric('Impact', format_cost(anomaly.get('total_impact', 0)))
        columns[1].metric('Expected', format_cost(anomaly.get('total_expected_spend', 0)))
        columns[2].metric('Actual', format_cost(anomaly.get('total_actual_spend', 0)))
        columns[3].metric('Detected by',
                          'Both' if anomaly.get('confirmed') else
                          ('AWS' if anomaly.get('source') == 'aws_cad' else 'Baseline'))

        _render_series_chart(anomaly, series)

        causes = anomaly.get('root_causes') or []
        if causes:
            st.markdown('**AWS root causes**')
            for cause in causes:
                st.caption(' · '.join(
                    '{0}: {1}'.format(k, v) for k, v in cause.items() if v))

        if STORE_AVAILABLE:
            history = sighting_history(anomaly.get('service', 'Unknown'))
            if len(history) > 1:
                st.warning('{0} has been flagged {1} times in recorded history - '
                           'this is a pattern, not a one-off.'.format(
                               anomaly.get('service'), len(history)))

        _render_ai_section(anomaly, series)
        _render_state_controls(anomaly, state)


def _render_series_chart(anomaly: Dict[str, Any],
                         series: Dict[str, Dict[str, float]]) -> None:
    service_series = series.get(anomaly.get('service', ''), {})
    if not service_series or not PLOTLY_AVAILABLE:
        return
    dates = sorted(service_series)
    values = [service_series[d] for d in dates]

    figure = go.Figure()
    figure.add_trace(go.Scatter(x=dates, y=values, mode='lines',
                                name='Daily cost', line={'color': '#2e86c1'}))
    start = str(anomaly.get('start_date'))[:10]
    end = str(anomaly.get('end_date'))[:10] or start
    if start in service_series or end in service_series:
        figure.add_vrect(x0=start, x1=end, fillcolor='#e74c3c', opacity=0.18,
                         line_width=0, annotation_text='anomaly')
    figure.update_layout(height=260, margin={'l': 10, 'r': 10, 't': 30, 'b': 10},
                         title='{0} - daily unblended cost'.format(anomaly.get('service')),
                         yaxis_title='USD', showlegend=False)
    st.plotly_chart(figure, width='stretch')


def _render_ai_section(anomaly: Dict[str, Any],
                       series: Dict[str, Dict[str, float]]) -> None:
    st.markdown('**Explanation**')
    if not AI_AVAILABLE:
        st.caption('AI explanations unavailable - finops_anomaly_ai module not loaded.')
        return

    status = ai_status()
    if not status['available']:
        st.caption(status['message'])
        return

    cache_key = 'anomaly_ai_{0}'.format(anomaly['id'])
    if st.button('Explain this anomaly', key='btn_' + cache_key):
        with st.spinner('Analysing the cost series...'):
            # the whole series dict, so the model can see what else moved that day
            st.session_state[cache_key] = explain_anomaly(anomaly, series)

    explanation = st.session_state.get(cache_key)
    if not explanation:
        return
    if explanation.get('error'):
        st.error(explanation['error'])
        return

    st.info('**Probable cause:** {0}'.format(explanation.get('probable_cause', '')))
    columns = st.columns(2)
    columns[0].metric('Pattern', explanation.get('pattern', 'unknown'))
    columns[1].metric('Confidence', explanation.get('confidence', 'unknown'))
    if explanation.get('recurring_cost_risk'):
        st.warning(explanation['recurring_cost_risk'])
    actions = explanation.get('recommended_actions') or []
    if actions:
        st.markdown('**Recommended actions**')
        for action in actions:
            st.markdown('- {0}'.format(action))
    if explanation.get('investigation_steps'):
        st.markdown('**How to confirm**')
        for step in explanation['investigation_steps']:
            st.markdown('- {0}'.format(step))
    st.caption('Generated by {0}. Check it against the numbers above.'.format(
        explanation.get('model', 'Claude')))


def _render_state_controls(anomaly: Dict[str, Any], state: Dict[str, Any]) -> None:
    if not STORE_AVAILABLE:
        return
    st.markdown('---')
    persistence = backend_status()
    if not persistence['persistent']:
        st.caption('⚠️ {0}'.format(persistence['message']))
    left, middle, right = st.columns([1, 2, 1])
    with left:
        current = state.get('status', 'new')
        choice = st.selectbox('Status', STATUSES,
                              index=STATUSES.index(current) if current in STATUSES else 0,
                              key='status_' + anomaly['id'])
    with middle:
        note = st.text_input('Note', value=state.get('note', ''),
                             key='note_' + anomaly['id'],
                             placeholder='e.g. expected - migration cutover')
    with right:
        st.write('')
        if st.button('Save', key='save_' + anomaly['id']):
            saved = save_state(anomaly, status=choice, note=note)
            if saved.get('ok'):
                st.success('Saved')
                st.session_state.pop('anomaly_states', None)
            else:
                st.warning(saved.get('message', 'Could not save'))


# --- Entry point -----------------------------------------------------------

def render_anomaly_page() -> None:
    # The host app renders the page title and subtitle; repeating them here
    # gave the page two headings.
    st.caption('AWS Cost Anomaly Detection plus an independent baseline detector, '
               'cross-referenced. A finding both agree on is the strongest signal.')

    controls = st.columns([1, 1, 1, 1])
    days = controls[0].selectbox('Lookback', [30, 60, 90, 180], index=2,
                                 key='anomaly_days')
    sensitivity = controls[1].slider('Sensitivity', 2.0, 6.0,
                                     det.DEFAULT_SENSITIVITY, 0.5,
                                     key='anomaly_sensitivity',
                                     help='Lower finds more, and more noise.')
    with controls[2]:
        auto_impact = st.checkbox(
            'Scale threshold to this account', value=True,
            key='anomaly_auto_impact',
            help='A fixed dollar floor cannot suit every account. On this '
                 'setting the threshold is a quarter of the median daily '
                 'spend, and the figure used is shown below.')
        min_impact = None
        if not auto_impact:
            min_impact = st.number_input('Min impact $/day', min_value=0.0,
                                         value=det.DEFAULT_MIN_IMPACT, step=1.0,
                                         key='anomaly_min_impact')
    controls[3].write('')
    refresh = controls[3].button('🔄 Run detection', type='primary',
                                 key='anomaly_refresh')

    # The connection is part of the signature. Without it, a detection that ran
    # before AWS was connected stayed cached afterwards, so the page kept
    # reporting "not connected" long after the sidebar said otherwise.
    signature = (days, sensitivity, min_impact,
                 bool(st.session_state.get('aws_connected')),
                 st.session_state.get('aws_account_id'),
                 bool(st.session_state.get('demo_mode')))
    if refresh or st.session_state.get('anomaly_signature') != signature:
        with st.spinner('Checking detectors and scanning cost history...'):
            st.session_state['anomaly_result'] = det.detect_all(
                days=days, sensitivity=sensitivity, min_impact=min_impact)
            st.session_state['anomaly_signature'] = signature
            st.session_state.pop('anomaly_states', None)

    result = st.session_state.get('anomaly_result')
    if result is None:
        st.info('Press **Run detection** to scan.')
        return

    if STORE_AVAILABLE and 'anomaly_states' not in st.session_state:
        st.session_state['anomaly_states'] = load_states()
    states = st.session_state.get('anomaly_states') or {}

    render_verdict(result)
    render_detector_health(result)

    anomalies = result.get('anomalies') or []
    if STORE_AVAILABLE and anomalies:
        record_sighting(anomalies)

    if not anomalies:
        return

    summary = st.columns(4)
    summary[0].metric('Findings', len(anomalies))
    summary[1].metric('Total impact', format_cost(result.get('total_impact', 0)))
    summary[2].metric('Confirmed by both', result.get('confirmed_count', 0))
    summary[3].metric('Services affected',
                      len({a.get('service') for a in anomalies}))

    used = result.get('min_impact_used')
    if used is not None:
        st.caption('Reporting daily increases of {0} or more{1}.'.format(
            format_cost(used),
            ' (scaled to this account)' if result.get('min_impact_auto') else ''))

    render_anomaly_table(result, states)

    st.markdown('### Detail')
    series = result.get('series') or {}
    for anomaly in anomalies:
        render_anomaly_detail(anomaly, series, states)
