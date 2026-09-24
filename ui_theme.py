"""
Cloud Compliance Canvas - design system
=======================================
One place for the visual language, so every screen inherits it instead of each
page inventing its own look.

The governing idea: this is an operations console, not a marketing page.
Saturation is reserved for status - chrome is grey. Where the old UI painted
healthy services in amber, which in ops semantics reads as degraded, colour
here means exactly one thing: green is fine, amber is degraded, red needs you,
grey is unknown. "Unknown" is a first-class state; a console that renders
"we could not check" in the same green as "we checked and it is fine" is
lying to its operator.

Type is IBM Plex Sans with Plex Mono for identifiers and figures. Plex was
drawn for enterprise software and has real tabular figures, so columns of
dollars and account IDs line up instead of shimmering.

Version: 1.0.0
"""

from typing import Optional

import streamlit as st

# --- Tokens ----------------------------------------------------------------

CANVAS = '#EEF1F5'      # cool paper, not cream
SURFACE = '#FFFFFF'
SURFACE_SUNK = '#F7F9FB'
INK = '#1A2332'         # cool graphite
INK_MUTED = '#5A6B80'
INK_FAINT = '#8494A8'
LINE = '#D6DEE8'
LINE_STRONG = '#B9C5D4'
PRIMARY = '#0B4F6C'     # petrol - institutional, calm, not AWS orange
PRIMARY_SOFT = '#E3EDF2'

OK = '#1E7A4D'
OK_SOFT = '#E6F4EC'
WARN = '#B06A00'
WARN_SOFT = '#FDF2E0'
CRITICAL = '#B3261E'
CRITICAL_SOFT = '#FBEAE8'
UNKNOWN = '#5A6B80'
UNKNOWN_SOFT = '#ECEFF3'

STATES = {
    'ok': (OK, OK_SOFT),
    'warn': (WARN, WARN_SOFT),
    'critical': (CRITICAL, CRITICAL_SOFT),
    'unknown': (UNKNOWN, UNKNOWN_SOFT),
    'info': (PRIMARY, PRIMARY_SOFT),
}


def inject_theme() -> None:
    """
    Load fonts and the global stylesheet. Call once, after set_page_config.

    Blank lines are stripped before injection. Streamlit renders markdown
    first, and a blank line inside a raw HTML block ends that block - which
    dumps the rest of the stylesheet onto the page as visible text.
    """
    compact = '\n'.join(line for line in _STYLESHEET.splitlines() if line.strip())
    st.markdown(compact, unsafe_allow_html=True)


# Fonts come in via @import rather than <link>: Streamlit strips <link> tags,
# so a linked font silently never loads.
_STYLESHEET = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root {
    --cc-canvas: #EEF1F5;
    --cc-surface: #FFFFFF;
    --cc-sunk: #F7F9FB;
    --cc-ink: #1A2332;
    --cc-muted: #5A6B80;
    --cc-faint: #8494A8;
    --cc-line: #D6DEE8;
    --cc-line-strong: #B9C5D4;
    --cc-primary: #0B4F6C;
    --cc-primary-soft: #E3EDF2;
    --cc-ok: #1E7A4D;
    --cc-warn: #B06A00;
    --cc-critical: #B3261E;
    --cc-unknown: #5A6B80;
    --cc-radius: 6px;
}

/* ---------- Base ---------- */
html, body, [class*="css"], .stApp {
    font-family: 'IBM Plex Sans', -apple-system, 'Segoe UI', sans-serif;
    color: var(--cc-ink);
}
.stApp { background: var(--cc-canvas); }
.block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1560px; }

/* Streamlit scopes its own heading font with a class, which outranks a bare
   element selector - hence .stApp and the explicit !important on the family. */
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6,
[data-testid="stMarkdownContainer"] h1, [data-testid="stMarkdownContainer"] h2,
[data-testid="stMarkdownContainer"] h3, [data-testid="stMarkdownContainer"] h4 {
    font-family: 'IBM Plex Sans', -apple-system, 'Segoe UI', sans-serif !important;
    color: var(--cc-ink);
    letter-spacing: -0.012em;
    font-weight: 600;
}
h1 { font-size: 1.72rem; line-height: 1.2; }
h2 { font-size: 1.28rem; line-height: 1.25; margin-top: 1.6rem; }
h3 { font-size: 1.06rem; line-height: 1.3; margin-top: 1.2rem; }
h4 { font-size: 0.95rem; }
p, li, label, .stMarkdown { font-size: 0.925rem; line-height: 1.55; }

code, pre, .stCode, [data-testid="stMetricValue"] {
    font-family: 'IBM Plex Mono', ui-monospace, monospace;
}
code {
    background: var(--cc-sunk);
    border: 1px solid var(--cc-line);
    border-radius: 3px;
    padding: 0.08em 0.34em;
    font-size: 0.86em;
    color: var(--cc-ink);
}

/* Streamlit's own top chrome competes with the app header */
[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer { visibility: hidden; }

/* ---------- Sidebar ---------- */
[data-testid="stSidebar"] {
    background: #FFFFFF;
    border-right: 1px solid var(--cc-line);
}
[data-testid="stSidebar"] .block-container { padding-top: 1.1rem; }
[data-testid="stSidebar"] hr { margin: 0.85rem 0; border-color: var(--cc-line); }

/* Navigation rows are buttons; secondary = inactive, primary = current */
[data-testid="stSidebar"] .stButton > button {
    width: 100%;
    text-align: left;
    justify-content: flex-start;
    font-size: 0.895rem;
    font-weight: 500;
    padding: 0.4rem 0.7rem;
    border-radius: 5px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--cc-ink);
    box-shadow: none;
    min-height: 0;
    transition: background 120ms ease, color 120ms ease;
}
/* The label sits in a nested element, so aligning the button is not enough */
[data-testid="stSidebar"] .stButton > button > div,
[data-testid="stSidebar"] .stButton > button p {
    text-align: left;
    width: 100%;
    justify-content: flex-start;
    margin: 0;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background: var(--cc-sunk);
    color: var(--cc-primary);
    border-color: var(--cc-line);
}
[data-testid="stSidebar"] .stButton > button[kind="primary"],
[data-testid="stSidebar"] .stButton > button[data-testid="stBaseButton-primary"] {
    background: var(--cc-primary-soft);
    color: var(--cc-primary);
    font-weight: 600;
    border-color: transparent;
    border-left: 3px solid var(--cc-primary);
    padding-left: calc(0.7rem - 2px);
}
[data-testid="stSidebar"] .stButton > button:focus-visible {
    outline: 2px solid var(--cc-primary);
    outline-offset: 1px;
}

.cc-navgroup {
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--cc-faint);
    letter-spacing: 0.01em;
    margin: 0.95rem 0 0.3rem 0.2rem;
}
.cc-brand {
    display: flex; align-items: baseline; gap: 0.5rem;
    padding: 0.1rem 0 0.7rem;
    border-bottom: 1px solid var(--cc-line);
    margin-bottom: 0.4rem;
}
.cc-brand-name { font-size: 1rem; font-weight: 600; color: var(--cc-ink); }
.cc-brand-env {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.66rem; font-weight: 500;
    padding: 0.1rem 0.36rem; border-radius: 3px;
    background: var(--cc-sunk); color: var(--cc-muted);
    border: 1px solid var(--cc-line);
}

/* ---------- Cards: 1px border, no shadow, status carried by a left rail ---------- */
.cc-card {
    background: var(--cc-surface);
    border: 1px solid var(--cc-line);
    border-left: 3px solid var(--cc-line-strong);
    border-radius: var(--cc-radius);
    padding: 0.85rem 1rem;
    margin-bottom: 0.6rem;
}
.cc-card[data-state="ok"] { border-left-color: var(--cc-ok); }
.cc-card[data-state="warn"] { border-left-color: var(--cc-warn); }
.cc-card[data-state="critical"] { border-left-color: var(--cc-critical); }
.cc-card[data-state="unknown"] { border-left-color: var(--cc-unknown); }
.cc-card-title {
    font-size: 0.815rem; font-weight: 600; color: var(--cc-muted);
    margin-bottom: 0.3rem;
}
.cc-card-value {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.35rem; font-weight: 500; color: var(--cc-ink);
    font-variant-numeric: tabular-nums;
}
.cc-card-note { font-size: 0.78rem; color: var(--cc-faint); margin-top: 0.22rem; }

.cc-statuschip {
    display: inline-flex; align-items: center; gap: 0.32rem;
    font-size: 0.735rem; font-weight: 600;
    padding: 0.12rem 0.46rem; border-radius: 3px;
    border: 1px solid transparent;
}
.cc-statuschip .cc-dot {
    width: 6px; height: 6px; border-radius: 50%; background: currentColor;
}

/* ---------- Page header ---------- */
.cc-pagehead { margin-bottom: 1.1rem; }
.cc-pagehead h1 { margin: 0 0 0.18rem; }
.cc-pagehead p {
    margin: 0; color: var(--cc-muted); font-size: 0.9rem; max-width: 74ch;
}

/* ---------- Metrics ---------- */
[data-testid="stMetric"] {
    background: var(--cc-surface);
    border: 1px solid var(--cc-line);
    border-radius: var(--cc-radius);
    padding: 0.7rem 0.85rem;
}
[data-testid="stMetricLabel"] p {
    font-size: 0.78rem !important; font-weight: 600; color: var(--cc-muted);
}
[data-testid="stMetricValue"] {
    font-size: 1.4rem; font-weight: 500; color: var(--cc-ink);
    font-variant-numeric: tabular-nums;
}

/* ---------- Tabs (sub-navigation within a page) ---------- */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.12rem;
    border-bottom: 1px solid var(--cc-line);
    background: transparent;
    flex-wrap: wrap;
}
.stTabs [data-baseweb="tab"] {
    height: auto; padding: 0.45rem 0.8rem;
    background: transparent; border-radius: 4px 4px 0 0;
    font-size: 0.875rem; font-weight: 500; color: var(--cc-muted);
    border-bottom: 2px solid transparent;
}
.stTabs [data-baseweb="tab"]:hover { color: var(--cc-primary); background: var(--cc-sunk); }
.stTabs [aria-selected="true"] {
    color: var(--cc-primary) !important; font-weight: 600;
    border-bottom-color: var(--cc-primary) !important;
    background: transparent !important;
}
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] { display: none; }

/* ---------- Alerts use the status palette ---------- */
[data-testid="stAlert"] {
    border-radius: var(--cc-radius);
    border: 1px solid var(--cc-line);
    border-left-width: 3px;
    padding: 0.7rem 0.9rem;
    font-size: 0.895rem;
}

/* ---------- Expanders ---------- */
[data-testid="stExpander"] {
    border: 1px solid var(--cc-line);
    border-radius: var(--cc-radius);
    background: var(--cc-surface);
}
[data-testid="stExpander"] summary { font-size: 0.895rem; font-weight: 500; }

/* ---------- Tables ---------- */
[data-testid="stDataFrame"] {
    border: 1px solid var(--cc-line);
    border-radius: var(--cc-radius);
    font-variant-numeric: tabular-nums;
}

/* ---------- Buttons in the main area ----------
   Scoped to stMain so the sidebar's nav buttons keep their own treatment;
   ".main" no longer exists in current Streamlit, which is why the primary
   button stayed AWS orange.                                              */
[data-testid="stMain"] .stButton > button {
    border-radius: 5px;
    font-size: 0.885rem;
    font-weight: 500;
    border: 1px solid var(--cc-line-strong);
}
[data-testid="stMain"] .stButton > button[kind="primary"],
[data-testid="stMain"] [data-testid="stBaseButton-primary"] {
    background: var(--cc-primary) !important;
    border-color: var(--cc-primary) !important;
    color: #FFFFFF !important;
}
[data-testid="stMain"] .stButton > button[kind="primary"]:hover {
    background: #0D6485 !important;
}

/* ---------- Inputs ---------- */
[data-baseweb="select"] > div, .stTextInput input, .stNumberInput input {
    border-radius: 5px !important;
    border-color: var(--cc-line-strong) !important;
    font-size: 0.89rem;
}

/* ---------- Legacy overrides ----------
   The old stylesheet painted healthy services in AWS orange. In an operations
   console amber means degraded, so a green service rendered as a warning.
   Status colour now means one thing only.                                  */
.service-badge {
    display: inline-flex; align-items: center; gap: 0.32rem;
    padding: 0.1rem 0.44rem !important;
    border-radius: 3px !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    margin: 0 !important;
    text-transform: lowercase;
    border: 1px solid transparent;
}
.service-badge::first-letter { text-transform: uppercase; }
.service-badge.active {
    background: #E6F4EC !important; color: #1E7A4D !important;
    border-color: #1E7A4D33;
}
.service-badge.inactive {
    background: #ECEFF3 !important; color: #5A6B80 !important;
    border-color: #5A6B8033;
}
.service-badge.warning {
    background: #FDF2E0 !important; color: #B06A00 !important;
    border-color: #B06A0033;
}

/* The old full-bleed gradient banner competed with the page header */
.main-header {
    background: var(--cc-surface) !important;
    border: 1px solid var(--cc-line) !important;
    border-top: 3px solid var(--cc-primary) !important;
    border-radius: var(--cc-radius) !important;
    box-shadow: none !important;
    padding: 1.1rem 1.3rem !important;
    text-align: left !important;
}
.main-header h1 { color: var(--cc-ink) !important; font-size: 1.35rem !important; }
.main-header p { color: var(--cc-muted) !important; font-size: 0.9rem !important; }

/* ---------- Motion: answer the user's action, nothing else ---------- */
@media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
}
</style>
"""


# --- Components ------------------------------------------------------------

def status_chip(label: str, state: str = 'unknown') -> str:
    """An inline status pill. Returns HTML - caller renders it."""
    colour, background = STATES.get(state, STATES['unknown'])
    return (
        '<span class="cc-statuschip" style="color:{0};background:{1};border-color:{0}33;">'
        '<span class="cc-dot"></span>{2}</span>'
    ).format(colour, background, label)


def page_header(title: str, subtitle: str = '') -> None:
    """Section title plus one line saying what question this page answers."""
    subtitle_html = '<p>{0}</p>'.format(subtitle) if subtitle else ''
    st.markdown(
        '<div class="cc-pagehead"><h1>{0}</h1>{1}</div>'.format(title, subtitle_html),
        unsafe_allow_html=True)


def status_card(title: str, value: str, state: str = 'unknown',
                note: str = '', chip: Optional[str] = None) -> None:
    """A card whose left rail carries its state."""
    chip_html = ('<div style="margin-top:0.4rem;">{0}</div>'.format(
        status_chip(chip, state)) if chip else '')
    note_html = '<div class="cc-card-note">{0}</div>'.format(note) if note else ''
    st.markdown(
        '<div class="cc-card" data-state="{state}">'
        '<div class="cc-card-title">{title}</div>'
        '<div class="cc-card-value">{value}</div>'
        '{note}{chip}</div>'.format(state=state, title=title, value=value,
                                    note=note_html, chip=chip_html),
        unsafe_allow_html=True)


def brand(name: str, environment: str = '') -> None:
    env_html = ('<span class="cc-brand-env">{0}</span>'.format(environment)
                if environment else '')
    st.markdown(
        '<div class="cc-brand"><span class="cc-brand-name">{0}</span>{1}</div>'
        .format(name, env_html), unsafe_allow_html=True)


def nav_group(label: str) -> None:
    st.markdown('<div class="cc-navgroup">{0}</div>'.format(label),
                unsafe_allow_html=True)


def render_navigation(groups, state_key: str = 'active_section',
                      default: int = 1) -> int:
    """
    Grouped sidebar navigation. Returns the active section index.

    `groups` is [(group_label, [(item_label, index), ...]), ...]. Rows are
    buttons rather than a radio so the groups can carry headings and the
    current row can be styled as a selected nav item.
    """
    if state_key not in st.session_state:
        st.session_state[state_key] = default
    active = st.session_state[state_key]

    for group_label, items in groups:
        nav_group(group_label)
        for item_label, index in items:
            if st.button(item_label, key='nav_{0}'.format(index),
                         type='primary' if index == active else 'secondary',
                         width='stretch'):
                st.session_state[state_key] = index
                st.rerun()

    return st.session_state[state_key]


def credential_row(label: str, configured: bool, required: bool = True,
                   detail: str = '', hint: str = '') -> None:
    """
    One credential's state.

    Missing-but-optional is not a failure, and rendering it in the same red as
    a broken required credential is what made this panel read as "the app is
    broken" when it was only "you have not connected AWS yet".
    """
    if configured:
        state, text = 'ok', detail or 'Connected'
    elif required:
        state, text = 'critical', hint or 'Required - not configured'
    else:
        state, text = 'unknown', hint or 'Not configured'

    colour, background = STATES[state]
    detail_html = ('<div style="font-size:0.74rem;color:{0};margin-top:0.1rem;'
                   'font-family:\'IBM Plex Mono\',monospace;">{1}</div>'
                   ).format(INK_FAINT, text)
    st.markdown(
        '<div style="display:flex;align-items:flex-start;gap:0.5rem;'
        'padding:0.34rem 0;">'
        '<span style="width:7px;height:7px;border-radius:50%;background:{0};'
        'margin-top:0.42rem;flex:0 0 auto;box-shadow:0 0 0 3px {1};"></span>'
        '<div><div style="font-size:0.865rem;font-weight:500;">{2}</div>{3}</div>'
        '</div>'.format(colour, background, label, detail_html),
        unsafe_allow_html=True)
