"""
FinOps Anomaly - AI explanation layer
=====================================
Claude's job here is to EXPLAIN an anomaly that the detectors already found,
not to find one.

That split is deliberate. An LLM asked to spot anomalies in a cost blob cannot
do reliable arithmetic over a series, and a hallucinated spike is
indistinguishable from a real one. Given a confirmed anomaly plus its numbers,
though, "what usually causes an EC2 jump of this shape" is exactly the kind of
judgement it is good at - and every claim it makes is checkable against the
figures already on screen.

Output is constrained with structured outputs (output_config.format), so the
caller gets validated JSON instead of the previous find('[')/rfind(']')
substring scrape of free text.

Version: 1.0.0
"""

import json
import os
from typing import Any, Dict, List, Optional

import streamlit as st

try:
    import anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False

MODEL = 'claude-opus-5'
MAX_TOKENS = 16000

# Keep prompts small and the analysis focused on the recent past
SERIES_DAYS = 60
CO_MOVER_COUNT = 3

SYSTEM_PROMPT = (
    "You are a FinOps analyst explaining a cost anomaly that has already been "
    "detected by two independent detectors. Your job is explanation, not "
    "detection - do not dispute that the anomaly occurred.\n\n"
    "Ground every statement in the numbers you are given. If the data does not "
    "support a specific cause, say so and set confidence to low rather than "
    "inventing a plausible-sounding one. Never invent instance IDs, account "
    "names, ticket numbers, or dollar figures that are not in the input.\n\n"
    "Distinguish carefully between a one-off spike (cost returns to baseline, "
    "the damage is bounded) and a new run rate (cost stays elevated, the "
    "monthly bill has permanently changed). That distinction decides how "
    "urgently a human should care."
)

RESPONSE_SCHEMA = {
    'type': 'object',
    'properties': {
        'probable_cause': {
            'type': 'string',
            'description': 'The most likely cause, in one or two sentences, '
                           'grounded in the supplied numbers.',
        },
        'pattern': {
            'type': 'string',
            'enum': ['one-off spike', 'new run rate', 'gradual creep',
                     'seasonal or expected', 'unclear'],
        },
        'confidence': {'type': 'string', 'enum': ['high', 'medium', 'low']},
        'recurring_cost_risk': {
            'type': 'string',
            'description': 'If this became the new run rate, the monthly impact '
                           'and why. Empty string if it is clearly a one-off.',
        },
        'recommended_actions': {
            'type': 'array',
            'items': {'type': 'string'},
            'description': 'Concrete next actions, most valuable first. 1-4 items.',
        },
        'investigation_steps': {
            'type': 'array',
            'items': {'type': 'string'},
            'description': 'How a human confirms or refutes the probable cause - '
                           'specific consoles, APIs or logs. 1-4 items.',
        },
    },
    'required': ['probable_cause', 'pattern', 'confidence', 'recurring_cost_risk',
                 'recommended_actions', 'investigation_steps'],
    'additionalProperties': False,
}


# --- Key resolution --------------------------------------------------------

def _resolve_api_key() -> Optional[str]:
    """
    Same precedence the rest of the app uses: [anthropic] api_key in secrets,
    then a flat ANTHROPIC_API_KEY secret, then the environment.
    """
    try:
        if hasattr(st, 'secrets'):
            secrets = st.secrets
            if 'anthropic' in secrets and 'api_key' in secrets['anthropic']:
                return secrets['anthropic']['api_key']
            for name in ('ANTHROPIC_API_KEY', 'anthropic_api_key',
                         'CLAUDE_API_KEY', 'claude_api_key'):
                if name in secrets:
                    return secrets[name]
    except Exception:
        pass
    return os.environ.get('ANTHROPIC_API_KEY')


def get_client():
    if not ANTHROPIC_SDK_AVAILABLE:
        return None
    key = _resolve_api_key()
    if not key:
        return None
    try:
        return anthropic.Anthropic(api_key=key)
    except Exception:
        return None


def ai_status() -> Dict[str, Any]:
    """Whether explanations can run, and if not, what to fix."""
    if not ANTHROPIC_SDK_AVAILABLE:
        return {'available': False,
                'message': 'The `anthropic` package is not installed.'}
    if not _resolve_api_key():
        return {'available': False,
                'message': 'No Anthropic API key found. Add [anthropic] api_key to '
                           '.streamlit/secrets.toml or set ANTHROPIC_API_KEY.'}
    return {'available': True, 'model': MODEL,
            'message': 'Explanations enabled ({0}).'.format(MODEL)}


# --- Prompt assembly -------------------------------------------------------

def _recent(service_series: Dict[str, float], days: int = SERIES_DAYS) -> List[str]:
    dates = sorted(service_series)[-days:]
    return ['{0}  ${1:,.2f}'.format(d, service_series[d]) for d in dates]


def _co_movers(all_series: Dict[str, Dict[str, float]], service: str,
               start_date: str, count: int = CO_MOVER_COUNT) -> List[str]:
    """
    Which other services moved most on the same day? Often the real story -
    a spike shared across services points at a region or an account event
    rather than anything specific to one service.
    """
    movers = []
    for other, by_date in all_series.items():
        if other == service or start_date not in by_date:
            continue
        dates = sorted(d for d in by_date if d < start_date)
        if len(dates) < 7:
            continue
        window = [by_date[d] for d in dates[-14:]]
        typical = sorted(window)[len(window) // 2]
        delta = by_date[start_date] - typical
        if abs(delta) >= 1:
            movers.append((abs(delta), other, typical, by_date[start_date], delta))
    movers.sort(reverse=True)
    return ['{0}: ${1:,.2f} → ${2:,.2f} ({3:+,.2f})'.format(m[1], m[2], m[3], m[4])
            for m in movers[:count]]


def build_prompt(anomaly: Dict[str, Any],
                 all_series: Dict[str, Dict[str, float]]) -> str:
    service = anomaly.get('service', 'Unknown')
    service_series = (all_series or {}).get(service, {})
    start = str(anomaly.get('start_date'))[:10]

    lines = [
        'ANOMALY',
        '  Service:          {0}'.format(service),
        '  Account:          {0}'.format(anomaly.get('account', 'unknown')),
        '  Region:           {0}'.format(anomaly.get('region', 'unknown')),
        '  Window:           {0} to {1}'.format(start, str(anomaly.get('end_date'))[:10]),
        '  Expected spend:   ${0:,.2f}'.format(anomaly.get('total_expected_spend', 0)),
        '  Actual spend:     ${0:,.2f}'.format(anomaly.get('total_actual_spend', 0)),
        '  Excess:           ${0:,.2f}'.format(anomaly.get('total_impact', 0)),
        '  Detected by:      {0}'.format(
            'AWS Cost Anomaly Detection and this app\'s baseline detector (they agree)'
            if anomaly.get('confirmed') else
            ('AWS Cost Anomaly Detection' if anomaly.get('source') == 'aws_cad'
             else 'baseline detector (median + MAD)')),
    ]

    causes = anomaly.get('root_causes') or []
    if causes:
        lines.append('  AWS root causes:')
        for cause in causes[:5]:
            lines.append('    - ' + ', '.join(
                '{0}={1}'.format(k, v) for k, v in cause.items() if v))

    if service_series:
        lines.append('')
        lines.append('DAILY UNBLENDED COST FOR {0} (last {1} days)'.format(
            service, SERIES_DAYS))
        lines.extend('  ' + row for row in _recent(service_series))

    movers = _co_movers(all_series or {}, service, start)
    if movers:
        lines.append('')
        lines.append('OTHER SERVICES THAT MOVED ON {0}'.format(start))
        lines.extend('  ' + row for row in movers)
    elif all_series:
        lines.append('')
        lines.append('No other service moved materially on {0} - this looks '
                     'specific to {1}.'.format(start, service))

    lines.append('')
    lines.append('Explain this anomaly. Judge from the series whether spend '
                 'returned to baseline afterwards or settled at a new level.')
    return '\n'.join(lines)


# --- The call --------------------------------------------------------------

def explain_anomaly(anomaly: Dict[str, Any],
                    all_series: Optional[Dict[str, Dict[str, float]]] = None
                    ) -> Dict[str, Any]:
    """
    Ask Claude to explain one already-detected anomaly.

    Returns the parsed explanation, or {'error': ...}. Never raises - a failed
    explanation must not take the page down with it.
    """
    client = get_client()
    if client is None:
        return {'error': ai_status()['message']}

    prompt = build_prompt(anomaly, all_series or {})

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            thinking={'type': 'adaptive'},
            system=[{
                'type': 'text',
                'text': SYSTEM_PROMPT,
                # Engages once the prefix is long enough to be cacheable; the
                # instructions are identical on every call, so it costs nothing
                # to mark them and saves re-reading them as the prompt grows.
                'cache_control': {'type': 'ephemeral'},
            }],
            output_config={'format': {'type': 'json_schema',
                                      'schema': RESPONSE_SCHEMA}},
            messages=[{'role': 'user', 'content': prompt}],
        )
    except anthropic.AuthenticationError:
        return {'error': 'The Anthropic API key was rejected. Check the key in '
                         '.streamlit/secrets.toml - a revoked key fails exactly '
                         'like a malformed one.'}
    except anthropic.RateLimitError:
        return {'error': 'Rate limited by the Anthropic API. Try again shortly.'}
    except anthropic.NotFoundError:
        return {'error': 'Model {0} is not available to this key.'.format(MODEL)}
    except anthropic.APIStatusError as exc:
        return {'error': 'Anthropic API error {0}: {1}'.format(
            exc.status_code, getattr(exc, 'message', exc))}
    except anthropic.APIConnectionError:
        return {'error': 'Could not reach the Anthropic API - check network access.'}
    except Exception as exc:
        return {'error': '{0}: {1}'.format(type(exc).__name__, exc)}

    if getattr(response, 'stop_reason', None) == 'refusal':
        return {'error': 'The model declined to answer this request.'}

    try:
        text = next(block.text for block in response.content
                    if getattr(block, 'type', None) == 'text')
        parsed = json.loads(text)
    except (StopIteration, ValueError, TypeError) as exc:
        return {'error': 'Could not read the model response: {0}'.format(exc)}

    parsed['model'] = MODEL
    usage = getattr(response, 'usage', None)
    if usage is not None:
        parsed['usage'] = {
            'input_tokens': getattr(usage, 'input_tokens', None),
            'output_tokens': getattr(usage, 'output_tokens', None),
            'cache_read_input_tokens': getattr(usage, 'cache_read_input_tokens', None),
        }
    return parsed
