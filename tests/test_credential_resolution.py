"""
Tests for AWS credential resolution from Streamlit secrets.

The regression under test: uppercase AWS_* names placed INSIDE the [aws]
section resolved to nothing, because uppercase was only recognised at the top
level and lowercase only inside the section. The app reported "no AWS
credentials" while the secrets were sitting right there.

Run:  python -m pytest tests/test_credential_resolution.py -q
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def resolver(monkeypatch):
    """Import the resolver with a stubbed st.secrets."""
    import streamlit_app

    def install(secrets, env=None):
        monkeypatch.setattr(streamlit_app, 'st',
                            types.SimpleNamespace(secrets=secrets,
                                                  session_state={}))
        for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                     'AWS_DEFAULT_REGION', 'AWS_REGION', 'AWS_SESSION_TOKEN'):
            monkeypatch.delenv(name, raising=False)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        return streamlit_app.resolve_aws_credentials

    return install


class Secrets(dict):
    """dict with st.secrets' .get semantics."""


KEY = 'AKIAIOSFODNN7EXAMPLE'
SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


# --- The reported failure --------------------------------------------------

def test_uppercase_keys_inside_the_aws_section_resolve(resolver):
    """Exactly the layout in the user's Streamlit Cloud secrets."""
    resolve = resolver(Secrets({
        'ANTHROPIC_API_KEY': 'sk-ant-api03-x',
        'aws': {
            'AWS_ACCESS_KEY_ID': KEY,
            'AWS_SECRET_ACCESS_KEY': SECRET,
            'AWS_DEFAULT_REGION': 'us-east-1',
        },
    }))
    creds = resolve()
    assert creds['access_key'] == KEY
    assert creds['secret_key'] == SECRET
    assert creds['region'] == 'us-east-1'


def test_that_layout_now_counts_as_having_credentials(resolver):
    """has_aws is bool(access_key and secret_key) - it must be True here."""
    resolve = resolver(Secrets({'aws': {'AWS_ACCESS_KEY_ID': KEY,
                                        'AWS_SECRET_ACCESS_KEY': SECRET}}))
    creds = resolve()
    assert bool(creds['access_key'] and creds['secret_key']) is True


# --- Every other layout has to keep working --------------------------------

def test_lowercase_keys_inside_the_section(resolver):
    resolve = resolver(Secrets({'aws': {'access_key_id': KEY,
                                        'secret_access_key': SECRET,
                                        'region': 'eu-west-1'}}))
    creds = resolve()
    assert creds['access_key'] == KEY
    assert creds['region'] == 'eu-west-1'


def test_management_prefixed_keys(resolver):
    resolve = resolver(Secrets({'aws': {'management_access_key_id': KEY,
                                        'management_secret_access_key': SECRET}}))
    assert resolve()['access_key'] == KEY


def test_flat_top_level_keys(resolver):
    resolve = resolver(Secrets({'AWS_ACCESS_KEY_ID': KEY,
                                'AWS_SECRET_ACCESS_KEY': SECRET}))
    assert resolve()['secret_key'] == SECRET


def test_environment_variables(resolver):
    resolve = resolver(Secrets({}), env={'AWS_ACCESS_KEY_ID': KEY,
                                         'AWS_SECRET_ACCESS_KEY': SECRET})
    assert resolve()['access_key'] == KEY


def test_mixed_case_is_tolerated(resolver):
    resolve = resolver(Secrets({'aws': {'Aws_Access_Key_Id': KEY,
                                        'Secret_Access_Key': SECRET}}))
    assert resolve()['access_key'] == KEY


def test_session_token_for_temporary_credentials(resolver):
    resolve = resolver(Secrets({'aws': {'AWS_ACCESS_KEY_ID': 'ASIA' + KEY[4:],
                                        'AWS_SECRET_ACCESS_KEY': SECRET,
                                        'AWS_SESSION_TOKEN': 'tok'}}))
    assert resolve()['session_token'] == 'tok'


# --- Precedence and edges --------------------------------------------------

def test_section_wins_over_top_level(resolver):
    resolve = resolver(Secrets({'AWS_ACCESS_KEY_ID': 'TOPLEVEL',
                                'aws': {'AWS_ACCESS_KEY_ID': KEY,
                                        'AWS_SECRET_ACCESS_KEY': SECRET}}))
    assert resolve()['access_key'] == KEY


def test_secrets_win_over_environment(resolver):
    resolve = resolver(Secrets({'aws': {'AWS_ACCESS_KEY_ID': KEY,
                                        'AWS_SECRET_ACCESS_KEY': SECRET}}),
                       env={'AWS_ACCESS_KEY_ID': 'FROMENV'})
    assert resolve()['access_key'] == KEY


def test_region_defaults_when_absent(resolver):
    resolve = resolver(Secrets({'aws': {'AWS_ACCESS_KEY_ID': KEY,
                                        'AWS_SECRET_ACCESS_KEY': SECRET}}))
    assert resolve()['region'] == 'us-east-1'


def test_aws_region_is_accepted_as_well_as_default_region(resolver):
    resolve = resolver(Secrets({'aws': {'AWS_REGION': 'ap-south-1'}}))
    assert resolve()['region'] == 'ap-south-1'


def test_values_are_stripped(resolver):
    """Trailing whitespace in a pasted secret is a classic silent failure."""
    resolve = resolver(Secrets({'aws': {'AWS_ACCESS_KEY_ID': '  ' + KEY + '  ',
                                        'AWS_SECRET_ACCESS_KEY': SECRET + '\n'}}))
    creds = resolve()
    assert creds['access_key'] == KEY
    assert creds['secret_key'] == SECRET


def test_no_secrets_at_all_returns_blanks_not_an_exception(resolver):
    class Exploding:
        def get(self, *args, **kwargs):
            raise RuntimeError('No secrets found')

        def items(self):
            raise RuntimeError('No secrets found')

    resolve = resolver(Exploding())
    creds = resolve()
    assert creds['access_key'] == ''
    assert creds['region'] == 'us-east-1'


def test_nested_sections_are_not_mistaken_for_credentials(resolver):
    resolve = resolver(Secrets({'firebase': {'AWS_ACCESS_KEY_ID': 'WRONG'},
                                'aws': {'AWS_ACCESS_KEY_ID': KEY,
                                        'AWS_SECRET_ACCESS_KEY': SECRET}}))
    assert resolve()['access_key'] == KEY
