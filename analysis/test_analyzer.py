# test_analyzer.py
import sys
import types

import pytest

import analyzer
from backup_texts import BACKUP_TEXTS

SUPPORTED_TYPES = ["SQL Injection", "XSS", "Command Injection", "Hardcoded Secrets"]


def make_finding(vuln_type, finding_id="V001"):
    return {
        "id": finding_id,
        "type": vuln_type,
        "cwe": "CWE-0",
        "language": "python",
        "line": 10,
        "severity": "High",
        "code_snippet": "example",
    }


@pytest.fixture
def no_llm(monkeypatch):
    """Make the LLM unavailable so the tests use the backup texts."""
    monkeypatch.setattr(analyzer, "ask_llm", lambda finding: None)


@pytest.mark.parametrize("vuln_type", SUPPORTED_TYPES)
def test_supported_type_returns_three_fields(no_llm, vuln_type):
    result = analyzer.analyze_finding(make_finding(vuln_type))
    for field in ("impact", "explanation", "recommendation"):
        assert isinstance(result[field], str)
        assert result[field].strip() != ""


def test_same_id_is_returned(no_llm):
    result = analyzer.analyze_finding(make_finding("XSS", "V042"))
    assert result["id"] == "V042"


def test_unsupported_type_returns_error(no_llm):
    result = analyzer.analyze_finding(make_finding("Buffer Overflow"))
    assert "error" in result
    assert "impact" not in result


def test_backup_text_used_when_llm_fails(no_llm):
    result = analyzer.analyze_finding(make_finding("SQL Injection"))
    assert result["impact"] == BACKUP_TEXTS["SQL Injection"]["impact"]


def test_llm_text_used_when_llm_works(monkeypatch):
    fake = {"impact": "i", "explanation": "e", "recommendation": "r"}
    monkeypatch.setattr(analyzer, "ask_llm", lambda finding: fake)
    result = analyzer.analyze_finding(make_finding("SQL Injection"))
    assert result == {
        "id": "V001",
        "impact": "i",
        "explanation": "e",
        "recommendation": "r",
    }


def test_backup_texts_cover_all_four_types():
    assert set(BACKUP_TEXTS) == set(SUPPORTED_TYPES)


SECRET = "sk-live-9f2a41c7e0b8"


def secret_finding(snippet):
    finding = make_finding("Hardcoded Secrets")
    finding["code_snippet"] = snippet
    return finding


def test_mask_secret_hides_quoted_value():
    masked = analyzer.mask_secret('API_KEY = "' + SECRET + '"')
    assert SECRET not in masked
    assert masked == 'API_KEY = "***"'


def test_mask_secret_hides_unquoted_value():
    masked = analyzer.mask_secret("API_KEY = " + SECRET)
    assert SECRET not in masked
    assert "***" in masked


def test_message_for_llm_has_no_secret():
    message = analyzer.build_message(secret_finding('API_KEY = "' + SECRET + '"'))
    assert SECRET not in message
    assert "***" in message


def test_other_types_are_not_masked():
    finding = make_finding("SQL Injection")
    finding["code_snippet"] = "cur.execute('SELECT ' + name)"
    message = analyzer.build_message(finding)
    assert "cur.execute('SELECT ' + name)" in message


def test_secret_is_not_sent_to_the_llm(monkeypatch):
    """The text that reaches the (fake) LLM client must not contain the secret."""
    sent = {}

    class FakeClient:
        def __init__(self, **kwargs):
            self.messages = self

        def create(self, **kwargs):
            sent["text"] = kwargs["messages"][0]["content"]
            block = types.SimpleNamespace(
                text='{"impact": "i", "explanation": "e", "recommendation": "r"}'
            )
            return types.SimpleNamespace(content=[block])

    fake_module = types.SimpleNamespace(Anthropic=FakeClient)
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = analyzer.ask_llm(secret_finding('API_KEY = "' + SECRET + '"'))

    assert result is not None
    assert SECRET not in sent["text"]
    assert "***" in sent["text"]
