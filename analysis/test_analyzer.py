# test_analyzer.py
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