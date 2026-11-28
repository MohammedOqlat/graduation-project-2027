# test_main.py
# Tests for the POST /analyze endpoint.
import pytest
from fastapi.testclient import TestClient

import analyzer
from main import app

client = TestClient(app)


@pytest.fixture
def no_llm(monkeypatch):
    """Make the LLM unavailable so the endpoint uses the backup texts."""
    monkeypatch.setattr(analyzer, "ask_llm", lambda finding: None)


def test_missing_id_returns_422(no_llm):
    response = client.post("/analyze", json={"type": "SQL Injection"})
    assert response.status_code == 422


def test_missing_type_returns_422(no_llm):
    response = client.post("/analyze", json={"id": "V001"})
    assert response.status_code == 422


def test_unsupported_type_returns_error_field(no_llm):
    response = client.post(
        "/analyze", json={"id": "V001", "type": "Buffer Overflow"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "V001"
    assert "error" in body
    assert "impact" not in body


def test_valid_finding_returns_analysis(no_llm):
    response = client.post("/analyze", json={"id": "V007", "type": "XSS"})
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "V007"
    for field in ("impact", "explanation", "recommendation"):
        assert body[field].strip() != ""
