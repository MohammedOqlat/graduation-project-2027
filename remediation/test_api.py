# test_api.py  -  run with:  pytest -v
# Tests for the POST /remediate endpoint in main.py.
import httpx                                    # to create the "Detection is down" error
import pytest                                   # the test framework
from fastapi.testclient import TestClient       # calls our API without starting a real server

import remediator                               # we replace its rescan() in one test
from conftest import VULNERABLE_SAMPLE          # the vulnerable sample code
from main import app                            # the application we test

client = TestClient(app)                        # a fake browser for our app


def test_remediate_returns_fixed_code_and_summary(real_detector):
    response = client.post("/remediate", json={"code": VULNERABLE_SAMPLE})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["verified"] is True
    assert body["summary"]["fixed"] == 5
    assert "os.environ.get('API_KEY')" in body["fixed_code"]
    assert body["results"][0]["id"] == "V001"                        # the same ids as Detection


def test_remediate_accepts_the_findings_of_detection(real_detector):
    findings = real_detector.detect(VULNERABLE_SAMPLE)               # what POST /detect returns
    response = client.post("/remediate", json={"code": VULNERABLE_SAMPLE, "findings": findings})
    assert response.status_code == 200
    assert [item["status"] for item in response.json()["results"]] == ["Fixed"] * 5


def test_empty_code_returns_422():
    response = client.post("/remediate", json={"code": "   "})
    assert response.status_code == 422


def test_unsupported_language_returns_422():
    response = client.post("/remediate", json={"code": "x = 1", "language": "javascript"})
    assert response.status_code == 422


def test_invalid_python_returns_422():
    response = client.post("/remediate", json={"code": "def broken(:", "findings": []})
    assert response.status_code == 422


def test_missing_code_returns_422():
    response = client.post("/remediate", json={})                    # FastAPI checks the body for us
    assert response.status_code == 422


def test_detection_service_down_returns_502(monkeypatch):
    def detection_is_down(code):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(remediator, "rescan", detection_is_down)
    response = client.post("/remediate", json={"code": "x = 1"})     # no findings: Detection is needed
    assert response.status_code == 502
    assert "Detection" in response.json()["detail"]
