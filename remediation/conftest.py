# conftest.py
# ------------------------------------------------------------
# pytest reads this file automatically before the tests.
# It gives the tests the REAL Detection code, so we test Remediation
# together with Mohammed's detector (Fix -> Re-scan -> Verify), not with a fake.
# ------------------------------------------------------------

import importlib.util     # lets us load a Python file from any folder by its path
import pathlib            # builds file paths in a safe way

import pytest             # the test framework

import remediator         # our module: we replace its rescan() function during the tests

# ../detection/detector.py  (the Detection folder is next to the remediation folder)
DETECTOR_PATH = pathlib.Path(__file__).parent.parent / "detection" / "detector.py"

# A copy of detection/samples_vulnerable.py, so the tests do not depend on that file.
VULNERABLE_SAMPLE = '''import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)
API_KEY = "sk-live-1234567890abcdef"


@app.route("/login")
def login():
    user = request.args.get("user")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")
    return "ok"


@app.route("/hello")
def hello():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    subprocess.run(f"nslookup {host}", shell=True)
    return "done"
'''


def load_detector():
    """Load detector.py from its path. We do NOT add the Detection folder to sys.path,
    because both folders have a main.py and Python would mix them up."""
    spec = importlib.util.spec_from_file_location("detector", DETECTOR_PATH)   # describe the file
    module = importlib.util.module_from_spec(spec)                             # create an empty module
    spec.loader.exec_module(module)                                            # run the file inside it
    return module


@pytest.fixture
def real_detector(monkeypatch):
    """Make remediator.rescan() call the real detector directly (no web server needed)."""
    if not DETECTOR_PATH.exists():                                             # the Detection folder is missing
        pytest.skip("detection/detector.py was not found next to the remediation folder")
    detector = load_detector()
    monkeypatch.setattr(remediator, "rescan", lambda code: detector.detect(code))
    return detector
