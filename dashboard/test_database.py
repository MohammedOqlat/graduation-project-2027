# dashboard/test_database.py
# ------------------------------------------------------------
# PyTest tests for database.py, using the fake data.
# Run them (from inside the dashboard folder) with:
#       pytest
# ------------------------------------------------------------

import pytest                                  # the testing library

import database                                # our database.py
from fake_data import FAKE_FINDINGS            # the fake findings


@pytest.fixture(autouse=True)                  # runs automatically before EVERY test
def use_temp_database(tmp_path, monkeypatch):
    # Point the database to a temporary file, so the tests never touch the real scanix.db.
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    database.create_tables()                   # create fresh empty tables for this test


def test_score_with_fake_data():
    # 1 Critical (25) + 2 High (20) = 45 points lost -> 100 - 45 = 55
    assert database.calculate_score(FAKE_FINDINGS) == 55


def test_score_with_no_findings_is_100():
    assert database.calculate_score([]) == 100


def test_score_never_below_zero():
    many_critical = [{"severity": "Critical"}] * 10   # 10 x 25 = 250 points lost
    assert database.calculate_score(many_critical) == 0


def test_count_by_severity():
    counts = database.count_by_severity(FAKE_FINDINGS)
    assert counts == {"Critical": 1, "High": 2, "Medium": 0, "Low": 0}


def test_save_and_get_scan():
    scan_id = database.save_scan("fake_sample.py", FAKE_FINDINGS)   # save
    scan = database.get_scan(scan_id)                               # read it back

    assert scan["filename"] == "fake_sample.py"       # the file name was stored
    assert scan["score"] == 55                        # the score was stored
    assert len(scan["findings"]) == 3                 # all 3 findings were stored
    assert scan["findings"][0]["type"] == "Hardcoded Secrets"   # same order as Detection: line 8 comes first
    assert scan["findings"][0]["status"] == "Open"    # default status


def test_get_scan_that_does_not_exist():
    assert database.get_scan(999) is None


def test_latest_scan_id():
    assert database.get_latest_scan_id() is None      # empty database
    database.save_scan("a.py", FAKE_FINDINGS)
    second = database.save_scan("b.py", FAKE_FINDINGS)
    assert database.get_latest_scan_id() == second    # newest scan


def read_analysis(finding_db_id):
    # Small helper for the tests: read one row of the analysis table directly.
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM analysis WHERE finding_id = ?", (finding_db_id,)).fetchone()
    conn.close()
    return row                                         # None when there is no analysis


def test_findings_keep_detection_order():
    # Lines are NOT increasing here (30 first, then 5). We must get the same order back.
    findings = [dict(FAKE_FINDINGS[0], line=30), dict(FAKE_FINDINGS[1], line=5)]
    scan = database.get_scan(database.save_scan("order.py", findings))
    assert [f["line"] for f in scan["findings"]] == [30, 5]


def test_save_analysis():
    scan = database.get_scan(database.save_scan("a.py", FAKE_FINDINGS))
    finding_db_id = scan["findings"][0]["id"]          # OUR database id (1), not "V001"

    database.save_analysis(finding_db_id, "Key can be stolen", "The key is in the code", "Use environment variables")

    row = read_analysis(finding_db_id)
    assert row["impact"] == "Key can be stolen"
    assert row["explanation"] == "The key is in the code"
    assert row["recommendation"] == "Use environment variables"


def test_save_analysis_replaces_the_old_one():
    scan = database.get_scan(database.save_scan("a.py", FAKE_FINDINGS))
    finding_db_id = scan["findings"][0]["id"]

    database.save_analysis(finding_db_id, "old", "old", "old")
    database.save_analysis(finding_db_id, "new", "new", "new")   # same finding again

    assert read_analysis(finding_db_id)["impact"] == "new"       # the new one won


def test_save_analysis_for_a_finding_that_does_not_exist():
    # Foreign keys are ON, so SQLite must refuse an analysis for a missing finding.
    with pytest.raises(Exception):
        database.save_analysis(999, "x", "x", "x")
