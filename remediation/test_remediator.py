# test_remediator.py  -  run with:  pytest -v
# Tests for remediator.py: fix -> re-scan -> verify, using the REAL detector (see conftest.py).
import ast                      # to check that the fixed code is valid Python
import pathlib                  # to find the sample file of the Detection part

import pytest                   # the test framework

import fixers                   # we replace fix functions in a few tests
import remediator               # the code we test
from conftest import VULNERABLE_SAMPLE   # the vulnerable sample code


def statuses(result):
    """Return {finding id: status} for a result."""
    return {item["id"]: item["status"] for item in result["results"]}


# ---------- The full cycle ----------

def test_full_cycle_fixes_and_verifies_everything(real_detector):
    result = remediator.remediate(VULNERABLE_SAMPLE)                 # no findings given: Detection is asked
    assert result["summary"]["total"] == 5                           # secret, sql, xss, 2 commands
    assert set(statuses(result).values()) == {"Fixed"}               # every finding is fixed
    assert result["summary"]["verified"] is True                     # and the re-scan is clean
    assert result["summary"]["score_after"] == 100
    assert real_detector.detect(result["fixed_code"]) == []          # Detection agrees: nothing is left


def test_score_before_matches_dashboard_formula(real_detector):
    # Critical 25 (secret) + High 10 (sql) + High 10 (xss) + Critical 25 + Critical 25 = 95 -> 100 - 95 = 5
    result = remediator.remediate(VULNERABLE_SAMPLE)
    assert result["summary"]["score_before"] == 5


def test_fixed_code_is_valid_python_and_has_the_expected_changes(real_detector):
    fixed = remediator.remediate(VULNERABLE_SAMPLE)["fixed_code"]
    ast.parse(fixed)                                                 # raises an error if it is not valid
    assert "os.environ.get('API_KEY')" in fixed                      # the secret moved out of the code
    assert "'SELECT * FROM users WHERE name = ?', (user,)" in fixed  # parameterized query
    assert "html.escape(str(name))" in fixed                         # escaped output
    assert "shell=True" not in fixed                                 # no more shell
    assert "os.system" not in fixed


def test_imports_are_added_once_and_existing_ones_are_kept(real_detector):
    fixed = remediator.remediate(VULNERABLE_SAMPLE)["fixed_code"]
    assert fixed.count("import os") == 1                             # already imported: not added again
    assert fixed.count("import subprocess") == 1
    assert fixed.count("import html") == 1                           # new import
    assert "import sqlite3" in fixed                                 # untouched imports stay


def test_running_remediation_twice_changes_nothing(real_detector):
    first = remediator.remediate(VULNERABLE_SAMPLE)["fixed_code"]
    second = remediator.remediate(first)
    assert second["fixed_code"] == first                             # nothing left to fix
    assert second["summary"]["total"] == 0
    assert second["summary"]["verified"] is True


def test_safe_code_is_not_changed(real_detector):
    code = 'import os\nTOKEN = os.environ.get("TOKEN")\n'
    result = remediator.remediate(code)
    assert result["fixed_code"] == code
    assert result["results"] == []


def test_changes_show_before_and_after(real_detector):
    result = remediator.remediate(VULNERABLE_SAMPLE)
    sql = [item for item in result["results"] if item["type"] == "SQL Injection"][0]
    assert sql["changes"][0]["line"] == 15
    assert "+ user +" in sql["changes"][0]["before"]
    assert "?" in sql["changes"][0]["after"]


def test_works_with_the_real_sample_of_the_detection_part(real_detector):
    path = pathlib.Path(__file__).parent.parent / "detection" / "samples_vulnerable.py"
    if not path.exists():
        pytest.skip("the detection folder is not next to this folder")
    result = remediator.remediate(path.read_text())
    assert result["summary"]["verified"] is True


# ---------- Findings that cannot be fixed ----------

def test_unfixable_finding_stays_vulnerable_but_others_are_fixed(real_detector):
    code = (
        'import os\n'
        'import subprocess\n'
        'def f(host, term):\n'
        '    os.system("cat " + host + " | wc -l")\n'        # shell pipe: manual review
        '    subprocess.run("ping " + host, shell=True)\n'    # fixable
    )
    result = remediator.remediate(code)
    assert statuses(result) == {"V001": "Still Vulnerable", "V002": "Fixed"}
    assert "Manual review" in result["results"][0]["note"]
    assert result["summary"]["verified"] is False                    # one problem is left
    assert result["summary"]["still_vulnerable"] == 1
    assert "| wc -l" in result["fixed_code"]                         # the unfixable line was not touched


def test_unknown_type_is_left_for_manual_review(real_detector):
    findings = [{"id": "X1", "type": "Weak Crypto", "line": 1, "severity": "Medium"}]
    result = remediator.remediate("x = 1\n", findings)
    assert result["results"][0]["status"] == "Still Vulnerable"
    assert result["fixed_code"] == "x = 1\n"


def test_finding_without_line_is_left_for_manual_review(real_detector):
    findings = [{"id": "X1", "type": "XSS", "severity": "High"}]
    result = remediator.remediate("x = 1\n", findings)
    assert result["results"][0]["status"] == "Still Vulnerable"


def test_invalid_python_raises_syntax_error(real_detector):
    with pytest.raises(SyntaxError):
        remediator.remediate("def broken(:\n", [])


# ---------- The safety checks ----------

def test_broken_fix_is_thrown_away(real_detector, monkeypatch):
    def bad_fix(tree, lines, finding):                               # a fix that creates invalid Python
        return {"edits": [{"start": 1, "end": 1, "text": "def broken(:"}], "imports": [], "note": ""}
    monkeypatch.setitem(fixers.FIXERS, "Hardcoded Secrets", bad_fix)
    code = 'API_KEY = "sk-live-123456"\n'
    result = remediator.remediate(code)
    assert result["fixed_code"] == code                              # the original code comes back
    assert result["results"][0]["status"] == "Still Vulnerable"
    assert "invalid code" in result["results"][0]["note"]


def test_fix_that_does_not_help_is_not_called_fixed(real_detector, monkeypatch):
    def useless_fix(tree, lines, finding):                           # changes the line but keeps the secret
        return {"edits": [{"start": 1, "end": 1, "text": 'API_KEY = "sk-live-999999"'}], "imports": [], "note": ""}
    monkeypatch.setitem(fixers.FIXERS, "Hardcoded Secrets", useless_fix)
    result = remediator.remediate('API_KEY = "sk-live-123456"\n')
    assert result["results"][0]["status"] == "Still Vulnerable"      # the re-scan still sees the problem
    assert result["summary"]["verified"] is False


def test_fix_that_creates_a_new_problem_is_reported(real_detector, monkeypatch):
    def risky_fix(tree, lines, finding):                             # replaces the secret by a new command injection
        return {"edits": [{"start": 2, "end": 2, "text": 'os.system("ls " + folder)'}], "imports": [], "note": ""}
    monkeypatch.setitem(fixers.FIXERS, "Hardcoded Secrets", risky_fix)
    result = remediator.remediate('import os\nAPI_KEY = "sk-live-123456"\n')
    assert result["results"][0]["status"] == "Fixed"                 # the secret is gone
    assert result["summary"]["new_issues"] == 1                      # but a new problem appeared
    assert result["new_issues"][0]["type"] == "Command Injection"
    assert result["summary"]["verified"] is False


def test_two_fixes_on_the_same_line_do_not_overlap(real_detector):
    findings = [
        {"id": "A", "type": "Command Injection", "line": 2, "severity": "Critical"},
        {"id": "B", "type": "Command Injection", "line": 2, "severity": "Critical"},   # same line twice
    ]
    code = 'import os\nos.system("ls " + folder)\n'
    result = remediator.remediate(code, findings)
    assert statuses(result) == {"A": "Fixed", "B": "Still Vulnerable"}
    assert "Another fix" in result["results"][1]["note"]


# ---------- Imports and line numbers ----------

def test_new_import_goes_after_the_docstring():
    tree = ast.parse('"""My module."""\nx = 1\n')
    assert remediator.find_import_line(tree) == 2


def test_new_import_goes_after_future_imports():
    tree = ast.parse('from __future__ import annotations\nx = 1\n')
    assert remediator.find_import_line(tree) == 2


def test_new_import_goes_before_the_first_import():
    tree = ast.parse('# comment\nimport sqlite3\nx = 1\n')
    assert remediator.find_import_line(tree) == 2


def test_new_import_goes_before_the_first_statement_when_there_are_no_imports():
    tree = ast.parse('# comment\n\nx = 1\n')
    assert remediator.find_import_line(tree) == 3


def test_apply_edits_replaces_inserts_and_maps_lines():
    lines = ["a", "b", "c", "d"]
    edits = [
        {"start": 2, "end": 3, "text": "BC"},                        # two lines become one
        {"start": 1, "end": 0, "text": "import x"},                 # a new line before line 1
    ]
    new_lines, line_map = remediator.apply_edits(lines, edits)
    assert new_lines == ["import x", "a", "BC", "d"]
    assert line_map == {1: 2, 2: 3, 3: 3, 4: 4}                      # old line number -> new line number


def test_final_new_line_is_kept_or_not_kept(real_detector):
    with_newline = remediator.remediate('API_KEY = "sk-live-123456"\n')["fixed_code"]
    without_newline = remediator.remediate('API_KEY = "sk-live-123456"')["fixed_code"]
    assert with_newline.endswith("\n")
    assert not without_newline.endswith("\n")
