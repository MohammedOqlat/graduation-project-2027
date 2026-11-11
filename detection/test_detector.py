# test_detector.py  -  run with:  pytest -v
import pathlib
import pytest
from detector import detect

HERE = pathlib.Path(__file__).parent


def types(code):
    return [f["type"] for f in detect(code)]


def test_sql_injection_concat():
    assert types('cur.execute("SELECT * FROM t WHERE a=\'" + x + "\'")') == ["SQL Injection"]

def test_sql_injection_fstring_variable():
    assert "SQL Injection" in types('q = f"DELETE FROM t WHERE id={i}"\ncur.execute(q)')

def test_sql_parameterized_is_safe():
    assert types('cur.execute("SELECT * FROM t WHERE a = ?", (x,))') == []

def test_xss_return_fstring():
    assert types('def f():\n    return f"<b>{name}</b>"') == ["XSS"]

def test_xss_escaped_is_safe():
    assert types('def f():\n    return f"<b>{escape(name)}</b>"') == []

def test_command_injection_os_system():
    assert types('os.system("ls " + d)') == ["Command Injection"]

def test_command_injection_shell_true():
    assert types('subprocess.run(f"ls {d}", shell=True)') == ["Command Injection"]

def test_subprocess_list_is_safe():
    assert types('subprocess.run(["ls", d])') == []

def test_hardcoded_secret():
    assert types('password = "Admin123"') == ["Hardcoded Secrets"]

def test_env_secret_is_safe():
    assert types('password = os.environ.get("PW")') == []

def test_output_has_all_fields_for_analysis():
    f = detect('API_KEY = "abc123"')[0]
    assert set(f) == {"id", "type", "cwe", "language", "line", "severity", "code_snippet"}
    assert f["id"] == "V001" and f["line"] == 1

def test_vulnerable_sample_finds_all_four_types():
    found = {f["type"] for f in detect((HERE / "samples_vulnerable.py").read_text())}
    assert found == {"SQL Injection", "XSS", "Command Injection", "Hardcoded Secrets"}

def test_safe_sample_has_zero_findings():
    assert detect((HERE / "samples_safe.py").read_text()) == []

def test_invalid_python_raises():
    with pytest.raises(SyntaxError):
        detect("def (:")
