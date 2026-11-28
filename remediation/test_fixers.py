# test_fixers.py  -  run with:  pytest -v
# Tests for fixers.py: every fix function, on small pieces of code.
import ast                      # to turn the test code into a tree, like the remediator does

import pytest                   # the test framework

from fixers import FIXERS, CannotFix   # the fix functions and the "cannot fix" error


def run_fix(code, vuln_type, line):
    """Run the fix function of `vuln_type` on `code` and return its result."""
    tree = ast.parse(code)                                        # the code as a tree
    finding = {"type": vuln_type, "line": line}                   # the minimum a fixer needs
    return FIXERS[vuln_type](tree, code.splitlines(), finding)


def new_texts(fix):
    """Return the new code of every edit as a list of text lines."""
    return [edit["text"] for edit in fix["edits"]]


# ---------- Hardcoded Secrets ----------

def test_secret_moves_to_environment_variable():
    fix = run_fix('API_KEY = "sk-live-123"', "Hardcoded Secrets", 1)
    assert new_texts(fix) == ["API_KEY = os.environ.get('API_KEY')"]
    assert fix["imports"] == ["os"]                               # the new code needs "import os"
    assert "API_KEY" in fix["note"]                               # the developer is told which variable to set


def test_secret_in_attribute_uses_attribute_name():
    fix = run_fix('self.db_password = "x"', "Hardcoded Secrets", 1)
    assert new_texts(fix) == ["self.db_password = os.environ.get('DB_PASSWORD')"]


def test_secret_keeps_indentation_and_comment():
    code = 'def f():\n    password = "abc123"  # temporary'
    fix = run_fix(code, "Hardcoded Secrets", 2)
    assert new_texts(fix) == ["    password = os.environ.get('PASSWORD')  # temporary"]


# ---------- SQL Injection ----------

def test_sql_concatenation_with_quotes():
    code = 'cur.execute("SELECT * FROM users WHERE name = \'" + user + "\'")'
    fix = run_fix(code, "SQL Injection", 1)
    assert new_texts(fix) == ["cur.execute('SELECT * FROM users WHERE name = ?', (user,))"]
    assert fix["imports"] == []                                   # no import is needed


def test_sql_fstring_with_two_values():
    code = 'cur.execute(f"SELECT * FROM t WHERE a = {a} AND b = \'{b}\'")'
    fix = run_fix(code, "SQL Injection", 1)
    assert new_texts(fix) == ["cur.execute('SELECT * FROM t WHERE a = ? AND b = ?', (a, b))"]


def test_sql_percent_format():
    fix = run_fix('cur.execute("SELECT * FROM t WHERE id = %s" % uid)', "SQL Injection", 1)
    assert new_texts(fix) == ["cur.execute('SELECT * FROM t WHERE id = ?', (uid,))"]


def test_sql_dot_format():
    fix = run_fix('cur.execute("DELETE FROM t WHERE id = {}".format(uid))', "SQL Injection", 1)
    assert new_texts(fix) == ["cur.execute('DELETE FROM t WHERE id = ?', (uid,))"]


def test_sql_two_step_changes_both_lines():
    code = 'def f():\n    query = f"SELECT * FROM t WHERE id = {i}"\n    cur.execute(query)'
    fix = run_fix(code, "SQL Injection", 3)
    assert new_texts(fix) == [
        "    cur.execute(query, (i,))",                           # the execute line
        "    query = 'SELECT * FROM t WHERE id = ?'",             # the line that built the query
    ]


def test_sql_like_pattern_needs_manual_review():
    code = 'cur.execute("SELECT * FROM t WHERE name LIKE \'%" + term + "%\'")'
    with pytest.raises(CannotFix):
        run_fix(code, "SQL Injection", 1)


def test_sql_executemany_and_executescript_are_not_fixed():
    for name in ("executemany", "executescript"):
        with pytest.raises(CannotFix):
            run_fix('cur.' + name + '("DELETE FROM t WHERE id=" + i)', "SQL Injection", 1)


def test_sql_variable_used_twice_needs_manual_review():
    code = 'def f():\n    q = f"SELECT {x}"\n    cur.execute(q)\n    cur.execute(q)'
    with pytest.raises(CannotFix):
        run_fix(code, "SQL Injection", 3)


def test_sql_variables_of_other_functions_are_not_mixed():
    code = (
        'def a():\n    q = "SELECT 1"\n    return q\n'
        'def b():\n    q = f"SELECT * FROM t WHERE id = {i}"\n    cur.execute(q)'
    )
    fix = run_fix(code, "SQL Injection", 6)                      # "q" is used once in b(), but twice in the whole file
    assert "    q = 'SELECT * FROM t WHERE id = ?'" in new_texts(fix)


# ---------- XSS ----------

def test_xss_return_fstring():
    code = 'def hello():\n    return f"<h1>Hello {name}</h1>"'
    fix = run_fix(code, "XSS", 2)
    assert new_texts(fix) == ["    return f'<h1>Hello {html.escape(str(name))}</h1>'"]
    assert fix["imports"] == ["html"]


def test_xss_concatenation():
    code = 'def hello():\n    return "<b>" + name + "</b>"'
    fix = run_fix(code, "XSS", 2)
    assert new_texts(fix) == ["    return f'<b>{html.escape(str(name))}</b>'"]


def test_xss_render_template_string():
    code = 'def hello():\n    return render_template_string("<p>%s</p>" % name)'
    fix = run_fix(code, "XSS", 2)
    assert new_texts(fix) == ["    return render_template_string(f'<p>{html.escape(str(name))}</p>')"]


def test_xss_two_step_changes_only_the_built_line():
    code = 'def hello():\n    page = f"<h1>{name}</h1>"\n    return page'
    fix = run_fix(code, "XSS", 3)
    assert new_texts(fix) == ["    page = f'<h1>{html.escape(str(name))}</h1>'"]


# ---------- Command Injection ----------

def test_command_os_system_becomes_subprocess_run():
    fix = run_fix('os.system("ping -c 1 " + host)', "Command Injection", 1)
    assert new_texts(fix) == ["subprocess.run(['ping', '-c', '1', host])"]
    assert fix["imports"] == ["subprocess"]


def test_command_subprocess_shell_true_is_fixed():
    fix = run_fix('subprocess.run(f"nslookup {host}", shell=True)', "Command Injection", 1)
    assert new_texts(fix) == ["subprocess.run(['nslookup', host])"]
    assert fix["imports"] == []                                   # subprocess is already imported by the user


def test_command_keeps_other_keywords():
    fix = run_fix('subprocess.run("ls " + path, shell=True, check=True)', "Command Injection", 1)
    assert new_texts(fix) == ["subprocess.run(['ls', path], check=True)"]


def test_command_list_with_shell_true_only_removes_shell():
    fix = run_fix('subprocess.run(["ls", path], shell=True)', "Command Injection", 1)
    assert new_texts(fix) == ["subprocess.run(['ls', path])"]


def test_command_two_step():
    code = 'def f():\n    cmd = "ping " + host\n    os.system(cmd)'
    fix = run_fix(code, "Command Injection", 3)
    assert new_texts(fix) == ["    subprocess.run(cmd)", "    cmd = ['ping', host]"]


def test_command_with_shell_features_needs_manual_review():
    with pytest.raises(CannotFix):
        run_fix('os.system("cat " + name + " | grep error")', "Command Injection", 1)


def test_command_value_glued_to_text_needs_manual_review():
    with pytest.raises(CannotFix):
        run_fix('os.system("ls file_" + name)', "Command Injection", 1)


def test_command_popen_needs_manual_review():
    with pytest.raises(CannotFix):
        run_fix('os.popen("ls " + path)', "Command Injection", 1)


def test_command_from_plain_variable_needs_manual_review():
    with pytest.raises(CannotFix):
        run_fix('def f(cmd):\n    os.system(cmd)', "Command Injection", 2)


# ---------- General rules ----------

def test_statement_sharing_its_line_is_not_changed():
    with pytest.raises(CannotFix):
        run_fix('if ok: os.system("ls " + d)', "Command Injection", 1)


def test_wrong_line_number_needs_manual_review():
    with pytest.raises(CannotFix):
        run_fix('x = 1', "SQL Injection", 50)
