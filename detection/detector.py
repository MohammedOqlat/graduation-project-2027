# detector.py
# SCANIX - Detection role.
# Input : Python source code (a string).
# Output: a list of findings. Each finding has the SAME fields that
#         Ayah's Analysis service expects: id, type, cwe, language, line,
#         severity, code_snippet.
#
# How it works: instead of searching the text with regular expressions,
# we parse the code into an AST (Abstract Syntax Tree) with Python's built-in
# "ast" module. The AST lets us see the real structure of the code
# (a function call, an f-string, a variable assignment) so we get fewer
# false positives than plain text search.

import ast
import re

# ---------------------------------------------------------------
# 1) Rule table: one place to change CWE and severity per type
# ---------------------------------------------------------------
RULES = {
    "SQL Injection":     {"cwe": "CWE-89",  "severity": "High"},
    "XSS":               {"cwe": "CWE-79",  "severity": "High"},
    "Command Injection": {"cwe": "CWE-78",  "severity": "Critical"},
    "Hardcoded Secrets": {"cwe": "CWE-798", "severity": "Critical"},
}

# Variable names that suggest a secret (password, api_key, token, ...)
SECRET_NAME = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key)",
    re.IGNORECASE,
)
# Values that are obviously not real secrets
PLACEHOLDERS = {"", "changeme", "your_api_key", "your-api-key", "xxx", "xxxx", "none", "null"}

SQL_WORDS = re.compile(r"\b(select|insert|update|delete|drop|where)\b", re.IGNORECASE)
HTML_TAG = re.compile(r"<\s*[a-zA-Z/]")

# Functions that make text safe -> if used, we do NOT report XSS / SQLi
SANITIZERS = {"escape", "quote", "quote_plus", "bleach", "clean"}


# ---------------------------------------------------------------
# 2) Small helper functions
# ---------------------------------------------------------------
def full_name(node):
    """Turn a call target into text. Example: os.system -> 'os.system'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = full_name(node.value)
        return (base + "." + node.attr) if base else node.attr
    return ""


def is_dynamic_string(node):
    """True when a string is BUILT from other values (not a fixed constant).
    Examples that return True:  f"..{x}"   "..." + x   "..%s" % x   "..{}".format(x)
    """
    if isinstance(node, ast.JoinedStr):                       # f-string
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def string_text(node):
    """Collect all the fixed text pieces inside a string expression."""
    parts = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return " ".join(parts)


def uses_sanitizer(node):
    """True if the expression calls escape()/quote()/... somewhere inside."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = full_name(child.func).split(".")[-1]
            if name in SANITIZERS:
                return True
    return False


# ---------------------------------------------------------------
# 3) The visitor: walks the whole tree and applies the 4 rules
# ---------------------------------------------------------------
class Detector(ast.NodeVisitor):
    def __init__(self, source):
        self.lines = source.splitlines()
        self.raw = []                 # findings before numbering
        # variables that hold a dynamic SQL string / dynamic HTML string
        self.sql_vars = set()
        self.html_vars = set()

    def add(self, vuln_type, node):
        line = node.lineno
        snippet = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        self.raw.append({"type": vuln_type, "line": line, "code_snippet": snippet})

    # ---- assignments: Hardcoded Secrets + remember dynamic strings ----
    def visit_Assign(self, node):
        value = node.value
        for target in node.targets:
            name = target.id if isinstance(target, ast.Name) else (
                target.attr if isinstance(target, ast.Attribute) else "")
            # Rule: Hardcoded Secrets
            if (name and SECRET_NAME.search(name)
                    and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    and value.value.strip().lower() not in PLACEHOLDERS):
                self.add("Hardcoded Secrets", node)
            # Remember variables built from dynamic strings (one-step taint)
            if name and is_dynamic_string(value) and not uses_sanitizer(value):
                text = string_text(value)
                if SQL_WORDS.search(text):
                    self.sql_vars.add(name)
                if HTML_TAG.search(text):
                    self.html_vars.add(name)
        self.generic_visit(node)

    # ---- function calls: Command Injection + SQL Injection + XSS ----
    def visit_Call(self, node):
        name = full_name(node.func)
        short = name.split(".")[-1]
        arg0 = node.args[0] if node.args else None

        # Rule: Command Injection
        if name in ("os.system", "os.popen") and arg0 is not None and not isinstance(arg0, ast.Constant):
            self.add("Command Injection", node)
        elif name.startswith("subprocess.") and arg0 is not None:
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                             for k in node.keywords)
            if shell_true and not isinstance(arg0, ast.Constant):
                self.add("Command Injection", node)

        # Rule: SQL Injection  (cursor.execute(...) with a dynamic query)
        if short in ("execute", "executemany", "executescript") and arg0 is not None:
            if (is_dynamic_string(arg0) and SQL_WORDS.search(string_text(arg0))) or \
               (isinstance(arg0, ast.Name) and arg0.id in self.sql_vars):
                self.add("SQL Injection", node)

        # Rule: XSS  (dynamic HTML sent to the browser)
        if short in ("render_template_string", "HTMLResponse", "make_response", "Markup") and arg0 is not None:
            if self.is_unsafe_html(arg0):
                self.add("XSS", node)
        self.generic_visit(node)

    # ---- return statements: XSS in Flask-style "return f'<h1>{name}</h1>'" ----
    def visit_Return(self, node):
        if node.value is not None and self.is_unsafe_html(node.value):
            self.add("XSS", node)
        self.generic_visit(node)

    def is_unsafe_html(self, expr):
        if uses_sanitizer(expr):
            return False
        if is_dynamic_string(expr) and HTML_TAG.search(string_text(expr)):
            return True
        return isinstance(expr, ast.Name) and expr.id in self.html_vars


# ---------------------------------------------------------------
# 4) Public function used by main.py and the tests
# ---------------------------------------------------------------
def detect(source, language="python"):
    """Scan source code and return a list of findings (dicts)."""
    if language != "python":
        raise ValueError("Only 'python' is supported for now")
    tree = ast.parse(source)          # raises SyntaxError if the code is invalid
    detector = Detector(source)
    detector.visit(tree)

    # remove duplicates (same type + same line) and sort by line
    seen, unique = set(), []
    for f in sorted(detector.raw, key=lambda f: f["line"]):
        key = (f["type"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    findings = []
    for number, f in enumerate(unique, start=1):
        rule = RULES[f["type"]]
        findings.append({
            "id": "V" + str(number).zfill(3),
            "type": f["type"],
            "cwe": rule["cwe"],
            "language": language,
            "line": f["line"],
            "severity": rule["severity"],
            "code_snippet": f["code_snippet"],
        })
    return findings
