# detector.py
# SCANIX - Detection part (Mohammed)
#
# Input : Python source code as a string
# Output: a list of findings. Each finding is a dictionary with the fields
#         that the Analysis service expects:
#         id, type, cwe, language, line, severity, code_snippet
#
# Idea: we do NOT search the code like plain text. We ask Python's "ast"
# module to read the code and give us a tree of its real structure
# (assignments, function calls, f-strings...). Then we walk over the tree
# and check 4 simple rules. This gives fewer false alarms than text search.

import ast
import re


# =====================================================================
# PART 1: Settings (the things we may want to change later)
# =====================================================================

# For each vulnerability type: its CWE number and its severity
RULES = {
    "SQL Injection":     {"cwe": "CWE-89",  "severity": "High"},
    "XSS":               {"cwe": "CWE-79",  "severity": "High"},
    "Command Injection": {"cwe": "CWE-78",  "severity": "Critical"},
    "Hardcoded Secrets": {"cwe": "CWE-798", "severity": "Critical"},
}

# If a variable name contains one of these words, it may hold a secret
SECRET_WORDS = [
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "api-key", "apikey",
    "private_key", "private-key", "privatekey",
]

# Values that are clearly not real secrets
FAKE_VALUES = ["", "changeme", "your_api_key", "your-api-key", "xxx", "xxxx", "none", "null"]

# Functions that make text safe. If one of them is used, we do NOT report.
SAFE_FUNCTIONS = ["escape", "quote", "quote_plus", "bleach", "clean"]

# Functions that run a database query
SQL_FUNCTIONS = ["execute", "executemany", "executescript"]

# Functions that send HTML to the browser
HTML_FUNCTIONS = ["render_template_string", "HTMLResponse", "make_response", "Markup"]

# Text patterns (regular expressions)
# \b means "whole word", so "select" matches but "selected" does not
SQL_PATTERN = re.compile(r"\b(select|insert|update|delete|drop|where)\b", re.IGNORECASE)
# a "<" followed by a letter or "/" means an HTML tag, like <h1> or </div>
HTML_PATTERN = re.compile(r"<\s*[a-zA-Z/]")


# =====================================================================
# PART 2: Small helper functions (each one does one simple job)
# =====================================================================

def get_name(node):
    """Return the name of a function as text.
    Example: the call os.system(...) gives "os.system"."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        before_dot = get_name(node.value)
        if before_dot:
            return before_dot + "." + node.attr
        return node.attr
    return ""


def is_built_string(node):
    """True if the text is BUILT from other values (not a fixed text).
    These 4 ways return True:
        f"SELECT {x}"           (f-string)
        "SELECT " + x           (plus)
        "SELECT %s" % x         (percent)
        "SELECT {}".format(x)   (format)
    A fixed text like "SELECT 1" returns False."""
    # 1) f-string: it must contain at least one {value}
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                return True
        return False

    # 2) joining with + or %
    #    it is only "built" if at least one side is NOT a fixed value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left_is_fixed = isinstance(node.left, ast.Constant)
        right_is_fixed = isinstance(node.right, ast.Constant)
        if left_is_fixed and right_is_fixed:
            return False
        return True

    # 3) "....".format(...)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True

    return False


def get_fixed_text(node):
    """Collect all the fixed text pieces inside an expression.
    Example: "SELECT * FROM t WHERE a=" + x  gives  "SELECT * FROM t WHERE a=" """
    pieces = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            pieces.append(child.value)
    return " ".join(pieces)


def has_safe_function(node):
    """True if escape(), quote(), ... is used anywhere inside the expression."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            last_part = get_name(child.func).split(".")[-1]
            if last_part in SAFE_FUNCTIONS:
                return True
    return False


def get_target_name(target):
    """Return the variable name on the left side of '='.
    password = ...      gives "password"
    self.password = ... gives "password"
    anything else       gives "" """
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def looks_like_secret_name(name):
    """True if the variable name contains a word like password or token."""
    name = name.lower()
    for word in SECRET_WORDS:
        if word in name:
            return True
    return False


def is_real_string(node):
    """True if the node is a fixed text value, like "abc"."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


# =====================================================================
# PART 3: The Detector class - walks over the tree and checks the rules
# =====================================================================
# ast.NodeVisitor walks over the tree for us. Whenever it meets an
# Assign node it calls visit_Assign, a Call node calls visit_Call, and
# a Return node calls visit_Return. We only write what to do there.

class Detector(ast.NodeVisitor):

    def __init__(self, source_code):
        self.code_lines = source_code.splitlines()
        self.problems = []          # everything we find (before numbering)
        self.sql_variables = set()  # variables that hold a built SQL text
        self.html_variables = set() # variables that hold a built HTML text

    def add_problem(self, vuln_type, node):
        line_number = node.lineno
        if line_number <= len(self.code_lines):
            snippet = self.code_lines[line_number - 1].strip()
        else:
            snippet = ""
        self.problems.append({
            "type": vuln_type,
            "line": line_number,
            "code_snippet": snippet,
        })

    # ------------------------------------------------------------
    # Lines like:  name = value
    # ------------------------------------------------------------
    def visit_Assign(self, node):
        for target in node.targets:
            name = get_target_name(target)
            if name != "":
                self.check_hardcoded_secret(node, name)
                self.remember_built_strings(name, node.value)
        self.generic_visit(node)   # continue into the children

    def check_hardcoded_secret(self, node, name):
        """Rule 4: a secret written directly in the code."""
        value = node.value
        if not looks_like_secret_name(name):
            return
        if not is_real_string(value):
            return
        if value.value.strip().lower() in FAKE_VALUES:
            return
        self.add_problem("Hardcoded Secrets", node)

    def remember_built_strings(self, name, value):
        """Remember variables that hold a built SQL or HTML text, so that
        we can catch the 2-step case:
            query = f"SELECT ... {x}"
            cursor.execute(query)
        """
        if not is_built_string(value):
            return
        if has_safe_function(value):
            return
        text = get_fixed_text(value)
        if SQL_PATTERN.search(text):
            self.sql_variables.add(name)
        if HTML_PATTERN.search(text):
            self.html_variables.add(name)

    # ------------------------------------------------------------
    # Function calls like:  something(...)
    # ------------------------------------------------------------
    def visit_Call(self, node):
        function_name = get_name(node.func)
        last_part = function_name.split(".")[-1]

        if len(node.args) > 0:
            first_argument = node.args[0]
            self.check_command_injection(node, function_name, first_argument)
            self.check_sql_injection(node, last_part, first_argument)
            self.check_xss_in_call(node, last_part, first_argument)

        self.generic_visit(node)

    def check_command_injection(self, node, function_name, first_argument):
        """Rule 3: user data used inside a system command."""
        if isinstance(first_argument, ast.Constant):
            return   # a fixed command is safe

        # os.system(command) or os.popen(command)
        if function_name == "os.system" or function_name == "os.popen":
            self.add_problem("Command Injection", node)
            return

        # subprocess.run(command, shell=True) (or call, Popen, ...)
        if function_name.startswith("subprocess."):
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.add_problem("Command Injection", node)
                        return

    def check_sql_injection(self, node, last_part, first_argument):
        """Rule 1: a built SQL text passed to execute()."""
        if last_part not in SQL_FUNCTIONS:
            return

        # Case A: the query is built inside execute(...)
        if is_built_string(first_argument):
            if SQL_PATTERN.search(get_fixed_text(first_argument)):
                self.add_problem("SQL Injection", node)
                return

        # Case B: execute(query) where "query" was built on an earlier line
        if isinstance(first_argument, ast.Name):
            if first_argument.id in self.sql_variables:
                self.add_problem("SQL Injection", node)

    def check_xss_in_call(self, node, last_part, first_argument):
        """Rule 2 (part 1): built HTML passed to a function that sends HTML."""
        if last_part in HTML_FUNCTIONS:
            if self.is_unsafe_html(first_argument):
                self.add_problem("XSS", node)

    # ------------------------------------------------------------
    # Lines like:  return something
    # ------------------------------------------------------------
    def visit_Return(self, node):
        """Rule 2 (part 2): a Flask view that returns built HTML,
        like:  return f"<h1>{name}</h1>" """
        if node.value is not None:
            if self.is_unsafe_html(node.value):
                self.add_problem("XSS", node)
        self.generic_visit(node)

    def is_unsafe_html(self, expression):
        """True if the expression is HTML built from other values
        and is NOT protected by escape()."""
        if has_safe_function(expression):
            return False
        if is_built_string(expression):
            if HTML_PATTERN.search(get_fixed_text(expression)):
                return True
        if isinstance(expression, ast.Name):
            if expression.id in self.html_variables:
                return True
        return False


# =====================================================================
# PART 4: The main function (used by main.py and by the tests)
# =====================================================================

def remove_duplicates(problems):
    """Keep only one problem for each (type, line) pair."""
    seen = set()
    unique = []
    for problem in problems:
        key = (problem["type"], problem["line"])
        if key not in seen:
            seen.add(key)
            unique.append(problem)
    return unique


def get_line(problem):
    return problem["line"]


def detect(source_code, language="python"):
    """Scan the code and return a list of findings."""
    if language != "python":
        raise ValueError("Only 'python' is supported for now")

    # Step 1: turn the code into a tree (raises SyntaxError if code is invalid)
    tree = ast.parse(source_code)

    # Step 2: walk over the tree and collect problems
    detector = Detector(source_code)
    detector.visit(tree)

    # Step 3: sort by line number, then remove duplicates
    problems = sorted(detector.problems, key=get_line)
    problems = remove_duplicates(problems)

    # Step 4: give each problem an id (V001, V002, ...) and add CWE + severity
    findings = []
    number = 1
    for problem in problems:
        rule = RULES[problem["type"]]
        findings.append({
            "id": "V" + str(number).zfill(3),
            "type": problem["type"],
            "cwe": rule["cwe"],
            "language": language,
            "line": problem["line"],
            "severity": rule["severity"],
            "code_snippet": problem["code_snippet"],
        })
        number += 1
    return findings