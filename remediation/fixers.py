# fixers.py
# ------------------------------------------------------------
# SCANIX - Part 3 (Remediation) - the FIXES file.
#
# What this file does:
#   For each vulnerability type there is ONE function that creates a safe fix:
#       fix_hardcoded_secret   -> moves the secret to an environment variable
#       fix_sql_injection      -> changes the query to a parameterized query
#       fix_xss                -> wraps the user values with html.escape()
#       fix_command_injection  -> runs the command as a list, without a shell
#
#   How a fix works (the same 4 steps every time):
#       1. Find the statement (one line of code) that Detection reported.
#       2. Change that statement in the code TREE (the "ast" tree, like Detection).
#       3. Turn the changed statement back into text with ast.unparse().
#       4. Return an "edit": which lines to replace and the new text.
#
#   A fix function RETURNS a dictionary like this:
#       {
#         "edits":   [ {"start": 16, "end": 16, "text": "new code"} ],  # lines to replace
#         "imports": ["os"],                                             # imports the new code needs
#         "note":    "a short message for the developer",                # can be empty
#       }
#   If a fix is not safe, the function RAISES CannotFix("reason") instead.
#   We prefer "no fix" over a wrong fix: a human must review that finding.
# ------------------------------------------------------------

import ast      # reads Python code as a tree, and writes a tree back as code
import re       # regular expressions: used to split texts and to clean names
import shlex    # splits a command text into words, the same way a shell does


class CannotFix(Exception):
    """Raised when a safe automatic fix is not possible. The message says why."""


# ============================================================
# PART 1: Settings
# ============================================================

MARKER = "\x00"   # a special character that cannot appear in normal code; it marks "a value goes here"

# Same lists as in the Detection part (detector.py), because we must understand the same code.
SQL_FUNCTIONS = ["execute", "executemany", "executescript"]
HTML_FUNCTIONS = ["render_template_string", "HTMLResponse", "make_response", "Markup"]

# Characters with a special meaning in a shell (pipe, redirect, variables, wildcards...).
# If the command text contains one of them we cannot turn it into a safe list by machine.
SHELL_CHARS = set("|&;<>$`()*?~{}\\\n")


# ============================================================
# PART 2: Small helper functions (each one does one simple job)
# ============================================================

def get_name(node):
    """Return the name of a function as text. The call os.system(...) gives "os.system".
    (Same helper as in detector.py.)"""
    if isinstance(node, ast.Name):                  # a plain name like  print
        return node.id
    if isinstance(node, ast.Attribute):             # a dotted name like  os.system
        before_dot = get_name(node.value)           # first get the part before the dot
        if before_dot:
            return before_dot + "." + node.attr     # join the two parts with a dot
        return node.attr
    return ""                                       # anything else has no simple name


def is_text(node):
    """True if the node is a fixed text value, like "abc"."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def find_statement(tree, line):
    """Return the simple statement (one instruction) that starts on this line number."""
    for node in ast.walk(tree):                     # visit every node of the tree
        if isinstance(node, ast.stmt) and node.lineno == line and not hasattr(node, "body"):
            return node                             # "body" means a block (if, for, def...): skip those
    raise CannotFix("No simple statement starts at line " + str(line))


def find_call(statement, is_wanted):
    """Return the first function call inside the statement that is_wanted() accepts, or None."""
    for node in ast.walk(statement):                # visit every node inside the statement
        if isinstance(node, ast.Call) and node.args and is_wanted(node):
            return node                             # only calls that have at least one argument
    return None


def find_scope(tree, line):
    """Return the function that contains this line (or the whole file if there is none).
    We use it so that a variable from another function is never mixed up with ours."""
    scope = tree                                    # start with the whole file
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= node.end_lineno:          # the line is inside this function
                if scope is tree or node.lineno > scope.lineno:  # keep the innermost function
                    scope = node
    return scope


def find_assignment(tree, name, line):
    """Find the line  name = ...  that built the variable used on `line` (the 2-step case):
            query = f"SELECT ... {x}"
            cursor.execute(query)
    The variable must be used only ONCE, otherwise changing it could break other code."""
    scope = find_scope(tree, line)                  # look only inside the same function
    found = None
    uses = 0                                        # how many times the variable is read
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and node.lineno < line and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id == name:
                if found is None or node.lineno > found.lineno:   # keep the nearest earlier one
                    found = node
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            uses = uses + 1                         # a "Load" means the variable is read here
    if found is None:
        raise CannotFix("Could not find where the variable '" + name + "' is built")
    if uses != 1:
        raise CannotFix("The variable '" + name + "' is used " + str(uses) + " times, fix it by hand")
    return found


def locate_built_string(tree, expression, line):
    """Return (the built text expression, the assignment statement or None).
    - direct case:   execute("..." + x)   -> the expression itself, no assignment
    - 2-step case:   execute(query)       -> what was assigned to `query` earlier"""
    if isinstance(expression, ast.Name):
        assignment = find_assignment(tree, expression.id, line)
        return assignment.value, assignment
    return expression, None


def replace_node(root, old, new):
    """Inside `root`, replace the node `old` by the node `new`."""
    for parent in ast.walk(root):                               # look at every parent node
        for field, value in ast.iter_fields(parent):            # and at each of its fields
            if value is old:                                    # the field holds the node itself
                setattr(parent, field, new)
                return
            if isinstance(value, list):                         # the field holds a list of nodes
                for index, item in enumerate(value):
                    if item is old:
                        value[index] = new
                        return


def make_edit(statement, lines):
    """Turn a changed statement back into text and describe which lines it replaces."""
    start = statement.lineno                                    # first line of the statement
    end = statement.end_lineno                                  # last line (can be more than one)
    # ast gives positions in BYTES, so we cut the lines as bytes to be correct with Arabic letters.
    before = lines[start - 1].encode("utf-8")[:statement.col_offset].decode("utf-8")
    after = lines[end - 1].encode("utf-8")[statement.end_col_offset:].decode("utf-8").strip()
    if before.strip() != "":                                    # something else is before it: if x: os.system(..)
        raise CannotFix("The statement shares its line with other code")
    if after != "" and not after.startswith("#"):               # something else is after it: a; b
        raise CannotFix("The statement shares its line with other code")
    text = before + ast.unparse(statement)                      # keep the indentation + new code
    if after != "":
        text = text + "  " + after                              # keep the comment at the end of the line
    return {"start": start, "end": end, "text": text}


# ============================================================
# PART 3: Reading built texts  ("SELECT " + x,  f"..{x}..",  "..%s" % x,  "..{}".format(x))
# ============================================================
# We turn every one of these 4 forms into the SAME simple list of pieces:
#     [("text", "SELECT * FROM t WHERE id = "), ("value", <the node of x>)]
# After that, each fixer only has to work with this list.

def interleave(texts, values):
    """Put the texts and the values one after the other: text, value, text, value, text."""
    pieces = []
    for index, text in enumerate(texts):
        if text != "":
            pieces.append(("text", text))
        if index < len(values):
            pieces.append(("value", values[index]))
    return pieces


def flatten(node):
    """Return the list of pieces of a built text."""
    # 1) f-string:  f"SELECT {x}"
    if isinstance(node, ast.JoinedStr):
        pieces = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):            # the {x} part
                if part.conversion != -1 or part.format_spec is not None:
                    raise CannotFix("An f-string uses {x!r} or {x:format}")
                pieces.append(("value", part.value))
            else:                                               # the fixed text part
                pieces.append(("text", part.value))
        return pieces

    # 2) plus:  "SELECT " + x   (works for a chain like a + b + c too)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return flatten(node.left) + flatten(node.right)

    # 3) percent:  "SELECT %s" % x   or   "SELECT %s %s" % (x, y)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and is_text(node.left):
        if isinstance(node.right, ast.Tuple):
            values = node.right.elts
        elif isinstance(node.right, ast.Dict):
            raise CannotFix("A % format with names is not supported")
        else:
            values = [node.right]
        texts = re.split(r"%[sd]", node.left.value)             # cut the text at every %s or %d
        if any("%" in text for text in texts) or len(texts) - 1 != len(values):
            raise CannotFix("The % format is too complex")
        return interleave(texts, values)

    # 4) format:  "SELECT {}".format(x)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and is_text(node.func.value):
            texts = node.func.value.value.split("{}")           # cut the text at every {}
            has_other_braces = any("{" in text or "}" in text for text in texts)
            if node.keywords or has_other_braces or len(texts) - 1 != len(node.args):
                raise CannotFix("The .format() call is too complex")
            return interleave(texts, node.args)

    # 5) a fixed text, or any other value
    if is_text(node):
        return [("text", node.value)]
    return [("value", node)]


def require_built(pieces):
    """Make sure the pieces really contain BOTH fixed text and at least one value."""
    kinds = [kind for kind, content in pieces]
    if "text" not in kinds or "value" not in kinds:
        raise CannotFix("The text is not built from fixed text + a value")
    return pieces


# ============================================================
# PART 4: The 4 fixes
# ============================================================

def fix_hardcoded_secret(tree, lines, finding):
    """API_KEY = "sk-live-123"   becomes   API_KEY = os.environ.get("API_KEY")"""
    statement = find_statement(tree, finding["line"])           # the line Detection reported
    if not isinstance(statement, ast.Assign):                   # Detection only reports assignments
        raise CannotFix("The secret is not in a simple assignment")

    target = statement.targets[0]                               # the left side of the "="
    if isinstance(target, ast.Name):                            # password = "..."
        name = target.id
    elif isinstance(target, ast.Attribute):                     # self.password = "..."
        name = target.attr
    else:
        raise CannotFix("Cannot find the variable name of the secret")

    env_name = re.sub(r"[^A-Za-z0-9]", "_", name).upper()       # api-key -> API_KEY
    statement.value = ast.parse('os.environ.get("' + env_name + '")', mode="eval").body   # the new value

    return {
        "edits": [make_edit(statement, lines)],
        "imports": ["os"],                                      # the new code uses os
        "note": "Set the environment variable " + env_name + " before you run the program. "
                "Also change the old secret, because it was already visible in the code.",
    }


def is_sql_call(call):
    """True for a call like cursor.execute(...)."""
    return get_name(call.func).split(".")[-1] in SQL_FUNCTIONS


def build_query(pieces):
    """Turn the pieces into (query text with ? marks, list of value nodes)."""
    text = ""
    params = []                                                 # the values that go into the tuple
    for kind, content in pieces:
        if kind == "text":
            text = text + content                               # fixed text stays as it is
        else:
            text = text + MARKER                                # a value becomes a marker for now
            params.append(content)

    # A value inside quotes:  name = '<x>'  -> the quotes are not needed with a placeholder.
    text = text.replace("'" + MARKER + "'", MARKER).replace('"' + MARKER + '"', MARKER)

    # A marker that is STILL inside quotes (for example LIKE '%<x>%') cannot be fixed by machine.
    for index, character in enumerate(text):
        if character == MARKER:
            before = text[:index]
            if before.count("'") % 2 == 1 or before.count('"') % 2 == 1:
                raise CannotFix("A value is inside a quoted pattern such as LIKE '%...%'")
    return text.replace(MARKER, "?"), params                    # every marker becomes a ? placeholder


def fix_sql_injection(tree, lines, finding):
    """cur.execute("... '" + user + "'")   becomes   cur.execute("... ?", (user,))"""
    line = finding["line"]
    statement = find_statement(tree, line)
    call = find_call(statement, is_sql_call)
    if call is None:
        raise CannotFix("No database call found on this line")
    if get_name(call.func).split(".")[-1] != "execute":         # executemany / executescript work differently
        raise CannotFix("Only execute() can be fixed automatically")
    if len(call.args) != 1 or call.keywords:                    # it already has parameters
        raise CannotFix("The call already has more arguments")

    expression, assignment = locate_built_string(tree, call.args[0], line)
    pieces = require_built(flatten(expression))
    query, params = build_query(pieces)

    new_query = ast.Constant(value=query)                       # the new fixed query text
    if assignment is None:
        call.args[0] = new_query                                # direct case: change the argument
    else:
        assignment.value = new_query                            # 2-step case: change the earlier line
    call.args.append(ast.Tuple(elts=params, ctx=ast.Load()))    # add the values as a 2nd argument

    edits = [make_edit(statement, lines)]                       # the execute line
    if assignment is not None:
        edits.append(make_edit(assignment, lines))              # and the line that built the query
    return {"edits": edits, "imports": [], "note": ""}


def escape_call(value):
    """Build the code  html.escape(str(value))  as a tree node."""
    function = ast.parse("html.escape", mode="eval").body       # the name html.escape
    as_text = ast.Call(func=ast.Name(id="str", ctx=ast.Load()), args=[value], keywords=[])   # str(value)
    return ast.Call(func=function, args=[as_text], keywords=[])


def is_html_call(call):
    """True for a call like render_template_string(...) or make_response(...)."""
    return get_name(call.func).split(".")[-1] in HTML_FUNCTIONS


def fix_xss(tree, lines, finding):
    """return f"<h1>{name}</h1>"   becomes   return f"<h1>{html.escape(str(name))}</h1>" """
    line = finding["line"]
    statement = find_statement(tree, line)

    call = find_call(statement, is_html_call)                   # make_response(...), Markup(...) ...
    if call is not None:
        expression = call.args[0]                               # the HTML is the first argument
    elif isinstance(statement, ast.Return) and statement.value is not None:
        expression = statement.value                            # the HTML is the returned value
    else:
        raise CannotFix("No HTML output found on this line")

    built, assignment = locate_built_string(tree, expression, line)
    pieces = require_built(flatten(built))

    parts = []                                                  # the parts of the new f-string
    for kind, content in pieces:
        if kind == "text":
            parts.append(ast.Constant(value=content))           # fixed text stays the same
        else:                                                   # a value is wrapped with html.escape
            parts.append(ast.FormattedValue(value=escape_call(content), conversion=-1, format_spec=None))
    new_text = ast.JoinedStr(values=parts)                      # the new f-string

    if assignment is None:
        replace_node(statement, expression, new_text)           # direct case
        edits = [make_edit(statement, lines)]
    else:
        assignment.value = new_text                             # 2-step case: only the earlier line changes
        edits = [make_edit(assignment, lines)]
    return {"edits": edits, "imports": ["html"], "note": ""}


def is_command_call(call):
    """True for os.system(x), os.popen(x) or subprocess.xxx(x, shell=True) with a non-fixed x."""
    if isinstance(call.args[0], ast.Constant):                  # a fixed command is safe
        return False
    name = get_name(call.func)
    if name in ("os.system", "os.popen"):
        return True
    if name.startswith("subprocess."):
        for keyword in call.keywords:
            if keyword.arg == "shell":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return True
    return False


def build_arguments(pieces):
    """Turn the pieces of a command text into a list of argument nodes.
    "ping -c 1 " + host   gives   ["ping", "-c", "1", host]"""
    text = ""
    values = []
    for kind, content in pieces:
        if kind == "text":
            if any(character in SHELL_CHARS for character in content):
                raise CannotFix("The command uses shell features such as | & ; > $")
            text = text + content
        else:
            text = text + MARKER                                # a value becomes a marker
            values.append(content)

    try:
        words = shlex.split(text)                               # cut the text into words like a shell
    except ValueError:
        raise CannotFix("The command text has unbalanced quotes")

    arguments = []
    next_value = 0                                              # which value comes next
    for word in words:
        if word == MARKER:                                      # this word is exactly one value
            arguments.append(values[next_value])
            next_value = next_value + 1
        elif MARKER in word:                                    # a value is glued to other text
            raise CannotFix("A value is joined to other text inside one argument")
        else:
            arguments.append(ast.Constant(value=word))          # a fixed word like "ping"
    if next_value != len(values) or not arguments:
        raise CannotFix("Could not split the command into arguments")
    return arguments


def fix_command_injection(tree, lines, finding):
    """os.system("ping " + host)   becomes   subprocess.run(["ping", host])"""
    line = finding["line"]
    statement = find_statement(tree, line)
    call = find_call(statement, is_command_call)
    if call is None:
        raise CannotFix("No command call found on this line")
    name = get_name(call.func)
    if name == "os.popen":                                      # popen returns a file, run() does not
        raise CannotFix("os.popen needs a manual fix (use subprocess.run with capture_output)")

    first = call.args[0]
    edits_assignment = None                                     # set only in the 2-step case
    if not isinstance(first, (ast.List, ast.Tuple)):            # a text command must become a list
        expression, assignment = locate_built_string(tree, first, line)
        arguments = build_arguments(require_built(flatten(expression)))
        new_list = ast.List(elts=arguments, ctx=ast.Load())
        if assignment is None:
            call.args[0] = new_list                             # direct case
        else:
            assignment.value = new_list                         # 2-step case
            edits_assignment = assignment
    # (if the command is already a list, only "shell=True" is the problem)

    imports = []
    if name == "os.system":
        call.func = ast.parse("subprocess.run", mode="eval").body   # os.system(...) -> subprocess.run(...)
        imports.append("subprocess")
    else:
        call.keywords = [k for k in call.keywords if k.arg != "shell"]   # remove shell=True

    edits = [make_edit(statement, lines)]
    if edits_assignment is not None:
        edits.append(make_edit(edits_assignment, lines))
    return {"edits": edits, "imports": imports, "note": ""}


# The remediator uses this dictionary to choose the right fix for each finding type.
FIXERS = {
    "Hardcoded Secrets": fix_hardcoded_secret,
    "SQL Injection": fix_sql_injection,
    "XSS": fix_xss,
    "Command Injection": fix_command_injection,
}
