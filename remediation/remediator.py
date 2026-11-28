# remediator.py
# ------------------------------------------------------------
# SCANIX - Part 3 (Remediation) - the MAIN LOGIC file.
#
# Input : Python source code (text) + the list of findings from Detection
# Output: the FIXED code + a result for every finding + a summary
#
# The steps (this is the SCANIX idea:  Fix -> Re-scan -> Verify):
#   1. For each finding, ask the matching fix function (fixers.py) for a fix.
#   2. Collect all the fixes and apply them to the code.
#   3. Check that the new code is still valid Python.
#   4. RE-SCAN the new code with the Detection service (port 8001).
#   5. VERIFY: a finding is "Fixed" only if Detection no longer reports it.
#
# We never write to the user's files. We only RETURN the fixed code,
# so the developer reviews it first and decides whether to use it.
# ------------------------------------------------------------

import ast      # to read the code as a tree (to check it is valid and to find the imports)
import os       # to read the environment variable DETECTION_URL

import httpx    # to send the HTTP request to the Detection service

from fixers import FIXERS, CannotFix   # the fix functions and the "cannot fix" error

# The address of the Detection service. It can be changed without editing the code:
#   set the environment variable DETECTION_URL
DETECTION_URL = os.environ.get("DETECTION_URL", "http://127.0.0.1:8001/detect")

# How many points each severity removes from the score.
# This is the SAME table as in dashboard/database.py, so both parts give the same score.
SEVERITY_POINTS = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1}


# ============================================================
# PART 1: Talking to the Detection service
# ============================================================

def rescan(code):
    """Send the code to Detection (POST /detect) and return its list of findings."""
    response = httpx.post(
        DETECTION_URL,
        json={"code": code, "language": "python"},   # the same body that Detection expects
        timeout=10,                                  # do not wait more than 10 seconds
    )
    response.raise_for_status()                      # an error status (4xx / 5xx) raises an error
    return response.json()["findings"]               # Detection answers {"findings": [...], ...}


def calculate_score(findings):
    """Score = 100 - (25*Critical + 10*High + 4*Medium + 1*Low), never below 0."""
    penalty = 0
    for finding in findings:
        penalty = penalty + SEVERITY_POINTS.get(finding.get("severity"), 0)
    return max(0, 100 - penalty)


# ============================================================
# PART 2: Helpers that change the code text
# ============================================================

def is_imported(tree, module):
    """True if the code already has a line  import <module>."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == module and alias.asname is None:
                    return True
    return False


def find_import_line(tree):
    """Return the line number where new import lines must be inserted:
    before the first import, or after the docstring / __future__ lines."""
    position = None
    for index, statement in enumerate(tree.body):               # the top-level statements, in order
        is_docstring = (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )
        is_future = isinstance(statement, ast.ImportFrom) and statement.module == "__future__"
        if is_docstring or is_future:
            position = statement.end_lineno + 1                 # these two must stay first
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            return statement.lineno                             # insert just before the first import
        else:
            return position if position is not None else statement.lineno
    return position if position is not None else 1              # a file with nothing else in it


def apply_edits(lines, edits):
    """Apply all edits to the list of lines.
    Returns (new_lines, line_map). line_map tells where each OLD line number is now,
    because the fixes and the new imports move the lines."""
    edits = sorted(edits, key=lambda e: (e["start"], e["end"]))  # from the top of the file to the bottom
    new_lines = []
    line_map = {}                                                # old line number -> new line number
    old = 1                                                      # the next old line to copy
    for edit in edits:
        while old < edit["start"]:                               # copy the untouched lines before the edit
            new_lines.append(lines[old - 1])
            line_map[old] = len(new_lines)
            old = old + 1
        new_start = len(new_lines) + 1                           # where the new text will begin
        new_lines.extend(edit["text"].split("\n"))               # add the new text
        for number in range(edit["start"], edit["end"] + 1):     # every replaced line points to it
            line_map[number] = new_start
        old = max(old, edit["end"] + 1)                          # continue after the replaced lines
    while old <= len(lines):                                     # copy the rest of the file
        new_lines.append(lines[old - 1])
        line_map[old] = len(new_lines)
        old = old + 1
    return new_lines, line_map


# ============================================================
# PART 3: The main function
# ============================================================

def remediate(code, findings=None):
    """Fix the findings in `code`, re-scan, and return the full result."""
    ast.parse(code)                                  # raises SyntaxError if the code is not valid Python
    lines = code.splitlines()                        # the code as a list of lines

    if findings is None:                             # the caller did not send findings:
        findings = rescan(code)                      # ask Detection for them

    # ---------- Step 1: ask for a fix for every finding ----------
    results = []                                     # one result per finding
    edits = []                                       # all the accepted edits
    used_lines = set()                               # lines that already belong to an accepted edit
    needed_imports = set()                           # modules that the new code needs
    for finding in findings:
        result = {
            "id": finding.get("id"),
            "type": finding.get("type"),
            "line": finding.get("line"),
            "severity": finding.get("severity"),
            "status": "Still Vulnerable",            # changes to "Fixed" only after the re-scan proves it
            "changes": [],                           # the before / after of each changed line
            "note": "",
        }
        results.append(result)
        fix = None                                   # stays None when no fix is accepted
        try:
            fixer = FIXERS.get(finding.get("type"))
            if fixer is None:
                raise CannotFix("No automatic fix exists for this type")
            if not isinstance(finding.get("line"), int):
                raise CannotFix("The finding has no line number")
            fix = fixer(ast.parse(code), lines, finding)           # a fresh tree for every finding
            for edit in fix["edits"]:                              # two fixes must not change the same line
                for number in range(edit["start"], edit["end"] + 1):
                    if number in used_lines:
                        raise CannotFix("Another fix already changes the same lines")
        except CannotFix as error:
            result["note"] = "Manual review needed: " + str(error)
            continue                                                # go to the next finding

        # The fix is accepted: remember its edits, lines and imports.
        for edit in fix["edits"]:
            edits.append(edit)
            used_lines.update(range(edit["start"], edit["end"] + 1))
            result["changes"].append({
                "line": edit["start"],
                "before": "\n".join(lines[edit["start"] - 1:edit["end"]]).strip(),
                "after": edit["text"].strip(),
            })
        needed_imports.update(fix["imports"])
        result["note"] = fix["note"]
        result["status"] = "Pending"                                # waiting for the re-scan

    # ---------- Step 2: add the imports that the new code needs ----------
    tree = ast.parse(code)
    missing = sorted(name for name in needed_imports if not is_imported(tree, name))
    if missing:
        insert_at = find_import_line(tree)
        text = "\n".join("import " + name for name in missing)
        edits.append({"start": insert_at, "end": insert_at - 1, "text": text})   # end < start: insert only

    # ---------- Step 3: apply every edit and check the new code ----------
    new_lines, line_map = apply_edits(lines, edits)
    fixed_code = "\n".join(new_lines)
    if code.endswith("\n"):
        fixed_code = fixed_code + "\n"                                # keep the final new line
    try:
        ast.parse(fixed_code)                                         # the new code must be valid Python
    except SyntaxError:
        fixed_code = code                                             # if not, throw the changes away
        line_map = {number: number for number in range(1, len(lines) + 1)}
        for result in results:
            if result["status"] == "Pending":
                result["status"] = "Still Vulnerable"
                result["changes"] = []
                result["note"] = "Manual review needed: the fix produced invalid code, so nothing was changed"
        edits = []

    # ---------- Step 4: RE-SCAN the new code ----------
    if edits:
        remaining = rescan(fixed_code)                                # ask Detection again
    else:
        remaining = list(findings)                                    # nothing changed, so nothing to re-scan

    # ---------- Step 5: VERIFY each finding ----------
    still_there = set()                                               # (type, line) pairs found by the re-scan
    for item in remaining:
        still_there.add((item.get("type"), item.get("line")))
    known = set()                                                     # (type, new line) of the ORIGINAL findings
    for result in results:
        new_line = line_map.get(result["line"], result["line"])       # where the old line is now
        known.add((result["type"], new_line))
        if result["status"] == "Pending":
            if (result["type"], new_line) in still_there:             # Detection still reports it
                result["status"] = "Still Vulnerable"
                result["note"] = "A fix was applied, but the re-scan still reports this problem"
            else:
                result["status"] = "Fixed"

    # Problems that were NOT in the original list: the fix may have caused them.
    new_issues = [item for item in remaining if (item.get("type"), item.get("line")) not in known]

    fixed_count = sum(1 for result in results if result["status"] == "Fixed")
    still_count = len(results) - fixed_count
    return {
        "language": "python",
        "fixed_code": fixed_code,
        "results": results,
        "new_issues": new_issues,
        "summary": {
            "total": len(results),
            "fixed": fixed_count,
            "still_vulnerable": still_count,
            "new_issues": len(new_issues),
            "verified": still_count == 0 and len(new_issues) == 0,    # True only when the re-scan is clean
            "score_before": calculate_score(findings),
            "score_after": calculate_score(remaining),
        },
    }
