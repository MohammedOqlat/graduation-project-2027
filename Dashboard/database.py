# dashboard/database.py
# ------------------------------------------------------------
# SCANIX - Part 4 (Dashboard + Database) - the DATABASE file.
#
# What this file does:
#   1. Creates a small SQLite database file (scanix.db) with 3 tables.
#   2. save_scan(...)  -> saves one scan and all its findings.
#   3. get_scan(...)   -> reads one scan back with all its findings.
#   4. Two helpers: calculate_score(...) and count_by_severity(...).
#
# SQLite is built into Python (the "sqlite3" module), so we install nothing.
# The whole database is just ONE file on the disk.
# ------------------------------------------------------------

import os                      # to build the path of the database file
import sqlite3                 # Python's built-in SQLite library
from datetime import datetime  # to write the date and time of each scan

# Full path of the database file. It will be created next to this file.
# __file__ is the path of database.py, so the .db file lives in the dashboard folder.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanix.db")

# How many points each severity removes from the score (from the team leader).
SEVERITY_POINTS = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1}


def get_connection():
    """Open a connection to the database. Every function below uses this."""
    conn = sqlite3.connect(DB_PATH)           # open (or create) the database file
    conn.row_factory = sqlite3.Row            # rows behave like dictionaries: row["score"]
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignores foreign keys unless we turn them on
    return conn                               # give the connection to whoever asked


def create_tables():
    """Create the 3 tables if they do not exist yet. Safe to call many times."""
    conn = get_connection()

    # TABLE 1: scans - one row for every time the user clicks "Scan".
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,  -- unique number, SQLite counts 1, 2, 3...
            filename   TEXT    NOT NULL,                   -- name of the scanned file
            scanned_at TEXT    NOT NULL,                   -- date and time of the scan
            score      INTEGER NOT NULL                    -- security score from 0 to 100
        )
    """)

    # TABLE 2: findings - one row for every vulnerability found.
    # Many findings belong to ONE scan (one-to-many relationship).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT, -- unique number of the finding
            scan_id      INTEGER NOT NULL,                  -- which scan this finding belongs to
            type         TEXT    NOT NULL,                  -- e.g. SQL Injection
            cwe          TEXT,                              -- e.g. CWE-89
            line         INTEGER,                           -- line number in the scanned code
            severity     TEXT    NOT NULL,                  -- Critical / High / Medium / Low
            code_snippet TEXT,                              -- the vulnerable line of code
            status       TEXT    NOT NULL DEFAULT 'Open',   -- Open, then Fixed or Still Vulnerable
            FOREIGN KEY (scan_id) REFERENCES scans(id)      -- scan_id must exist in the scans table
        )
    """)

    # TABLE 3: analysis - the explanation for ONE finding (one-to-one relationship).
    # It is filled later by Part 2 (Analysis). We only create the table now.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            finding_id     INTEGER PRIMARY KEY,             -- same number as findings.id (one analysis per finding)
            impact         TEXT,                            -- what can happen if attackers use it
            explanation    TEXT,                            -- why the code is dangerous
            recommendation TEXT,                            -- how to fix it
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        )
    """)

    conn.commit()   # save the changes to the file
    conn.close()    # close the connection (always close it when done)


def calculate_score(findings):
    """Score = 100 - (25*Critical + 10*High + 4*Medium + 1*Low), never below 0."""
    penalty = 0                                           # total points to remove
    for finding in findings:                              # look at every finding one by one
        # .get(name, 0) gives the points of that severity, or 0 if the name is unknown
        penalty = penalty + SEVERITY_POINTS.get(finding["severity"], 0)
    return max(0, 100 - penalty)                          # max(0, ...) makes sure it is never negative


def count_by_severity(findings):
    """Return how many findings we have in each severity, e.g. {'Critical': 1, 'High': 2, ...}."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}   # start every counter at 0
    for finding in findings:                                     # go over all findings
        severity = finding["severity"]                           # e.g. "High"
        if severity in counts:                                   # ignore unknown names
            counts[severity] = counts[severity] + 1              # add 1 to that counter
    return counts


def save_scan(filename, findings):
    """Save one scan + all its findings. Returns the new scan id."""
    score = calculate_score(findings)                            # work out the score first
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")    # current time as text

    conn = get_connection()

    # Insert the scan row. The ? marks are placeholders: SQLite fills them safely
    # from the tuple. NEVER join user text into SQL yourself (that is SQL Injection!).
    cursor = conn.execute(
        "INSERT INTO scans (filename, scanned_at, score) VALUES (?, ?, ?)",
        (filename, scanned_at, score),
    )
    scan_id = cursor.lastrowid   # the id SQLite just gave to this scan

    # Insert one row per finding, all linked to the scan with scan_id.
    # We do not give 'id' (SQLite makes it) and we do not give 'status' (it becomes 'Open').
    for finding in findings:
        conn.execute(
            "INSERT INTO findings (scan_id, type, cwe, line, severity, code_snippet) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                finding["type"],
                finding["cwe"],
                finding["line"],
                finding["severity"],
                finding["code_snippet"],
            ),
        )

    conn.commit()    # write everything to the file in one go
    conn.close()
    return scan_id   # return the id so the caller can open this scan later


def get_scan(scan_id):
    """Return the scan with its findings as a dictionary, or None if it does not exist."""
    conn = get_connection()

    # Read the scan row. fetchone() gives one row, or None when nothing matches.
    scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan_row is None:                 # no scan with this id
        conn.close()
        return None

    # Read all findings of this scan, ordered by line number.
    finding_rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY line", (scan_id,)
    ).fetchall()                         # fetchall() gives a list of rows
    conn.close()

    scan = dict(scan_row)                                  # turn the row into a normal dictionary
    scan["findings"] = [dict(row) for row in finding_rows] # add the findings list inside it
    return scan


def get_latest_scan_id():
    """Return the id of the newest scan, or None if the database has no scans."""
    conn = get_connection()
    row = conn.execute("SELECT MAX(id) FROM scans").fetchone()  # biggest id = newest scan
    conn.close()
    return row[0]   # row[0] is the first (and only) column; it is None when the table is empty
