# dashboard/fake_data.py
# ------------------------------------------------------------
# This file only holds the FAKE data from the team leader.
# It is exactly the shape that the Detection part (Mohammed) returns.
# We use it now so we can build the dashboard BEFORE the other parts are ready.
# Later we will delete this and use the real result of POST /scan.
# ------------------------------------------------------------

# A list [ ... ] with 3 findings. Each finding is a dictionary { "key": value }.
FAKE_FINDINGS = [
    {
        "id": "V001",                       # the id Detection gave (we do not store it, see database.py)
        "type": "Hardcoded Secrets",        # the kind of vulnerability
        "cwe": "CWE-798",                   # the official CWE number
        "language": "python",               # the language of the scanned code
        "line": 8,                          # the line number in the scanned file
        "severity": "Critical",             # Critical / High / Medium / Low
        "code_snippet": 'API_KEY = "sk-live-1234567890abcdef"',   # the bad line of code
    },
    {
        "id": "V002",
        "type": "SQL Injection",
        "cwe": "CWE-89",
        "language": "python",
        "line": 16,
        "severity": "High",
        "code_snippet": "cur.execute(\"SELECT * FROM users WHERE name = '\" + user + \"'\")",
    },
    {
        "id": "V003",
        "type": "XSS",
        "cwe": "CWE-79",
        "language": "python",
        "line": 23,
        "severity": "High",
        "code_snippet": 'return f"<h1>Hello {name}</h1>"',
    },
]
