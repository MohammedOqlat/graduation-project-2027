# dashboard/main.py
# ------------------------------------------------------------
# SCANIX - Part 4 (Dashboard + Database) - the WEB PAGE file.
#
# What this file does:
#   - Starts a FastAPI web server on port 8002.
#   - Page "/"            shows the LATEST scan from the database.
#   - Page "/scans/<id>"  shows one specific scan.
#   - Each page shows: the security score, the count per severity,
#     and a table of the findings.
#
# For now it uses FAKE data (fake_data.py). No connection to the other parts yet.
#
# How to run (from inside the dashboard folder):
#       python main.py
# Then open:  http://127.0.0.1:8002
# ------------------------------------------------------------

import html                                   # html.escape() makes text safe to show in a web page

import uvicorn                                # the server that runs FastAPI
from fastapi import FastAPI                   # the FastAPI framework
from fastapi.responses import HTMLResponse    # lets a route return an HTML page

from database import (                        # our own functions from database.py
    count_by_severity,
    create_tables,
    get_latest_scan_id,
    get_scan,
    save_scan,
)
from fake_data import FAKE_FINDINGS           # the fake findings from the team leader

app = FastAPI(title="SCANIX Dashboard")       # create the application

# ---------- Start-up: prepare the database ----------
create_tables()                               # make sure the 3 tables exist
if get_latest_scan_id() is None:              # the database is empty (first run)
    save_scan("fake_sample.py", FAKE_FINDINGS)  # save the fake scan so the page has something to show

# ---------- Look of the page (plain CSS, nothing special) ----------
PAGE_STYLE = """
body { font-family: Arial, sans-serif; background: #f3f4f6; margin: 0; padding: 24px; color: #111827; }
h1 { margin-top: 0; }
.score-box { background: white; border-radius: 12px; padding: 20px; text-align: center;
             max-width: 260px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.15); }
.score-number { font-size: 64px; font-weight: bold; }
.cards { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
.card { background: white; border-radius: 12px; padding: 16px 24px; text-align: center;
        min-width: 110px; box-shadow: 0 1px 4px rgba(0,0,0,.15); }
.card-number { font-size: 32px; font-weight: bold; }
table { border-collapse: collapse; width: 100%; background: white; border-radius: 12px; overflow: hidden; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
th { background: #1f2937; color: white; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
"""

# Colour for each severity (used in the cards and in the table).
SEVERITY_COLORS = {
    "Critical": "#b91c1c",   # dark red
    "High": "#ea580c",       # orange
    "Medium": "#ca8a04",     # yellow
    "Low": "#2563eb",        # blue
}


def safe(value):
    """Make any value safe to put inside HTML.

    The code snippets contain characters like < and > (for example <h1>).
    Without escaping, the browser would RUN them as HTML. A security tool
    must never have that bug (it would be XSS), so we escape everything.
    """
    return html.escape(str(value))            # "<h1>" becomes "&lt;h1&gt;"


def score_color(score):
    """Green when the score is good, orange when it is medium, red when it is bad."""
    if score >= 80:
        return "#15803d"                      # green
    if score >= 50:
        return "#ea580c"                      # orange
    return "#b91c1c"                          # red


def build_page(scan):
    """Take one scan dictionary (from get_scan) and return the full HTML page as text."""
    counts = count_by_severity(scan["findings"])   # e.g. {"Critical": 1, "High": 2, ...}

    # --- the 4 small cards (one per severity) ---
    cards_html = ""                                # we build the text piece by piece
    for severity, number in counts.items():        # loop over Critical, High, Medium, Low
        color = SEVERITY_COLORS[severity]
        cards_html += (
            f'<div class="card">'
            f'<div class="card-number" style="color:{color}">{number}</div>'
            f'<div>{severity}</div>'
            f'</div>'
        )

    # --- the table rows (one per finding) ---
    rows_html = ""
    for finding in scan["findings"]:
        color = SEVERITY_COLORS.get(finding["severity"], "#111827")
        rows_html += (
            f'<tr>'
            f'<td>{safe(finding["id"])}</td>'
            f'<td>{safe(finding["type"])}</td>'
            f'<td>{safe(finding["cwe"])}</td>'
            f'<td>{safe(finding["line"])}</td>'
            f'<td style="color:{color}; font-weight:bold">{safe(finding["severity"])}</td>'
            f'<td><code>{safe(finding["code_snippet"])}</code></td>'
            f'<td>{safe(finding["status"])}</td>'
            f'</tr>'
        )

    # --- if there are no findings, show a friendly row ---
    if rows_html == "":
        rows_html = '<tr><td colspan="7">No vulnerabilities found.</td></tr>'

    # --- put everything together in one page ---
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>SCANIX Dashboard</title>"
        f"<style>{PAGE_STYLE}</style></head><body>"
        "<h1>SCANIX Dashboard</h1>"
        f"<p>File: <b>{safe(scan['filename'])}</b> &nbsp;|&nbsp; "
        f"Scanned at: {safe(scan['scanned_at'])} &nbsp;|&nbsp; Scan #{safe(scan['id'])}</p>"
        '<div class="score-box">'
        "<div>Security Score</div>"
        f'<div class="score-number" style="color:{score_color(scan["score"])}">{safe(scan["score"])}</div>'
        "<div>out of 100</div></div>"
        f'<div class="cards">{cards_html}</div>'
        "<h2>Findings</h2>"
        "<table><tr><th>ID</th><th>Type</th><th>CWE</th><th>Line</th>"
        "<th>Severity</th><th>Code</th><th>Status</th></tr>"
        f"{rows_html}</table>"
        "</body></html>"
    )


# ---------- Routes (the web addresses of our server) ----------
@app.get("/", response_class=HTMLResponse)    # GET http://127.0.0.1:8002/
def home():
    """Show the latest scan."""
    scan = get_scan(get_latest_scan_id())     # find the newest scan id, then read that scan
    return build_page(scan)                   # turn it into HTML


@app.get("/scans/{scan_id}", response_class=HTMLResponse)   # GET /scans/1, /scans/2 ...
def show_scan(scan_id: int):                  # FastAPI converts the number in the address to int
    """Show one specific scan."""
    scan = get_scan(scan_id)
    if scan is None:                          # no scan with this number
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)
    return build_page(scan)


# ---------- Run the server ----------
if __name__ == "__main__":                    # true only when we run "python main.py"
    uvicorn.run(app, host="127.0.0.1", port=8002)   # start the server on port 8002
