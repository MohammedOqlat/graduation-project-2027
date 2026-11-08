# analyzer.py
import json
import os

from dotenv import load_dotenv

from backup_texts import BACKUP_TEXTS

load_dotenv()

MODEL = "claude-haiku-5-5"
REQUIRED_FIELDS = ("impact", "explanation", "recommendation")

SYSTEM_PROMPT = (
    "You are a security assistant. You receive one vulnerability finding in Python code. "
    "Reply with ONLY a JSON object, with no markdown and no extra text, that has exactly "
    'these three string fields: "impact", "explanation", "recommendation". '
    "Write for a student developer in plain English, one or two sentences per field. "
    "In recommendation, include a short secure code example."
)


def ask_llm(finding):
    """Ask the LLM for the analysis. Return a dict, or None if anything fails."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key, timeout=20)
        message = (
            "Vulnerability type: " + finding["type"] + "\n"
            "CWE: " + str(finding.get("cwe", "")) + "\n"
            "Line: " + str(finding.get("line", "")) + "\n"
            "Code snippet: " + str(finding.get("code_snippet", ""))
        )
        response = client.messages.create(
            model=MODEL,
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": message}],
        )
        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text.strip())
        for field in REQUIRED_FIELDS:
            if not isinstance(result.get(field), str) or not result[field].strip():
                return None
        return {field: result[field] for field in REQUIRED_FIELDS}
    except Exception as error:
        print("LLM failed:", type(error).__name__, error)
        return None


def analyze_finding(finding):
    """Take one finding from Detection and return its analysis."""
    finding_id = finding["id"]
    vuln_type = finding["type"]

    # Only the four supported types are analyzed
    if vuln_type not in BACKUP_TEXTS:
        return {
            "id": finding_id,
            "error": "Unsupported vulnerability type: " + vuln_type,
        }

    result = ask_llm(finding)
    if result is None:
        result = BACKUP_TEXTS[vuln_type]
        print("Analysis source: backup text")
    else:
        print("Analysis source: LLM")

    return {
        "id": finding_id,
        "impact": result["impact"],
        "explanation": result["explanation"],
        "recommendation": result["recommendation"],
    }