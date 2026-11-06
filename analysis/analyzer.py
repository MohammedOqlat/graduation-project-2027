# analyzer.py
from backup_texts import BACKUP_TEXTS


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

    text = BACKUP_TEXTS[vuln_type]
    return {
        "id": finding_id,
        "impact": text["impact"],
        "explanation": text["explanation"],
        "recommendation": text["recommendation"],
    }