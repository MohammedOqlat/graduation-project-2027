# test_analyzer.py
import json
from analyzer import analyze_finding

findings = [
    {"id": "V001", "type": "SQL Injection", "cwe": "CWE-89", "language": "python",
     "line": 14, "severity": "High", "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_id"},
    {"id": "V002", "type": "XSS", "cwe": "CWE-79", "language": "python",
     "line": 27, "severity": "Medium", "code_snippet": "return '<p>' + comment + '</p>'"},
    {"id": "V003", "type": "Command Injection", "cwe": "CWE-78", "language": "python",
     "line": 40, "severity": "Critical", "code_snippet": "os.system('ping ' + host)"},
    {"id": "V004", "type": "Hardcoded Secrets", "cwe": "CWE-798", "language": "python",
     "line": 5, "severity": "High", "code_snippet": "API_KEY = 'sk-12345'"},
    {"id": "V005", "type": "Buffer Overflow", "cwe": "CWE-120", "language": "python",
     "line": 9, "severity": "High", "code_snippet": "..."},
]

for finding in findings:
    print(json.dumps(analyze_finding(finding), indent=2))