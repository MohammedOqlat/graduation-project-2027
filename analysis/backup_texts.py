# backup_texts.py
# Fixed texts used when the LLM is unavailable or returns an invalid answer.

BACKUP_TEXTS = {
    "SQL Injection": {
        "impact": "An attacker can read, change or delete data in the database without permission, and may be able to log in without a valid password.",
        "explanation": "User input is joined directly into the SQL query string, so the input can change the meaning of the query instead of being treated as plain data.",
        "recommendation": 'Use a parameterized query, for example cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)), instead of building the query with string concatenation.',
    },
    "XSS": {
        "impact": "An attacker can run malicious JavaScript in another user's browser, which can steal session data or change what the page shows.",
        "explanation": "User input is placed into a web page without escaping, so the browser treats it as code instead of text.",
        "recommendation": "Escape all user-supplied output before it is placed in HTML, for example with html.escape(), or use a template engine that escapes by default.",
    },
    "Command Injection": {
        "impact": "An attacker can run any command on the server, which can lead to data theft or full control of the machine.",
        "explanation": "User input is passed to os.system or to subprocess with shell=True, so special shell characters in the input are executed as commands.",
        "recommendation": 'Use subprocess.run with a list of arguments and without shell=True, for example subprocess.run(["ping", "-c", "1", host]), and validate the input.',
    },
    "Hardcoded Secrets": {
        "impact": "Anyone who can read the source code, including through a public repository, can see the password or API key and use it.",
        "explanation": "A secret such as a password or an API key is written directly in the code instead of being stored outside it.",
        "recommendation": 'Move the secret to an environment variable and read it with os.environ.get("API_KEY"), and rotate any secret that was already exposed.',
    },
}

if __name__ == "__main__":
    print("Loaded", len(BACKUP_TEXTS), "backup texts:")
    for name in BACKUP_TEXTS:
        print("-", name)