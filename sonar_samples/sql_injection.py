import sqlite3


def vulnerable_login(db_path: str, username: str, password: str) -> bool:
    """
    Intentionally vulnerable example (for SonarQube comparison):
    SQL query built via string concatenation (SQL injection risk).
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Vulnerable: user-controlled input is concatenated into SQL
    query = "SELECT 1 FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row is not None


def vulnerable_login_format(db_path: str, username: str) -> bool:
    """
    Another intentionally vulnerable example:
    SQL built via string formatting (often triggers Sonar rule python:S2077).
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    query = "SELECT 1 FROM users WHERE username = '%s'" % username
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row is not None


