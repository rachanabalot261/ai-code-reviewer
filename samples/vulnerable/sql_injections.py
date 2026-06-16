import sqlite3

def get_user(username: str) -> dict:
    """Get user record by username."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: direct string interpolation — attacker sends ' OR '1'='1
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()