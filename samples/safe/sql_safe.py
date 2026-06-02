import sqlite3

def get_user(username: str) -> dict:
    """Get user record — parameterised query prevents SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()