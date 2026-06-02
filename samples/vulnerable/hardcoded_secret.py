import jwt

SECRET_KEY   = "supersecret123"
ADMIN_PASS   = "admin123"
DB_PASSWORD  = "production_db_pass_2024"

def generate_token(user_id: int) -> str:
    """Generate a JWT token."""
    # VULNERABLE: secret is in source code — anyone with repo access owns all tokens
    return jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm="HS256")