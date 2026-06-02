import os
import jwt

def generate_token(user_id: int) -> str:
    """Generate JWT — key loaded from environment variable, never hardcoded."""
    secret = os.environ["JWT_SECRET_KEY"]
    return jwt.encode({"user_id": user_id}, secret, algorithm="HS256")
