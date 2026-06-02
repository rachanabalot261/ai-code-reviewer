import json

def load_user_session(session_data: str) -> dict:
    """Load session — JSON only, pickle never used on user data."""
    try:
        data = json.loads(session_data)
        if not isinstance(data, dict):
            raise ValueError("Session must be a dict")
        return data
    except json.JSONDecodeError:
        return {}