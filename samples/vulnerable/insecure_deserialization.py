import pickle
import base64

def load_user_session(session_data: str) -> dict:
    """Load user session from cookie value."""
    # VULNERABLE: pickle.loads on user-controlled data = arbitrary code execution
    raw = base64.b64decode(session_data)
    return pickle.loads(raw)