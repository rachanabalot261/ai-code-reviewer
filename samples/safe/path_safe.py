import os

def read_user_file(filename: str) -> str:
    """Read a file — path traversal prevented with realpath."""
    base_dir = "/var/app/uploads"
    safe_path = os.path.realpath(os.path.join(base_dir, filename))
    if not safe_path.startswith(base_dir):
        raise ValueError("Path traversal attempt detected")
    with open(safe_path, "r") as f:
        return f.read()