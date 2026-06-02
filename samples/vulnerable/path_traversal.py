import os

def read_user_file(filename: str) -> str:
    """Read a file from the uploads directory."""
    base_dir = "/var/app/uploads"
    # VULNERABLE: filename not sanitised — ../../etc/passwd works
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "r") as f:
        return f.read()