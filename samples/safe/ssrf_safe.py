from urllib.parse import urlparse
import urllib.request

ALLOWED_SCHEMES = {"https"}
BLOCKED_HOSTS   = {"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"}

def fetch_avatar(url: str) -> bytes:
    """Fetch avatar — SSRF prevented with scheme and host validation."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTPS allowed")
    if parsed.hostname in BLOCKED_HOSTS:
        raise ValueError("Internal address blocked")
    with urllib.request.urlopen(url) as response:
        return response.read()