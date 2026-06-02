import urllib.request

def fetch_avatar(url: str) -> bytes:
    """Fetch a user's avatar from a URL they provide."""
    # VULNERABLE: no URL validation — attacker sends http://169.254.169.254/latest/meta-data/
    with urllib.request.urlopen(url) as response:
        return response.read()