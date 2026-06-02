from urllib.parse import urlparse
from flask import redirect, request

ALLOWED_HOSTS = {"yourdomain.com", "www.yourdomain.com"}

def handle_login_redirect():
    """Redirect after login — open redirect prevented."""
    next_url = request.args.get("next", "/dashboard")
    parsed = urlparse(next_url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        next_url = "/dashboard"
    return redirect(next_url)