from flask import redirect, request

def handle_login_redirect():
    """After login, redirect user to their requested page."""
    next_url = request.args.get("next", "/dashboard")
    # VULNERABLE: no validation that next_url is relative — attacker sends https://evil.com
    return redirect(next_url)