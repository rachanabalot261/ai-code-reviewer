import subprocess

def ping_host(host: str) -> str:
    """Ping a host and return output."""
    # VULNERABLE: host goes directly into shell — attacker sends 127.0.0.1; cat /etc/passwd
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout