import subprocess
import re

def ping_host(host: str) -> str:
    """Ping a host — shell injection prevented."""
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        raise ValueError("Invalid hostname")
    # List form + no shell=True = no injection possible
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout