from __future__ import annotations
import os
import json
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

_client = Groq(api_key=os.environ["GROQ_API_KEY"])
MODEL   = "llama-3.1-8b-instant"

_SYSTEM = """Respond ONLY with valid JSON: \
{"has_attack_surface": true/false, "surfaces": ["SQL", "FILESYSTEM", ...]}
Attack surfaces to check for: SQL (database queries), FILESYSTEM (file read/write), \
SHELL (subprocess/os.system), NETWORK (HTTP/socket calls), \
SERIALIZATION (pickle/yaml), XML (xml parsing), REDIRECT (flask redirect/302)."""

_USER = """Does this Python function touch any of these attack surfaces?
```python
{code}
```"""


def has_attack_surface(code: str) -> tuple[bool, list[str]]:
    """
    Fast free check: does this function touch any attack surface?
    Returns (bool, list_of_surfaces).
    On ANY error: returns (True, []) — fail open so nothing is skipped due to API errors.
    This is intentional. Never skip a function because the filter API call failed.
    """
    try:
        response = _client.chat.completions.create(
            model=MODEL,
            max_tokens=100,
            temperature=0,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": _USER.format(code=code)},
            ],
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        return data.get("has_attack_surface", True), data.get("surfaces", [])
    except Exception:
        # Fail open — always better to over-analyse than miss a vulnerability
        return True, []