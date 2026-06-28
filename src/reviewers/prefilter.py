"""
Pre-filter: fast binary check before expensive dual-LLM review.
Fails OPEN on any error - never skips a function due to API failure.
"""
from __future__ import annotations
import os, json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
MODEL = "gpt-5.4-mini"

_SYS = """Respond ONLY with JSON: {"has_attack_surface": true/false, "surfaces": [...]}
Surfaces to check: SQL | FILESYSTEM | SHELL | NETWORK | SERIALIZATION | XML | REDIRECT
If none apply: {"has_attack_surface": false, "surfaces": []}"""

_USR = """Does this Python function touch any attack surface?
```python
{code}
```"""


def has_attack_surface(code: str) -> tuple[bool, list[str]]:
    """
    Returns (has_surface, surfaces).
    FAILS OPEN on any error - always returns (True, []) on failure.
    Cost of missing a vulnerability >> cost of one unnecessary call.
    """
    try:
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": _SYS},
                {"role": "user", "content": _USR.format(code=code)},
            ],
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        data = json.loads(raw)
        return bool(data.get("has_attack_surface", True)), list(data.get("surfaces", []))
    except Exception:
        return True, []  # Fail open - always