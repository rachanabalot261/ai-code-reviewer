from __future__ import annotations
import os
import json
import time
from dotenv import load_dotenv
from groq import Groq

from src.models import ReviewResult
from src.prompts import VULNERABILITY_REVIEW_SYSTEM, VULNERABILITY_REVIEW_USER

load_dotenv()

_client = Groq(api_key=os.environ["GROQ_API_KEY"])

MODEL       = "llama-3.3-70b-versatile"
MAX_TOKENS  = 2048
TEMPERATURE = 0


def review(code: str) -> ReviewResult:
    """
    Review Python code for vulnerabilities using Llama via Groq.
    Identical interface to claude_reviewer.review().
    Always returns ReviewResult — never raises.
    """
    prompt = VULNERABILITY_REVIEW_USER.format(code=code)

    for attempt in range(3):
        try:
            response = _client.chat.completions.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                messages=[
                    {"role": "system", "content": VULNERABILITY_REVIEW_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                response_format={"type": "json_object"},  # Groq enforces valid JSON
            )

            raw_text = response.choices[0].message.content.strip()
            data = json.loads(raw_text)
            return ReviewResult.model_validate(data)

        except json.JSONDecodeError as e:
            if attempt == 2:
                return ReviewResult(
                    findings=[],
                    summary="Groq returned invalid JSON after 3 attempts",
                    has_error=True,
                    error_message=str(e),
                )
            time.sleep(1)

        except Exception as e:
            err = str(e).lower()
            if "rate_limit" in err or "429" in err:
                time.sleep(30 * (attempt + 1))
                continue
            return ReviewResult(
                findings=[],
                summary=f"Groq error: {type(e).__name__}",
                has_error=True,
                error_message=str(e),
            )

    return ReviewResult(
        findings=[],
        summary="Groq failed after 3 attempts",
        has_error=True,
        error_message="max_retries_exceeded",
    )