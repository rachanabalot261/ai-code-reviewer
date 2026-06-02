from __future__ import annotations
import os
import json
import time
from dotenv import load_dotenv
import anthropic

from src.models import ReviewResult
from src.prompts import VULNERABILITY_REVIEW_SYSTEM, VULNERABILITY_REVIEW_USER

load_dotenv()

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

MODEL      = "claude-sonnet-4-6"
MAX_TOKENS = 2048
TEMPERATURE = 0   # Deterministic — security analysis must be reproducible


def review(code: str) -> ReviewResult:
    """
    Review Python code for vulnerabilities using Claude.
    Always returns ReviewResult — never raises an exception.
    Handles: invalid JSON, API timeout, rate limit, network error.
    """
    prompt = VULNERABILITY_REVIEW_USER.format(code=code)

    for attempt in range(3):
        try:
            response = _client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                system=VULNERABILITY_REVIEW_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )

            raw_text = response.content[0].text.strip()

            # Strip markdown code fences if Claude wraps output in them
            if raw_text.startswith("```"):
                lines = raw_text.split("\n")
                raw_text = "\n".join(lines[1:-1])

            data = json.loads(raw_text)
            return ReviewResult.model_validate(data)

        except json.JSONDecodeError as e:
            if attempt == 2:
                return ReviewResult(
                    findings=[],
                    summary="Claude returned invalid JSON after 3 attempts",
                    has_error=True,
                    error_message=str(e),
                )
            # Remind model to output pure JSON on retry
            prompt += "\n\nIMPORTANT: Your previous response was not valid JSON. " \
                      "Respond with ONLY valid JSON, no other text."
            time.sleep(1)

        except anthropic.RateLimitError:
            wait = 60 * (attempt + 1)
            print(f"Claude rate limit — waiting {wait}s...")
            time.sleep(wait)

        except anthropic.APITimeoutError:
            if attempt == 2:
                return ReviewResult(
                    findings=[],
                    summary="Claude API timed out",
                    has_error=True,
                    error_message="timeout",
                )
            time.sleep(5)

        except Exception as e:
            return ReviewResult(
                findings=[],
                summary=f"Unexpected error: {type(e).__name__}",
                has_error=True,
                error_message=str(e),
            )

    return ReviewResult(
        findings=[],
        summary="Failed after 3 attempts",
        has_error=True,
        error_message="max_retries_exceeded",
    )
