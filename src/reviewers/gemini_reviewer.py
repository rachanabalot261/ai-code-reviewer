from __future__ import annotations
import os, json, time
from dotenv import load_dotenv
from openai import OpenAI
from src.models import ReviewResult
from src.prompts import VULNERABILITY_REVIEW_SYSTEM, VULNERABILITY_REVIEW_USER

load_dotenv()

_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])  # no base_url — defaults to OpenAI
MODEL = "gpt-5.4-mini"

def review(code: str) -> ReviewResult:
    """
    Review Python code for vulnerabilities using Claude via OpenRouter.
    Always returns ReviewResult — never raises an exception.
    """
    prompt = VULNERABILITY_REVIEW_USER.format(code=code)

    for attempt in range(3):
        try:
            response = _client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": VULNERABILITY_REVIEW_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            data = json.loads(raw)
            return ReviewResult.model_validate(data)

        except json.JSONDecodeError as e:
            if attempt == 2:
                return ReviewResult(
                    findings=[],
                    summary="Model returned invalid JSON after 3 attempts",
                    has_error=True,
                    error_message=str(e),
                )
            continue

        except Exception as e:
            err = str(e).lower()
            if "rate" in err or "429" in err:
                wait = 10 * (attempt + 1)
                print(f"  [OpenRouter] Rate limit hit — waiting {wait}s")
                time.sleep(wait)
                continue
            return ReviewResult(
                findings=[],
                summary=f"OpenRouter error: {type(e).__name__}",
                has_error=True,
                error_message=str(e),
            )

    return ReviewResult(
        findings=[],
        summary="Failed after 3 attempts",
        has_error=True,
        error_message="max_retries_exceeded",
    )