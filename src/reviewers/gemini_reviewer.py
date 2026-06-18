from __future__ import annotations
import os, json, time
from dotenv import load_dotenv
from google import genai
from google.genai import types
from src.models import ReviewResult
from src.prompts import VULNERABILITY_REVIEW_SYSTEM, VULNERABILITY_REVIEW_USER

load_dotenv()

_client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
MODEL   = "gemini-2.5-flash"


def review(code: str) -> ReviewResult:
    """
    Review Python code for vulnerabilities using Gemini 2.5 Flash.
    Always returns ReviewResult ??? never raises an exception.
    response_mime_type enforces JSON at API level ??? not just a prompt instruction.
    thinking_mode=none makes output deterministic and fast.
    """
    prompt = VULNERABILITY_REVIEW_USER.format(code=code)

    for attempt in range(3):
        try:
            response = _client.models.generate_content(
                model=MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=VULNERABILITY_REVIEW_SYSTEM,
                    response_mime_type="application/json",
                    thinking_config=types.ThinkingConfig(
                        thinking_budget=0
                    ),
                ),
            )
            raw = response.text.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            data = json.loads(raw)
            return ReviewResult.model_validate(data)

        except json.JSONDecodeError as e:
            if attempt == 2:
                return ReviewResult(
                    findings=[],
                    summary="Gemini returned invalid JSON after 3 attempts",
                    has_error=True,
                    error_message=str(e),
                )
            time.sleep(1 * (attempt + 1))

        except Exception as e:
            err = str(e).lower()
            if "quota" in err or "429" in err or "resource_exhausted" in err:
                wait = 30 * (attempt + 1)
                print(f"  [Gemini] Quota hit ??? waiting {wait}s")
                time.sleep(wait)
                continue
            if "503" in err or "unavailable" in err:
                time.sleep(10 * (attempt + 1))
                continue
            return ReviewResult(
                findings=[],
                summary=f"Gemini error: {type(e).__name__}",
                has_error=True,
                error_message=str(e),
            )

    return ReviewResult(
        findings=[],
        summary="Gemini failed after 3 attempts",
        has_error=True,
        error_message="max_retries_exceeded",
    )
