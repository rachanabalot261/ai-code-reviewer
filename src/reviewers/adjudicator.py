from __future__ import annotations
import os, json
from src.reviewers.gemini_throttle import throttle
from dotenv import load_dotenv
from google import genai
from google.genai import types
from src.models import Finding, AdjudicationResult
from src.prompts import ADJUDICATOR_SYSTEM, ADJUDICATOR_USER

load_dotenv()

_client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
MODEL   = "gemini-2.5-flash"


def adjudicate(code: str, finding: Finding, source_model: str) -> AdjudicationResult:
    """
    One model found the finding, the other did not. Who is right?
    On failure: keeps finding conservatively.
    Fail safe, not fail silent.
    """
    prompt = ADJUDICATOR_USER.format(
        code=code,
        vuln_type=finding.vuln_type.value,
        line_start=finding.line_start,
        description=finding.description,
        triggering_input=finding.triggering_input,
    )
    try:
        throttle.wait()
        response = _client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=ADJUDICATOR_SYSTEM,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        data    = json.loads(raw)
        correct = data.get("correct_model", source_model)
        if correct == "model_a":
            correct = source_model
        elif correct == "model_b":
            correct = "both_wrong"
        return AdjudicationResult(
            finding=finding,
            correct_model=correct,
            reasoning=data.get("reasoning", ""),
            confidence=float(data.get("confidence", 0.5)),
        )
    except Exception as e:
        # Conservative: keep finding on failure
        return AdjudicationResult(
            finding=finding,
            correct_model=source_model,
            reasoning=f"Adjudication failed ({type(e).__name__}) — kept conservatively",
            confidence=0.4,
            errored=True,
        )