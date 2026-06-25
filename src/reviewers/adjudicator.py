from __future__ import annotations
import os, json
from dotenv import load_dotenv
from openai import OpenAI
from src.models import Finding, AdjudicationResult
from src.prompts import ADJUDICATOR_SYSTEM, ADJUDICATOR_USER

load_dotenv()

_client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ["OPENAI_BASE_URL"],
)
MODEL = "anthropic/claude-sonnet-4.6"  # CONFIRM this exact slug on openrouter.ai/models before running


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
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": ADJUDICATOR_SYSTEM},
                {"role": "user", "content": prompt},
            ],
        )
        raw = response.choices[0].message.content.strip()
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
            errored=False,
        )
    except Exception as e:
        # Conservative: keep finding on failure
        return AdjudicationResult(
            finding=finding,
            correct_model=source_model,
            reasoning=f"Adjudication failed ({type(e).__name__}) — kept conservatively",
            errored=True,
        )