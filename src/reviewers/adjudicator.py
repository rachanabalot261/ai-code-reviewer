from __future__ import annotations
import os
import json
from dotenv import load_dotenv
import anthropic

from src.models import Finding, AdjudicationResult
from src.prompts import ADJUDICATOR_SYSTEM, ADJUDICATOR_USER

load_dotenv()

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL   = "claude-sonnet-4-6"


def adjudicate(code: str, finding: Finding, source_model: str) -> AdjudicationResult:
    """
    Resolve a disagreement: one model found the finding, the other didn't.
    Returns AdjudicationResult indicating which model was correct and why.
    On failure: keeps the finding with LOW confidence rather than dropping it.
    """
    prompt = ADJUDICATOR_USER.format(
        code=code,
        claude_finding=(
            f"{finding.vuln_type.value} at line {finding.line_start}: "
            f"{finding.description}"
        ),
        triggering_input=finding.triggering_input,
    )

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=256,
            temperature=0,
            system=ADJUDICATOR_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        data = json.loads(raw)
        return AdjudicationResult(
            finding=finding,
            correct_model=data.get("correct_model", "both_wrong"),
            reasoning=data.get("reasoning", ""),
        )
    except Exception as e:
        # If adjudication itself fails, keep finding with LOW confidence
        return AdjudicationResult(
            finding=finding,
            correct_model=source_model,
            reasoning=f"Adjudication failed: {e} — keeping original finding",
        )