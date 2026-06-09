from __future__ import annotations
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

from src.models import Finding, OrchestratorResult, ReviewResult
from src.reviewers import claude_reviewer, groq_reviewer, prefilter
from src.reviewers.adjudicator import adjudicate

CACHE_DIR = "findings_cache"
os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_key(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()[:16]


def _load_cache(key: str) -> OrchestratorResult | None:
    path = os.path.join(CACHE_DIR, f"{key}.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                return OrchestratorResult.model_validate_json(f.read())
        except Exception:
            return None
    return None


def _save_cache(key: str, result: OrchestratorResult) -> None:
    path = os.path.join(CACHE_DIR, f"{key}.json")
    with open(path, "w") as f:
        f.write(result.model_dump_json())


def _sig(f: Finding) -> str:
    """Unique signature for a finding — used for cross-model comparison."""
    return f"{f.vuln_type.value}:{f.line_start}"


def analyze(code: str, use_cache: bool = True) -> OrchestratorResult:
    """
    Full dual-LLM analysis pipeline.
    1. Check cache — return immediately if code seen before
    2. Pre-filter — skip if no attack surface detected
    3. Run Claude + Groq in parallel (halves latency)
    4. Agree: both found it → HIGH confidence
    5. Disagree: adjudicate → MEDIUM confidence if confirmed
    6. Sole: only one model → LOW confidence
    Returns OrchestratorResult with three confidence tiers.
    """
    key = _cache_key(code)
    if use_cache:
        cached = _load_cache(key)
        if cached:
            return cached

    # Pre-filter: does this even have an attack surface?
    has_surface, surfaces = prefilter.has_attack_surface(code)
    if not has_surface:
        result = OrchestratorResult(
            agreed_findings=[],
            adjudicated_findings=[],
            sole_findings=[],
            claude_raw=ReviewResult(findings=[], summary="Skipped — no attack surface"),
            groq_raw=ReviewResult(findings=[], summary="Skipped — no attack surface"),
            total_findings=0,
        )
        _save_cache(key, result)
        return result

    # Run both reviewers in parallel — ThreadPoolExecutor handles blocking HTTP
    with ThreadPoolExecutor(max_workers=2) as executor:
        claude_future = executor.submit(claude_reviewer.review, code)
        groq_future   = executor.submit(groq_reviewer.review, code)
        claude_result = claude_future.result()
        groq_result   = groq_future.result()

    claude_sigs = {_sig(f): f for f in claude_result.findings}
    groq_sigs   = {_sig(f): f for f in groq_result.findings}

    agreed:      list[Finding] = []
    adjudicated: list[Finding] = []
    sole:        list[Finding] = []
    adj_sigs:    set[str]      = set()

    # Agreed findings: both models found it — highest confidence
    for sig, finding in claude_sigs.items():
        if sig in groq_sigs:
            agreed.append(finding)

    # Claude-only findings: adjudicate
    for sig, finding in claude_sigs.items():
        if sig not in groq_sigs:
            adj = adjudicate(code, finding, "claude")
            if adj.correct_model in ("claude", "both_right"):
                adjudicated.append(finding)
                adj_sigs.add(sig)

    # Groq-only findings: adjudicate
    for sig, finding in groq_sigs.items():
        if sig not in claude_sigs:
            adj = adjudicate(code, finding, "groq")
            if adj.correct_model in ("groq", "both_right"):
                adjudicated.append(finding)
                adj_sigs.add(sig)

    # Sole findings: adjudication said wrong but preserve at LOW confidence
    for sig, finding in claude_sigs.items():
        if sig not in groq_sigs and sig not in adj_sigs:
            sole.append(finding)

    total = len(agreed) + len(adjudicated) + len(sole)

    result = OrchestratorResult(
        agreed_findings=agreed,
        adjudicated_findings=adjudicated,
        sole_findings=sole,
        claude_raw=claude_result,
        groq_raw=groq_result,
        total_findings=total,
    )
    _save_cache(key, result)
    return result