from __future__ import annotations
import hashlib
import json
import os
from src.sandbox_executor import run_exploit_proof
from concurrent.futures import ThreadPoolExecutor

from src.models import Finding, OrchestratorResult, ReviewResult
from src.reviewers import gemini_reviewer, groq_reviewer, prefilter
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
            gemini_raw=ReviewResult(findings=[], summary="Skipped — no attack surface"),
            groq_raw=ReviewResult(findings=[], summary="Skipped — no attack surface"),
            total_findings=0,
        )
        _save_cache(key, result)
        return result

    # Run both reviewers in parallel — ThreadPoolExecutor handles blocking HTTP
    with ThreadPoolExecutor(max_workers=2) as executor:
        gemini_future = executor.submit(gemini_reviewer.review, code)
        groq_future   = executor.submit(groq_reviewer.review, code)
        gemini_result = gemini_future.result()
        groq_result   = groq_future.result()

    gemini_sigs = {_sig(f): f for f in gemini_result.findings}
    groq_sigs   = {_sig(f): f for f in groq_result.findings}

    agreed:      list[Finding] = []
    adjudicated: list[Finding] = []
    sole:        list[Finding] = []
    adj_sigs:    set[str]      = set()
    adjudication_errors: int   = 0 

    # Agreed findings: both models found it — highest confidence
    for sig, finding in gemini_sigs.items():
        if sig in groq_sigs:
            agreed.append(finding)

    # Gemini-only findings: adjudicate
    for sig, finding in gemini_sigs.items():
        if sig not in groq_sigs:
            adj = adjudicate(code, finding, "gemini")
            if adj.errored:
                adjudication_errors += 1
            if adj.correct_model in ("gemini", "both_right"):
                adjudicated.append(finding)
                adj_sigs.add(sig)

    # Groq-only findings: adjudicate
    for sig, finding in groq_sigs.items():
        if sig not in gemini_sigs:
            adj = adjudicate(code, finding, "groq")
            if adj.errored:
                adjudication_errors += 1
            if adj.correct_model in ("groq", "both_right"):
                adjudicated.append(finding)
                adj_sigs.add(sig)

    # Sole findings: adjudication said wrong but preserve at LOW confidence
    for sig, finding in gemini_sigs.items():
        if sig not in groq_sigs and sig not in adj_sigs:
            sole.append(finding)

    exploit_proofs = []
    for finding in agreed + adjudicated:
        if finding.vuln_type.value != "HARDCODED_SECRET":
            proof = run_exploit_proof(code, finding)
            exploit_proofs.append(proof)

    total = len(agreed) + len(adjudicated) + len(sole)
    total = len(agreed) + len(adjudicated) + len(sole)

    result = OrchestratorResult(
        agreed_findings=agreed,
        adjudicated_findings=adjudicated,
        sole_findings=sole,
        gemini_raw=gemini_result,
        groq_raw=groq_result,
        total_findings=total,
        adjudication_errors=adjudication_errors,
        exploit_proofs=exploit_proofs,
    )
    _save_cache(key, result)
    return result