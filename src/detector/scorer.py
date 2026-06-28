from __future__ import annotations
from src.detector import structural, patterns
from src.models import AIDetectionResult


def detect_and_route(code: str) -> AIDetectionResult:
    ss = structural.score(code)
    ps, matched = patterns.score(code)
    combined = 0.4 * ss + 0.6 * ps
    routing = "FULL" if combined >= 0.6 else "MEDIUM" if combined >= 0.3 else "SKIP"
    return AIDetectionResult(
        ai_probability=round(combined, 3),
        structural_score=round(ss, 3),
        pattern_score=round(ps, 3),
        matched_patterns=matched,
        routing=routing,
    )
