from __future__ import annotations
import os, json
from dotenv import load_dotenv
from openai import OpenAI
from src.models import Finding, VulnNode, ChainLink, ChainResult, Severity
from src.prompts import CHAIN_ANALYZER_SYSTEM, CHAIN_ANALYZER_USER

load_dotenv()
_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
MODEL = "gpt-5.4-mini"

_ORD = {s.value: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}


def _upgrade(sevs: list[Severity]) -> Severity:
    if not sevs:
        return Severity.LOW
    mx = max(sevs, key=lambda s: _ORD[s.value])
    med = sum(1 for s in sevs if s == Severity.MEDIUM)
    hi = sum(1 for s in sevs if s == Severity.HIGH)
    if med >= 2 and mx == Severity.MEDIUM:
        return Severity.HIGH
    if (hi >= 1 or mx == Severity.HIGH) and len(sevs) >= 2:
        return Severity.CRITICAL
    return mx


def analyze_chains(findings: list[Finding], source_code: str) -> list[ChainResult]:
    if len(findings) < 2:
        return []
    fj = json.dumps([{
        "id": f"F{i+1}", "vuln_type": f.vuln_type.value,
        "severity": f.severity.value, "location": f"line {f.line_start}",
        "description": f.description,
    } for i, f in enumerate(findings)], indent=2)
    try:
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": CHAIN_ANALYZER_SYSTEM},
                {"role": "user", "content": CHAIN_ANALYZER_USER.format(
                    findings_json=fj, source_code=source_code[:3500]
                )},
            ],
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("`"):
            raw = "\n".join(raw.split("\n")[1:-1])
        data = json.loads(raw)
    except Exception as e:
        print(f"  [Chain] Failed: {e}")
        return []
    results: list[ChainResult] = []
    for cd in data.get("chains", []):
        try:
            nodes = [VulnNode(**n) for n in cd.get("chain", [])]
            links = [ChainLink(**l) for l in cd.get("links", [])]
            results.append(ChainResult(
                chain=nodes, links=links,
                narrative=cd.get("narrative", ""),
                combined_severity=_upgrade([Severity(n.severity) for n in nodes]),
            ))
        except Exception:
            continue
    return results
