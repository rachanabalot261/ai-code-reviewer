from __future__ import annotations
import ast, os, json, sys, time
from dotenv import load_dotenv
from src.orchestrator import analyze as orch
from src.formal.verifier import verify
from src.detector.scorer import detect_and_route
from src.chainer.analyzer import analyze_chains

load_dotenv()


def extract_functions(code: str) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [(code, 1)]
    fns = []
    lines = code.split("\n")
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef):
            fns.append(("\n".join(lines[n.lineno - 1:n.end_lineno]), n.lineno))
    return fns or [(code, 1)]


def extract_module_context(code: str) -> str:
    """Top-level statements outside any function (imports, constants,
    secrets). Without these, extracted function snippets lose both the
    names they depend on at runtime (breaking sandbox execution) and any
    module-level vulnerability the function body never directly shows
    (e.g. a hardcoded secret assigned above the function, not inside it)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ""
    lines = code.split("\n")
    ctx_lines = []
    for n in tree.body:
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ctx_lines.extend(lines[n.lineno - 1:n.end_lineno])
    return "\n".join(ctx_lines)


def analyze_file(filepath: str, run_z3: bool = True) -> dict:
    t = time.time()
    with open(filepath, encoding="utf-8") as f:
        src = f.read()
    fns = extract_functions(src)
    ctx_block = extract_module_context(src)
    ctx_line_count = len(ctx_block.split("\n")) if ctx_block else 0
    all_f = []
    all_p = []
    all_z = []

    print(f"\n?? {filepath} - {len(fns)} function(s)")
    for code, sl in fns:
        snippet = (ctx_block + "\n" + code) if ctx_block else code
        det = detect_and_route(snippet)
        print(f"  line {sl:4d} ai={det.ai_probability:.2f} {det.routing:6s}", end="", flush=True)
        if det.routing == "SKIP":
            print()
            continue

        r = orch(snippet)
        off = (sl - 1) - ctx_line_count
        for fi in r.agreed_findings + r.adjudicated_findings + r.sole_findings:
            fi.line_start += off
            fi.line_end += off
        all_f.extend(r.agreed_findings + r.adjudicated_findings)
        all_p.extend(r.exploit_proofs)
        print(f" {r.total_findings}f", end="")
        if r.exploit_proofs:
            confirmed_n = sum(1 for p in r.exploit_proofs if p.confirmed)
            print(f" [exploit:{confirmed_n}/{len(r.exploit_proofs)}]", end="")

        if run_z3:
            z = verify(snippet)
            if z:
                all_z.append(z)
                print(f" [Z3:{z.status}]", end="")
        print()

    chains = analyze_chains(all_f, src) if len(all_f) >= 2 else []

    return {
        "filepath": filepath,
        "elapsed": round(time.time() - t, 1),
        "total_findings": len(all_f),
        "confirmed_exploits": sum(1 for p in all_p if p.confirmed),
        "findings": [f.model_dump() for f in all_f],
        "exploit_proofs": [p.model_dump() for p in all_p],
        "z3_results": [z.model_dump() for z in all_z],
        "attack_chains": [c.model_dump() for c in chains],
        "has_critical": any(f.severity.value == "CRITICAL" for f in all_f),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <file.py> [--no-z3]")
        sys.exit(1)
    flags = sys.argv[2:]
    r = analyze_file(sys.argv[1], "--no-z3" not in flags)
    print("\n" + json.dumps(r, indent=2))
