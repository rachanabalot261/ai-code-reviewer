from __future__ import annotations
import ast
from dataclasses import dataclass, field

IMPURE: frozenset[str] = frozenset({
    "execute", "executemany", "commit", "open", "write", "read", "unlink",
    "urlopen", "get", "post", "connect", "send", "system", "popen",
    "run", "call", "Popen", "print", "random", "randint", "choice", "sleep",
})
IMPURE_MODS: frozenset[str] = frozenset({
    "os", "sys", "subprocess", "socket", "requests", "urllib", "http",
    "sqlite3", "random", "secrets", "time", "datetime",
})


@dataclass
class PurityResult:
    is_pure: bool
    reasons: list[str] = field(default_factory=list)


def check_purity(code: str) -> PurityResult:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return PurityResult(False, [f"SyntaxError: {e}"])
    reasons: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            nm = (n.func.attr if isinstance(n.func, ast.Attribute)
                  else n.func.id if isinstance(n.func, ast.Name) else "")
            if nm in IMPURE:
                reasons.append(f"Calls impure: {nm}()")
        if isinstance(n, ast.Global):
            reasons.append(f"Mutates global: {', '.join(n.names)}")
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mod = getattr(n, "module", "") or ""
            for a in getattr(n, "names", []):
                full = f"{mod}.{a.name}" if mod else a.name
                if any(m in full for m in IMPURE_MODS):
                    reasons.append(f"Imports I/O module: {full}")
    return PurityResult(len(reasons) == 0, reasons)
