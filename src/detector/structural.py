from __future__ import annotations
import ast

GENERIC: frozenset[str] = frozenset({
    "data", "result", "response", "output", "value", "temp", "tmp",
    "item", "element", "obj", "info", "content", "payload", "params",
    "config", "settings", "options", "args", "kwargs", "context",
})


def score(code: str) -> float:
    signals: list[float] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 0.5
    vars_ = [n.id if isinstance(n, ast.Name) else n.arg
             for n in ast.walk(tree) if isinstance(n, (ast.Name, ast.arg))]
    if vars_:
        signals.append(min(sum(1 for v in vars_ if v in GENERIC) / len(vars_) * 2, 1.0))
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef):
            has_doc = (n.body and isinstance(n.body[0], ast.Expr)
                       and isinstance(n.body[0].value, ast.Constant)
                       and isinstance(n.body[0].value.value, str)
                       and len(n.body[0].value.value) > 20)
            if has_doc and len(n.body) <= 5:
                signals.append(0.7)
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    if fns:
        ann = sum(1 for f in fns if f.returns and all(a.annotation for a in f.args.args))
        if ann / len(fns) > 0.85:
            signals.append(0.65)
    return sum(signals) / len(signals) if signals else 0.25
