from __future__ import annotations
import ast, re

PATTERNS: list[tuple[str, object]] = []


def _reg(desc):
    def d(fn):
        PATTERNS.append((desc, fn))
        return fn
    return d


@_reg("SQL concat or f-string in query")
def sql_concat(c):
    return bool(re.search(r'(?:SELECT|INSERT|UPDATE|DELETE)', c, re.I)) and ("+" in c or bool(re.search(r'f["\'].*\{', c)))


@_reg("No input validation before use")
def no_valid(c):
    try:
        tree = ast.parse(c)
    except Exception:
        return False
    for f in ast.walk(tree):
        if isinstance(f, ast.FunctionDef) and f.args.args and len(f.body) > 2:
            if not any(isinstance(n, (ast.If, ast.Raise, ast.Assert)) for n in ast.walk(f)):
                return True
    return False


@_reg("Hardcoded credential string literal")
def hc(c):
    return any(re.search(p, c.lower()) for p in [
        r'password\s*=\s*["\'][^"\']{4,}["\']',
        r'secret(?:_key)?\s*=\s*["\'][^"\']{4,}["\']',
        r'api_key\s*=\s*["\'][^"\']{4,}["\']',
    ])


@_reg("pickle.loads on user data")
def pkl(c):
    return "pickle.loads" in c or "pickle.load(" in c


@_reg("shell=True with variable input")
def shell_var(c):
    return "shell=True" in c and any(x in c for x in ["f'", 'f"', ".format(", " + "])


@_reg("XML without defusedxml")
def xml_bare(c):
    return ("etree" in c or "minidom" in c) and "defusedxml" not in c


def score(code: str) -> tuple[float, list[str]]:
    matched = [d for d, fn in PATTERNS if fn(code)]
    return min(len(matched) * 0.25, 1.0), matched
