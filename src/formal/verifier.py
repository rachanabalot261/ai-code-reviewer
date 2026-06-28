from __future__ import annotations
import os, sys, json, subprocess, tempfile, ast
from dotenv import load_dotenv
from openai import OpenAI
from src.models import Z3PropertyJSON, Z3Result
from src.formal.purity import check_purity
from src.prompts import Z3_PROPERTY_SYSTEM, Z3_PROPERTY_USER

load_dotenv()
_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
MODEL = "gpt-5.4-mini"


class _BoolOpToZ3(ast.NodeTransformer):
    """Z3 symbolic booleans cannot use Python's and/or/not keywords directly -
    they raise on the implicit truthiness check Python tries internally.
    This rewrites them into Z3's And()/Or()/Not() function calls."""
    def visit_BoolOp(self, node):
        self.generic_visit(node)
        func_name = "And" if isinstance(node.op, ast.And) else "Or"
        return ast.Call(func=ast.Name(id=func_name, ctx=ast.Load()), args=node.values, keywords=[])

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Not):
            return ast.Call(func=ast.Name(id="Not", ctx=ast.Load()), args=[node.operand], keywords=[])
        return node


def _normalize_ops(expr: str) -> str:
    """LLMs sometimes emit C-style operators (&&, ||, !) instead of Python's
    and/or/not. Normalize before AST parsing."""
    return (
        expr.replace("&&", " and ").replace("||", " or ")
        .replace("!=", "<<NEQ>>").replace("!", " not ").replace("<<NEQ>>", "!=")
    )


def _compile_expr(expr: str) -> str:
    """Full pipeline: normalize C-style ops, then rewrite Python bool
    keywords into Z3 function calls. This is the deterministic compiler
    step - the LLM only ever produces the JSON IR, never raw Z3 code."""
    tree = ast.parse(_normalize_ops(expr).strip(), mode="eval")
    tree = _BoolOpToZ3().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def _to_z3(prop: Z3PropertyJSON) -> str:
    lines = ["from z3 import *", "s = Solver()", "s.set('timeout', 10000)", ""]
    for v in prop.variables:
        n, t = v["name"], v.get("type", "int")
        if t == "int":
            lines.append(f"{n} = Int('{n}')")
            if "min" in v:
                lines.append(f"s.add({n} >= {v['min']})")
            if "max" in v:
                lines.append(f"s.add({n} <= {v['max']})")
        elif t == "real":
            lines.append(f"{n} = Real('{n}')")
        elif t == "bool":
            lines.append(f"{n} = Bool('{n}')")
    lines.append("")
    for c in prop.constraints:
        lines.append(f"s.add({_compile_expr(c)})")
    assertion = _compile_expr(prop.assertion)
    lines += [
        "", f"s.add(Not({assertion}))", "",
        "r = s.check()",
        "if r == sat:",
        "  m = s.model()",
        "  ce = {str(d): str(m[d]) for d in m.decls()}",
        "  print('COUNTEREXAMPLE')",
        "  import json; print(json.dumps(ce))",
        "elif r == unsat: print('PROVED')",
        "else: print('TIMEOUT')",
    ]
    return "\n".join(lines)


def verify(code: str) -> Z3Result | None:
    if not check_purity(code).is_pure:
        return None

    try:
        response = _client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": Z3_PROPERTY_SYSTEM},
                {"role": "user", "content": Z3_PROPERTY_USER.format(code=code)},
            ],
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("`"):
            raw = "\n".join(raw.split("\n")[1:-1])
        prop = Z3PropertyJSON.model_validate(json.loads(raw))
    except Exception as e:
        return Z3Result(property_name="unknown", status="ERROR",
                         human_readable=f"Property generation failed: {e}")

    try:
        z3_script = _to_z3(prop)
    except Exception as e:
        return Z3Result(property_name=prop.property_name, status="ERROR",
                         human_readable=f"Expression compilation failed: {e}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(z3_script)
        sp = f.name
    try:
        p = subprocess.run([sys.executable, sp], capture_output=True, text=True, timeout=15)
        out = p.stdout.strip()
        if out.startswith("PROVED"):
            return Z3Result(property_name=prop.property_name, status="PROVED",
                             human_readable=f"Z3 proved: '{prop.assertion}' holds for ALL valid inputs.")
        elif out.startswith("COUNTEREXAMPLE"):
            ls = out.split("\n")
            ce = json.loads(ls[1]) if len(ls) > 1 else {}
            return Z3Result(property_name=prop.property_name, status="COUNTEREXAMPLE",
                             counterexample=ce,
                             human_readable=f"Z3 found: when {ce}, '{prop.assertion}' is VIOLATED.")
        elif out.startswith("TIMEOUT"):
            return Z3Result(property_name=prop.property_name, status="TIMEOUT",
                             human_readable="Z3 timed out - property too complex.")
        else:
            return Z3Result(property_name=prop.property_name, status="ERROR",
                             human_readable=f"Unexpected Z3 output: {out!r} | stderr: {p.stderr[:300]}")
    except subprocess.TimeoutExpired:
        return Z3Result(property_name=prop.property_name, status="TIMEOUT",
                         human_readable="Z3 hard timeout (15s).")
    except Exception as e:
        return Z3Result(property_name=prop.property_name, status="ERROR",
                         human_readable=f"Z3 error: {e}")
    finally:
        try:
            os.unlink(sp)
        except OSError:
            pass
