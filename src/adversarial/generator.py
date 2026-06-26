"""
3-stage adversarial test case generator.
Stages 1+2: FREE, no LLM, deterministic.
Stage 3: gemini-2.0-flash — semantic inputs specific to this function.
"""
from __future__ import annotations
import ast, os, json
from dotenv import load_dotenv
from google import genai
from google.genai import types
from src.models import TestCase
from src.prompts import ADVERSARIAL_STAGE3_SYSTEM, ADVERSARIAL_STAGE3_USER

load_dotenv()
_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])  # no base_url — defaults to OpenAI
MODEL = "gpt-5.4-mini"

# Stage 1: Boundary Values (FREE)
BOUNDARY: list[TestCase] = [
    TestCase(input_value="",           attack_type="BOUNDARY", description="empty string"),
    TestCase(input_value="A" * 10_000, attack_type="BOUNDARY", description="10k chars"),
    TestCwase(input_value="\x00",       attack_type="BOUNDARY", description="null byte"),
    TestCase(input_value="0",          attack_type="BOUNDARY", description="zero"),
    TestCase(input_value="-1",         attack_type="BOUNDARY", description="negative"),
    TestCase(input_value="2147483648", attack_type="BOUNDARY", description="INT32_MAX+1"),
]

# Stage 2: Injection Payloads (FREE)
SQL_PL: list[TestCase] = [
    TestCase(input_value="' OR '1'='1",                                attack_type="SQL_INJECTION", description="auth bypass"),
    TestCase(input_value="'; DROP TABLE users; --",                     attack_type="SQL_INJECTION", description="destructive"),
    TestCase(input_value="' UNION SELECT username,password FROM users --", attack_type="SQL_INJECTION", description="data extraction"),
    TestCase(input_value="1' AND SLEEP(5)--",                           attack_type="SQL_INJECTION", description="time-based blind"),
]
PATH_PL: list[TestCase] = [
    TestCase(input_value="../../../etc/passwd",    attack_type="PATH_TRAVERSAL", description="Unix passwd"),
    TestCase(input_value="%2e%2e%2fetc%2fpasswd", attack_type="PATH_TRAVERSAL", description="URL-encoded"),
    TestCase(input_value="....//....//etc/passwd", attack_type="PATH_TRAVERSAL", description="double-dot bypass"),
    TestCase(input_value="/etc/passwd",            attack_type="PATH_TRAVERSAL", description="absolute path"),
]
CMD_PL: list[TestCase] = [
    TestCase(input_value="127.0.0.1; cat /etc/passwd", attack_type="COMMAND_INJECTION", description="semicolon chain"),
    TestCase(input_value="127.0.0.1 | id",             attack_type="COMMAND_INJECTION", description="pipe to id"),
    TestCase(input_value="$(whoami)",                   attack_type="COMMAND_INJECTION", description="command substitution"),
    TestCase(input_value="`id`",                        attack_type="COMMAND_INJECTION", description="backtick"),
]
SSRF_PL: list[TestCase] = [
    TestCase(input_value="http://169.254.169.254/latest/meta-data/", attack_type="SSRF", description="AWS metadata"),
    TestCase(input_value="http://localhost:6379/",                    attack_type="SSRF", description="internal Redis"),
    TestCase(input_value="file:///etc/passwd",                        attack_type="SSRF", description="file:// scheme"),
]


def _surfaces(code: str) -> list[str]:
    """AST-based surface detection — deterministic, zero cost."""
    srf: set[str] = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ["UNKNOWN"]
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        nm = (n.func.attr if isinstance(n.func, ast.Attribute)
              else n.func.id if isinstance(n.func, ast.Name) else "")
        if nm in ("execute", "executemany"):                     srf.add("SQL")
        if nm in ("open", "read", "write", "listdir"):           srf.add("FILESYSTEM")
        if nm in ("run", "call", "system", "popen", "Popen"):    srf.add("SHELL")
        if nm in ("urlopen", "get", "post", "request", "fetch"): srf.add("NETWORK")
        if nm in ("loads", "load") and "pickle" in code:        srf.add("SERIALIZATION")
        if "xml" in code.lower() or "etree" in code.lower():    srf.add("XML")
        if nm == "redirect":                                     srf.add("REDIRECT")
    return list(srf)


def _stage3(code: str, surfaces: list[str]) -> list[TestCase]:
    """Gemini generates inputs that attack THIS function's specific logic."""
    try:
        response = _client.models.generate_content(
            model=MODEL,
            contents=ADVERSARIAL_STAGE3_USER.format(
                code=code,
                attack_surface=", ".join(surfaces) or "none"
            ),
            config=types.GenerateContentConfig(
                system_instruction=ADVERSARIAL_STAGE3_SYSTEM,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        return [TestCase(**i) for i in json.loads(raw) if isinstance(i, dict)]
    except Exception:
        return []  # Stage 3 failure is non-fatal — stages 1+2 still ran


def generate_test_cases(code: str) -> list[TestCase]:
    """Full 3-stage generation. Returns all test cases to run."""
    srfs  = _surfaces(code)
    cases = list(BOUNDARY)
    if "SQL" in srfs:        cases.extend(SQL_PL)
    if "FILESYSTEM" in srfs: cases.extend(PATH_PL)
    if "SHELL" in srfs:      cases.extend(CMD_PL)
    if "NETWORK" in srfs:    cases.extend(SSRF_PL)
    cases.extend(_stage3(code, srfs))
    return cases