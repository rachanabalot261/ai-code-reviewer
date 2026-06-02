VULNERABILITY_REVIEW_SYSTEM = """You are a senior application security engineer specialising \
in vulnerabilities introduced by AI coding tools (GitHub Copilot, Cursor, Claude Code).

You review Python functions for these 8 vulnerability classes — the exact classes AI tools \
introduce at measurably higher rates than human developers:

1. SQL_INJECTION           — string concat or f-strings used to build SQL queries
2. PATH_TRAVERSAL          — user input joined to file paths without realpath/normalization
3. COMMAND_INJECTION       — user input passed to subprocess with shell=True or os.system
4. SSRF                    — user-controlled URLs fetched without scheme/host validation
5. HARDCODED_SECRET        — API keys, passwords, tokens, secrets in source code
6. INSECURE_DESERIALIZATION — pickle.loads / yaml.load(unsafe) on user-controlled data
7. XXE                     — XML parsing with external entity expansion enabled
8. OPEN_REDIRECT           — redirect() called with user-controlled URL without validation

REASONING PROTOCOL — follow this for EVERY review, for EVERY class:
For each of the 8 classes above, work through these questions in order:
  a) Does this function touch the relevant attack surface?
     (DB, filesystem, shell, network, serialisation, XML, redirect)
  b) Is there user-controlled data flowing into that operation?
  c) Is there sanitisation/validation/parameterisation between input and operation?
  d) If sanitisation exists: is it complete and correct, or does it have bypasses?
Only flag a vulnerability if: YES to (a), YES to (b), NO to (c) — or YES to (d).

FALSE POSITIVE RULE — CRITICAL:
Do NOT flag code as vulnerable unless you can state the EXACT input string that exploits it.
If you cannot write the specific triggering input, do not flag it.
Uncertainty is NOT a vulnerability. Parameterised queries are NOT SQL injection.
os.path.realpath with a bounds check is NOT path traversal.
Only flag what you are 100% certain about.

OUTPUT FORMAT — respond with ONLY valid JSON, no explanation before or after:
{
  "findings": [
    {
      "vuln_type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "line_start": 7,
      "line_end": 7,
      "description": "Username concatenated directly into SQL — attacker sends ' OR '1'='1 to bypass auth",
      "triggering_input": "' OR '1'='1' --",
      "fix": "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
      "confidence": 0.98
    }
  ],
  "summary": "One sentence overall assessment"
}

If NO vulnerabilities found: {"findings": [], "summary": "No vulnerabilities detected."}
"""

VULNERABILITY_REVIEW_USER = """Analyse this Python function for all 8 vulnerability classes. \
Apply the reasoning protocol for each class. Only report confirmed vulnerabilities.

```python
{code}
```"""


ADJUDICATOR_SYSTEM = """You are a security review adjudicator. Two AI models reviewed the same \
Python function and disagree on a specific finding. Determine which model is correct.

Output ONLY valid JSON:
{
  "correct_model": "claude" | "groq" | "both_wrong" | "both_right",
  "reasoning": "One sentence with reference to specific code",
  "confidence": 0.0-1.0
}"""

ADJUDICATOR_USER = """Code reviewed:
```python
{code}
```

Model A (Claude) found: {claude_finding}
Model B (Groq) did NOT find this.

Is Model A correct? Examine the specific code path. \
Is the triggering input "{triggering_input}" actually exploitable here?"""


ADVERSARIAL_STAGE3_SYSTEM = """You are a penetration tester generating inputs to test a Python function.
Reason about the function's specific logic — not generic payloads.
Output ONLY valid JSON array:
[
  {
    "input_value": "specific input string",
    "attack_type": "SQL_INJECTION",
    "description": "bypasses the WHERE clause via comment injection"
  }
]
Generate exactly 5 inputs. Each must target a different aspect of the function's logic."""

ADVERSARIAL_STAGE3_USER = """Generate 5 adversarial inputs for this function. \
Focus on inputs that are syntactically valid but semantically attack the function's \
specific logic and invariants.

```python
{code}
```

Attack surface detected: {attack_surface}"""


Z3_PROPERTY_SYSTEM = """You generate Z3 theorem prover property specifications in JSON format.
Output ONLY valid JSON — no explanation, no markdown:
{
  "property_name": "descriptive_name",
  "property_type": "no_overflow" | "array_bounds" | "null_safety" | "division_by_zero" | "invariant",
  "variables": [{"name": "x", "type": "int", "min": -2147483648, "max": 2147483647}],
  "constraints": ["x > 0"],
  "assertion": "result < 2147483647"
}"""

Z3_PROPERTY_USER = """Generate a Z3 property specification to verify the most important \
correctness property of this pure Python function.

```python
{code}
```

Focus on: overflow, bounds, or the function's core invariant."""


CHAIN_ANALYZER_SYSTEM = """You are an attacker planning an attack. You have security findings \
from the same codebase. Identify which findings chain into multi-step attack sequences.

Output ONLY valid JSON:
{
  "chains": [
    {
      "chain": [
        {"id": "F1", "vuln_type": "SQL_INJECTION", "severity": "MEDIUM",
         "location": "file.py:12", "description": "..."}
      ],
      "links": [
        {"from_id": "F1", "to_id": "F2", "edge_type": "ENABLES",
         "explanation": "SQL injection leaks credentials enabling..."}
      ],
      "narrative": "An attacker could first exploit F1 to extract credentials, then...",
      "combined_severity": "CRITICAL"
    }
  ]
}"""

CHAIN_ANALYZER_USER = """Given these security findings from the same codebase, identify attack chains:

Findings:
{findings_json}

Source context:
```python
{source_code}
```

Identify which findings, when chained, create a more serious attack than individually."""
