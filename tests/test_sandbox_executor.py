import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.sandbox_executor import run_exploit_proof
from src.models import Finding, VulnerabilityType, Severity

with open("samples/vulnerable/command_injection.py") as f:
    code = f.read()

# Manually constructed finding — replace triggering_input with whatever
# your actual model reported for this sample if you want to test the real claim
finding = Finding(
    vuln_type=VulnerabilityType.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    line_start=1,
    line_end=1,
    description="test",
    triggering_input="; echo PWNED",
    fix="use list args, no shell=True",
    confidence=0.9,
)

proof = run_exploit_proof(code, finding)
print(proof.model_dump_json(indent=2))