from __future__ import annotations
import json
import subprocess
import tempfile
import os

from src.models import Finding, ExploitProof

DOCKER_IMAGE = "sandbox-runner"
TIMEOUT_SECONDS = 10


def run_exploit_proof(code: str, finding: Finding) -> ExploitProof:
    """
    Runs the triggering_input from a Finding against the actual code,
    fully sandboxed in Docker (no network, capped resources, read-only mount).
    Returns an ExploitProof — confirmed=True only if the exploit input
    actually executed against the code without the call itself erroring out.

    NOTE: confirmed=True means "the input ran through the vulnerable path,"
    not "we proved arbitrary code execution" — for command/SQL injection
    where the model's claim is exactly that, this is the right signal.
    For other classes (e.g. hardcoded secrets) this sandbox check isn't
    meaningful — only call this for exploitable-input vuln types.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=128m",
                "--pids-limit=50",
                "-v", f"{tmp_path}:/sandbox/target.py:ro",
                DOCKER_IMAGE,
                finding.triggering_input,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )

        if result.returncode != 0 and not result.stdout.strip():
            return ExploitProof(
                input_used=finding.triggering_input,
                actual_output="",
                confirmed=False,
                exploit_description=f"Docker run failed: {result.stderr.strip()[:500]}",
                attack_type=finding.vuln_type.value,
            )

        data = json.loads(result.stdout.strip().splitlines()[-1])

        confirmed = data.get("exception") is None and bool(data.get("output"))

        return ExploitProof(
            input_used=finding.triggering_input,
            actual_output=data.get("output", "")[:1000],
            confirmed=confirmed,
            exploit_description=(
                f"Sandbox executed triggering_input against the flagged function. "
                f"{'Exploit ran without error.' if confirmed else 'Exception or empty output — exploit not confirmed.'}"
            ),
            attack_type=finding.vuln_type.value,
        )

    except subprocess.TimeoutExpired:
        return ExploitProof(
            input_used=finding.triggering_input,
            actual_output="",
            confirmed=False,
            exploit_description=f"Sandbox timed out after {TIMEOUT_SECONDS}s",
            attack_type=finding.vuln_type.value,
        )
    except (json.JSONDecodeError, IndexError) as e:
        return ExploitProof(
            input_used=finding.triggering_input,
            actual_output=result.stdout[:500] if "result" in dir() else "",
            confirmed=False,
            exploit_description=f"Could not parse sandbox output: {e}",
            attack_type=finding.vuln_type.value,
        )
    finally:
        os.unlink(tmp_path)