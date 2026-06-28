from __future__ import annotations
import os, hashlib, json
from github import Github, GithubException
from src.models import Finding, Severity

_EMO = {Severity.CRITICAL: "??", Severity.HIGH: "??",
        Severity.MEDIUM: "??", Severity.LOW: "??", Severity.INFO: "?"}
DEDUP = ".ai-reviewer-seen.json"


def _hash(f: Finding, path: str) -> str:
    return hashlib.sha256(
        f"{f.vuln_type.value}:{path}:{f.line_start}".encode()
    ).hexdigest()[:14]


def _load() -> set[str]:
    if os.path.exists(DEDUP):
        try:
            with open(DEDUP) as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def _save(s: set[str]) -> None:
    try:
        with open(DEDUP, "w") as f:
            json.dump(list(s), f)
    except Exception:
        pass


def _fmt(f: Finding) -> str:
    e = _EMO.get(f.severity, "?")
    return (
        f"**{e} {f.severity.value} - {f.vuln_type.value}**\n\n"
        f"{f.description}\n\n"
        f"**Triggering input:** \{f.triggering_input}\\n\n"
        f"**Fix:** {f.fix}\n\n"
        f"<details><summary>Detection details</summary>\n\n"
        f"Confidence: {f.confidence:.0%}  \n"
        f"Verified by dual-LLM cross-model adjudication\n"
        f"</details>"
    )


def post_inline_comments(
    repo_name: str, pr_number: int, commit_sha: str,
    findings_by_file: dict[str, list[Finding]]
) -> bool:
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    seen = _load()
    new: set[str] = set()
    crit = False

    for path, findings in findings_by_file.items():
        for f in findings:
            h = _hash(f, path)
            if h in seen:
                continue
            try:
                pr.create_review_comment(
                    body=_fmt(f),
                    commit=repo.get_commit(commit_sha),
                    path=path,
                    line=f.line_start,
                )
                new.add(h)
            except GithubException as e:
                if e.status == 422:
                    try:
                        pr.create_issue_comment(
                            f"**{f.severity.value}** \{path}:{f.line_start}\\n\n" + _fmt(f)
                        )
                        new.add(h)
                    except Exception:
                        pass
            if f.severity == Severity.CRITICAL:
                crit = True

    seen.update(new)
    _save(seen)
    return crit


def block_merge_if_critical(repo_name: str, pr_number: int, narrative: str = "") -> None:
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    body = (
        "## ?? AI Reviewer - Merge Blocked\n\n"
        "Critical security vulnerabilities found. "
        "Resolve all ?? CRITICAL findings before merging.\n\n"
    )
    if narrative:
        body += f"### Attack Chain Identified\n\n{narrative}\n\n"
    body += "_Emergency override: add label \skip-ai-review\_"
    try:
        pr.create_review(body=body, event="REQUEST_CHANGES")
    except GithubException as e:
        print(f"  [GitHub] Block failed: {e}")
