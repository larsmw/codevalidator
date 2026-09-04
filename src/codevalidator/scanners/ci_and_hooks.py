from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, truncate

_PIPE_TO_SHELL_RE = re.compile(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?)\b")
_SECRET_ECHO_RE = re.compile(r"(?i)\becho\b[^\n]*\$\{?\{?\s*secrets\.")
_HOOK_NAMES = {
    "pre-commit", "pre-push", "post-checkout", "post-merge", "post-commit",
    "prepare-commit-msg", "commit-msg", "pre-rebase", "applypost-checkout",
}


def _scan_workflow(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    if re.search(r"(?m)^\s*pull_request_target\s*:", content):
        checks_out_head = re.search(r"(?i)ref:\s*\$\{\{\s*github\.event\.pull_request\.head", content)
        if checks_out_head:
            idx = checks_out_head.start()
            findings.append(Finding(
                scanner="ci-hooks",
                severity=Severity.CRITICAL,
                category="ci-privilege-escalation",
                file=rel_path,
                line=line_of(content, idx),
                summary="Workflow trigger is `pull_request_target` (runs with base-repo secrets/permissions) "
                        "but checks out the PR head ref - a fork PR can run its own code with your secrets",
                evidence=truncate(checks_out_head.group(0)),
                confidence="high",
            ))

    for m in _PIPE_TO_SHELL_RE.finditer(content):
        findings.append(Finding(
            scanner="ci-hooks",
            severity=Severity.HIGH,
            category="ci-pipe-to-shell",
            file=rel_path,
            line=line_of(content, m.start()),
            summary="CI step downloads a script and pipes it directly into a shell - "
                    "the fetched content isn't reviewed or pinned",
            evidence=truncate(m.group(0)),
            confidence="medium",
        ))

    for m in _SECRET_ECHO_RE.finditer(content):
        findings.append(Finding(
            scanner="ci-hooks",
            severity=Severity.HIGH,
            category="ci-secret-exposure",
            file=rel_path,
            line=line_of(content, m.start()),
            summary="CI step echoes a secret to the log/output",
            evidence=truncate(m.group(0)),
            confidence="medium",
        ))

    for m in re.finditer(r"(?im)^\s*uses:\s*([^\s@]+)@([0-9a-f]{6,40}|\S+)\s*$", content):
        ref = m.group(2)
        if not re.fullmatch(r"[0-9a-f]{40}", ref) and not re.match(r"^v?\d+(\.\d+)*$", ref):
            findings.append(Finding(
                scanner="ci-hooks",
                severity=Severity.LOW,
                category="unpinned-action",
                file=rel_path,
                line=line_of(content, m.start()),
                summary=f"GitHub Action `{m.group(1)}` is referenced by a mutable ref (`{ref}`) rather than "
                        "a pinned commit SHA - the action's code can change underneath you",
                evidence=truncate(m.group(0)),
                confidence="low",
            ))

    return findings


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        parts = f.rel_path.split("/")
        name = parts[-1]
        content = f.content

        if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows" and name.endswith((".yml", ".yaml")):
            findings.extend(_scan_workflow(f.rel_path, content))

        # Native .git/hooks/* are never tracked by git, so the only hook scripts that
        # can actually ship *in* a repo are husky-style ones committed under .husky/.
        is_hook_file = len(parts) >= 2 and parts[0] == ".husky" and name in _HOOK_NAMES
        if is_hook_file:
            for m in _PIPE_TO_SHELL_RE.finditer(content):
                findings.append(Finding(
                    scanner="ci-hooks",
                    severity=Severity.HIGH,
                    category="git-hook-network-exec",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary=f"Git hook `{name}` downloads and executes a remote script - runs automatically "
                            "on every commit/push for anyone who checks out this repo",
                    evidence=truncate(m.group(0)),
                    confidence="medium",
                ))

        if name == ".pre-commit-config.yaml":
            for m in re.finditer(r"(?m)^\s*language:\s*system\s*$", content):
                findings.append(Finding(
                    scanner="ci-hooks",
                    severity=Severity.LOW,
                    category="pre-commit-arbitrary-command",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary="pre-commit hook uses `language: system` - runs an arbitrary local command "
                            "rather than a sandboxed/pinned hook; confirm the entry is trustworthy",
                    evidence=None,
                    confidence="low",
                ))
    return findings
