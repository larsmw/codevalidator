from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, Severity

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(auth|login|session|token|crypto|secret|password|permission|privilege|admin|"
    r"payment|billing|\.github/workflows|dockerfile|terraform|\.tf$|migrations?/|"
    r"\bci\.ya?ml$|security)"
)

_TEST_DIR_RE = re.compile(r"(?i)(^|/)(tests?|specs?|__tests__)(/|$)")
_TEST_FILE_RE = re.compile(r"(?i)(^test_|_test\.|\.test\.|\.spec\.|_spec\.|Test\.\w+$|Tests\.\w+$)")

_ASSERTION_RE = re.compile(
    r"(?i)\b(assert\w*|expect\(|\.should\b|\.to\.(eq|equal|be)\b|t\.(Error|Fatal|Fail)\b)"
)
_SKIP_MARKER_RE = re.compile(
    r"(?i)(@pytest\.mark\.skip|@unittest\.skip|\bxit\s*\(|\bxdescribe\s*\(|\bskip\s*\(|"
    r"\.skip\s*\(|@Disabled\b|@Ignore\b|t\.Skip\s*\()"
)


def _is_test_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return bool(_TEST_DIR_RE.search(path) or _TEST_FILE_RE.search(name))


@dataclass
class _DiffLine:
    kind: str  # "context" | "add" | "remove"
    text: str  # without the leading +/-/space marker
    old_lineno: int | None
    new_lineno: int | None


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _split_diff_by_file(diff_text: str) -> list[tuple[str | None, list[str]]]:
    sections: list[tuple[str | None, list[str]]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    started = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if started:
                sections.append((current_path, current_lines))
            current_path, current_lines, started = None, [], True
            continue
        if started:
            if line.startswith("+++ "):
                raw = line[4:].strip()
                current_path = raw[2:] if raw.startswith("b/") else None
            current_lines.append(line)
    if started:
        sections.append((current_path, current_lines))
    return sections


def _parse_hunks(lines: list[str]) -> list[_DiffLine]:
    result: list[_DiffLine] = []
    old_ln = new_ln = 0
    for line in lines:
        m = _HUNK_HEADER_RE.match(line)
        if m:
            old_ln, new_ln = int(m.group(1)), int(m.group(2))
            continue
        if line.startswith("---") or line.startswith("+++") or line.startswith("index ") or line.startswith("\\"):
            continue
        if line.startswith("+"):
            result.append(_DiffLine("add", line[1:], None, new_ln))
            new_ln += 1
        elif line.startswith("-"):
            result.append(_DiffLine("remove", line[1:], old_ln, None))
            old_ln += 1
        elif line.startswith(" "):
            result.append(_DiffLine("context", line[1:], old_ln, new_ln))
            old_ln += 1
            new_ln += 1
        # other lines (e.g. "diff --git" leaked through, or blank) - ignore
    return result


def check_test_tampering(diff_text: str) -> list[Finding]:
    """Flag test assertions removed or tests skipped, especially alongside production code
    changes in the same diff - a classic way to hide a behavior change from CI."""
    sections = _split_diff_by_file(diff_text)
    if not sections:
        return []

    touches_non_test = any(
        path is not None and not _is_test_path(path) and any(not l.startswith(("---", "+++", "index")) for l in lines)
        for path, lines in sections
    )
    severity = Severity.HIGH if touches_non_test else Severity.MEDIUM
    context_note = (
        " This diff also touches non-test files, which is the pattern to worry about most - "
        "confirm the weakened test wasn't hiding a real behavior change."
        if touches_non_test else
        " No production code changed in this diff, which lowers (but doesn't eliminate) the concern."
    )

    findings: list[Finding] = []
    for path, lines in sections:
        if path is None or not _is_test_path(path):
            continue
        for dl in _parse_hunks(lines):
            if dl.kind == "remove" and _ASSERTION_RE.search(dl.text):
                findings.append(Finding(
                    scanner="diff-heuristics", severity=severity, category="test-weakened",
                    file=path, line=dl.old_lineno,
                    summary="A test assertion was removed in this diff." + context_note,
                    evidence=dl.text.strip()[:160],
                    confidence="low",
                ))
            elif dl.kind == "add" and _SKIP_MARKER_RE.search(dl.text):
                findings.append(Finding(
                    scanner="diff-heuristics", severity=severity, category="test-skipped",
                    file=path, line=dl.new_lineno,
                    summary="A test was marked skipped/disabled in this diff." + context_note,
                    evidence=dl.text.strip()[:160],
                    confidence="medium",
                ))
    return findings


def _git(repo_root: Path, *args: str, timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args], capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return result.stdout if result.returncode == 0 else None


def _is_range_spec(diff_spec: str) -> bool:
    return ".." in diff_spec


def _diff_authors(repo_root: Path, diff_spec: str) -> tuple[set[str], bool]:
    """Returns (author emails, is_pending) - is_pending means these are uncommitted
    changes attributed to the current git identity, not an actual commit author yet."""
    if _is_range_spec(diff_spec):
        out = _git(repo_root, "log", "--format=%ae", diff_spec)
        if out:
            return {line.strip().lower() for line in out.splitlines() if line.strip()}, False
    email = (_git(repo_root, "config", "user.email") or "").strip().lower()
    return ({email} if email else set()), True


def _file_history_authors(repo_root: Path, path: str) -> set[str]:
    out = _git(repo_root, "log", "--format=%ae", "--", path)
    if not out:
        return set()
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def _commit_count_for_author(repo_root: Path, email: str) -> int:
    out = _git(repo_root, "log", f"--author={email}", "--format=%H")
    return len(out.splitlines()) if out else 0


def check_author_anomaly(repo_root: Path, diff_spec: str) -> list[Finding]:
    """Flag sensitive-path files touched by an author who has never touched that file
    before. Cheap, deterministic, and a strong prior: a first-time editor of your auth
    or CI config is worth a closer look, regardless of what the diff itself contains.

    This is inherently approximate - for a commit-range spec, "history" is read from
    the currently checked-out state, which may or may not exclude the range's own
    commits depending on how the branches relate. Treat it as a heuristic, not proof.
    """
    touched_out = _git(repo_root, "diff", "--name-only", diff_spec)
    if not touched_out:
        return []
    touched = [p for p in touched_out.splitlines() if p.strip()]
    sensitive = [p for p in touched if _SENSITIVE_PATH_RE.search(p)]
    if not sensitive:
        return []

    diff_authors, is_pending = _diff_authors(repo_root, diff_spec)
    if not diff_authors:
        return []

    findings: list[Finding] = []
    for path in sensitive:
        history = _file_history_authors(repo_root, path)
        if not history:
            continue  # brand new file - nothing to compare against, not this check's concern
        unfamiliar = diff_authors - history
        if not unfamiliar:
            continue
        author = next(iter(unfamiliar))
        commit_count = _commit_count_for_author(repo_root, author)
        pending_note = " (uncommitted change - attributed to your current git identity)" if is_pending else ""
        experience_note = (
            f" This author has {commit_count} commit(s) in this repo overall."
            if commit_count else
            " This author has no other commits in this repo's visible history."
        )
        findings.append(Finding(
            scanner="diff-heuristics", severity=Severity.MEDIUM, category="unfamiliar-author-sensitive-path",
            file=path, line=None,
            summary=f"{author} has never touched this security-sensitive file before in the visible "
                    f"git history{pending_note}.{experience_note} Not inherently wrong (new team members "
                    "touch security code too) but worth a second reviewer's eyes.",
            confidence="low",
        ))
    return findings
