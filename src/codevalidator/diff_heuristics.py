from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity

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
