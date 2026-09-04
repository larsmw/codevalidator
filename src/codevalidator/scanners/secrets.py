from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, truncate

# (name, regex, severity)
_SIGNATURE_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    ("aws-secret-access-key-hint", re.compile(r"\bASIA[0-9A-Z]{16}\b"), Severity.HIGH),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    ("slack-webhook-url", re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]+/[0-9A-Z]+/[0-9A-Za-z]+"), Severity.MEDIUM),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    ("stripe-secret-key", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b"), Severity.HIGH),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b"), Severity.HIGH),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.HIGH),
]

_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(changeme|your[_-]?(api)?[_-]?key|xxxx+|example|placeholder|dummy|"
    r"insert[_-]?here|<[^>]+>|\$\{[^}]+\}|\bfake\b|\btest[_-]?key\b|redacted)\b"
)
_ENV_LOOKUP_RE = re.compile(r"(?i)\b(process\.env|os\.environ|getenv|ENV\[)")

_GENERIC_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret([_-]?key)?|access[_-]?token|auth[_-]?token|
       client[_-]?secret|private[_-]?key|password|passwd)\b
    \s*[:=]\s*
    (?P<q>['"])(?P<val>[A-Za-z0-9_\-/+=]{16,})(?P=q)
    """
)


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        # obvious test/fixture paths carry lower severity - still worth flagging
        is_test_path = any(seg in f.rel_path.lower() for seg in ("test", "fixture", "example", "mock"))

        for name, pattern, severity in _SIGNATURE_PATTERNS:
            for m in pattern.finditer(f.content):
                findings.append(Finding(
                    scanner="secrets",
                    severity=Severity.LOW if (is_test_path and severity < Severity.HIGH) else severity,
                    category="hardcoded-secret",
                    file=f.rel_path,
                    line=line_of(f.content, m.start()),
                    summary=f"Hardcoded credential matching {name} pattern",
                    evidence=truncate(m.group(0)),
                    confidence="high",
                ))

        for m in _GENERIC_ASSIGNMENT_RE.finditer(f.content):
            val = m.group("val")
            window_start = max(0, m.start() - 40)
            window = f.content[window_start:m.start()]
            if _PLACEHOLDER_RE.search(val) or _PLACEHOLDER_RE.search(m.group(0)):
                continue
            if _ENV_LOOKUP_RE.search(window):
                continue
            findings.append(Finding(
                scanner="secrets",
                severity=Severity.LOW if is_test_path else Severity.MEDIUM,
                category="hardcoded-secret",
                file=f.rel_path,
                line=line_of(f.content, m.start()),
                summary="Possible hardcoded credential assigned to a secret-looking variable",
                evidence=truncate(m.group(0)),
                confidence="medium",
            ))
    return findings
