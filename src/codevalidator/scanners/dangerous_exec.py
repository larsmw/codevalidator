from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, line_text, truncate, window_end

# Dynamic-code-execution sinks, by rough severity. These are common in legitimate
# metaprogramming too - the point isn't "never use eval", it's "surface every use
# so a human confirms none of them were slipped in by something other than intent".
_SINKS = [
    (re.compile(r"\beval\s*\("), "eval", Severity.MEDIUM),
    (re.compile(r"\bexec\s*\("), "exec", Severity.MEDIUM),
    (re.compile(r"(?<![-\w])new\s+Function\s*\("), "new-function", Severity.MEDIUM),
    (re.compile(r"\bos\.system\s*\("), "os.system", Severity.MEDIUM),
    (re.compile(r"\bos\.popen\s*\("), "os.popen", Severity.MEDIUM),
    (re.compile(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True"), "subprocess-shell-true", Severity.MEDIUM),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle.load(s)", Severity.MEDIUM),
    (re.compile(r"\bmarshal\.loads?\s*\("), "marshal.load(s)", Severity.MEDIUM),
    (re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.Safe)"), "yaml.load-unsafe", Severity.MEDIUM),
    (re.compile(r"__import__\s*\("), "dynamic-import", Severity.LOW),
    (re.compile(r"\bcompile\s*\([^)]*['\"]exec['\"]"), "compile-exec", Severity.MEDIUM),
    (re.compile(r"child_process\.\s*(exec|execSync)\s*\("), "child_process.exec", Severity.MEDIUM),
    (re.compile(r"\bvm\.(runInNewContext|runInThisContext)\s*\("), "vm.runIn*Context", Severity.MEDIUM),
    (re.compile(r"\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"), "php-assert-user-input", Severity.CRITICAL),
    (re.compile(r"\b(system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"), "php-shell-user-input", Severity.CRITICAL),
    (re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"), "curl-pipe-shell", Severity.HIGH),
    (re.compile(r"wget\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"), "wget-pipe-shell", Severity.HIGH),
]

_DECODE_FUNCS = re.compile(
    r"(?i)\b(atob|b64decode|base64\.b64decode|Buffer\.from\([^)]*['\"]base64['\"]\)|"
    r"base64_decode|fromhex|codecs\.decode\([^)]*hex)\b"
)
_EXEC_FUNCS = re.compile(r"(?i)\b(eval|exec|new\s+Function|system|popen|Invoke-Expression|iex)\b")

# reverse-shell-shaped code: dup2 onto a socket fd + spawn a shell
_REVERSE_SHELL_RE = re.compile(
    r"(?is)socket\.socket\([^)]*\).{0,300}?dup2\(.{0,200}?(subprocess\.call|os\.execve|/bin/(sh|bash))"
)
_NC_REVERSE_SHELL_RE = re.compile(r"\bnc\s+.*-e\s*/bin/(sh|bash)\b")


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        content = f.content

        for pattern, name, severity in _SINKS:
            for m in pattern.finditer(content):
                findings.append(Finding(
                    scanner="dangerous-exec",
                    severity=severity,
                    category="dynamic-code-execution",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary=f"Use of {name} - confirm the input isn't attacker- or network-controlled",
                    evidence=truncate(line_text(content, m.start())),
                    confidence="medium",
                ))

        # decode -> exec chain within the same line or the next line: classic
        # "hidden payload" backdoor shape (e.g. exec(base64.b64decode(...)))
        for m in _DECODE_FUNCS.finditer(content):
            nearby_end = window_end(content, m.end(), lines_forward=2)
            nearby = content[max(0, m.start() - 200):nearby_end]
            if _EXEC_FUNCS.search(nearby):
                findings.append(Finding(
                    scanner="dangerous-exec",
                    severity=Severity.CRITICAL,
                    category="obfuscated-payload-execution",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary="Decoded data (base64/hex) appears to feed directly into code execution - "
                             "a classic hidden-payload backdoor shape",
                    evidence=truncate(line_text(content, m.start())),
                    confidence="high",
                ))

        for m in _REVERSE_SHELL_RE.finditer(content):
            findings.append(Finding(
                scanner="dangerous-exec",
                severity=Severity.CRITICAL,
                category="reverse-shell",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary="Code shape matches a raw-socket reverse shell (socket + dup2 + shell exec)",
                evidence=truncate(line_text(content, m.start())),
                confidence="medium",
            ))
        for m in _NC_REVERSE_SHELL_RE.finditer(content):
            findings.append(Finding(
                scanner="dangerous-exec",
                severity=Severity.CRITICAL,
                category="reverse-shell",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary="netcat reverse-shell invocation (`nc ... -e /bin/sh`)",
                evidence=truncate(line_text(content, m.start())),
                confidence="high",
            ))
    return findings
