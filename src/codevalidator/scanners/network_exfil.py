from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, line_text, truncate

_SUSPICIOUS_HOSTS_RE = re.compile(
    r"(?i)\b((raw\.)?pastebin\.com|hastebin\.com|transfer\.sh|requestbin\.\S+|"
    r"webhook\.site|ngrok(-free)?\.(io|app)|discord(app)?\.com/api/webhooks|"
    r"api\.telegram\.org/bot)\b"
)

# Bare dotted-quad IPs are a genuinely useful signal (hardcoded C2 hosts) but a
# freestanding "\d{1,3}(\.\d{1,3}){3}" regex also matches RFC/spec section numbers,
# semver-ish identifiers, and other prose that happens to look like an IP. An
# octet-range-valid IP is still required, plus the surrounding line must not read
# like a document reference.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_RAW_IP_RE = re.compile(rf"\b(?:{_OCTET}\.){{3}}{_OCTET}(?::\d{{2,5}})?\b")
_DOC_REFERENCE_RE = re.compile(r"(?i)\b(rfc|section|clause|chapter|appendix|iso|ieee|cve|figure|table)\b|§")

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.ssh/id_(rsa|ed25519|ecdsa)|\.aws/credentials|\.netrc|"
    r"/etc/(passwd|shadow)|\.env\b|process\.env\b|os\.environ\b|"
    r"Login Data|Cookies['\"]?\)|keychain|\.gnupg/)"
)

_NETWORK_CALL_RE = re.compile(
    r"(?i)\b(requests\.(get|post|put)|urllib\.request\.urlopen|fetch\(|axios\.\w+\(|"
    r"http\.request|https\.request|socket\.socket\(|curl\s|Invoke-WebRequest|"
    r"XMLHttpRequest|WebClient\(\)\.(Upload|Download))\b"
)

# a window of this many chars around a sensitive-path match is searched for a nearby network call
_WINDOW = 400


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        content = f.content

        for m in _SUSPICIOUS_HOSTS_RE.finditer(content):
            findings.append(Finding(
                scanner="network-exfil",
                severity=Severity.MEDIUM,
                category="suspicious-network-endpoint",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary=f"Reference to a host commonly used for data exfiltration or C2: {m.group(0)!r}",
                evidence=truncate(line_text(content, m.start())),
                confidence="low",
            ))

        for m in _RAW_IP_RE.finditer(content):
            line = line_text(content, m.start())
            if _DOC_REFERENCE_RE.search(line):
                continue  # looks like an RFC/spec/version reference, not a network endpoint
            findings.append(Finding(
                scanner="network-exfil",
                severity=Severity.LOW,
                category="hardcoded-ip",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary=f"Hardcoded IP address {m.group(0)!r} - confirm it's not an unexplained C2/exfil endpoint",
                evidence=truncate(line),
                confidence="low",
            ))

        for m in _SENSITIVE_PATH_RE.finditer(content):
            start = max(0, m.start() - _WINDOW)
            end = min(len(content), m.end() + _WINDOW)
            window = content[start:end]
            net_match = _NETWORK_CALL_RE.search(window)
            if net_match:
                findings.append(Finding(
                    scanner="network-exfil",
                    severity=Severity.CRITICAL,
                    category="credential-exfiltration",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary=f"Sensitive path/credential ({m.group(0)!r}) is read near a network call "
                             f"({net_match.group(0)!r}) - possible exfiltration",
                    evidence=truncate(line_text(content, m.start())),
                    confidence="medium",
                ))
    return findings
