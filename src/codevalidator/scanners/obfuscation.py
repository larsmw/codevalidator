from __future__ import annotations

import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, shannon_entropy, truncate

# Unicode bidirectional control characters (LRE, RLE, PDF, LRO, RLO, LRI, RLI,
# FSI, PDI). Source code should essentially never contain these - their sole
# practical use in a source file is the "Trojan Source" attack (CVE-2021-42574):
# making code *display* differently than it *executes* to a reviewer.
# Built from code points rather than pasted literally - the raw characters are
# invisible or reorder surrounding text in most editors and terminals, which
# would be self-defeating to embed in the file that detects them.
_BIDI_CODEPOINTS = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
_BIDI_CONTROL_RE = re.compile("[" + "".join(chr(c) for c in _BIDI_CODEPOINTS) + "]")

# Zero-width / invisible characters that can hide content from a casual reading
# or be used for identifier smuggling (two visually-identical identifiers that
# differ only in an invisible character). Same rationale for building from
# code points instead of embedding the raw characters.
_ZERO_WIDTH_CODEPOINTS = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
_ZERO_WIDTH_RE = re.compile("[" + "".join(chr(c) for c in _ZERO_WIDTH_CODEPOINTS) + "]")

# Dean Edwards-style JS packer - a very common malware/obfuscation signature.
_JS_PACKER_RE = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d?\s*\)")

_LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock",
}

_LONG_TOKEN_RE = re.compile(r"""(?P<q>['"`])(?P<val>[A-Za-z0-9+/=_-]{60,})(?P=q)""")
_HASH_CONTEXT_RE = re.compile(r"(?i)(sha\d*|integrity|checksum|hash|digest|signature)")

_ENTROPY_THRESHOLD = 4.6


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        content = f.content
        name = f.rel_path.rsplit("/", 1)[-1]
        is_lockfile_or_min = name in _LOCKFILE_NAMES or name.endswith((".min.js", ".map"))

        for m in _BIDI_CONTROL_RE.finditer(content):
            findings.append(Finding(
                scanner="obfuscation",
                severity=Severity.CRITICAL,
                category="trojan-source",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary=f"Unicode bidirectional control character U+{ord(m.group(0)):04X} found in source - "
                        "can make code display differently than it executes (Trojan Source / CVE-2021-42574)",
                evidence=f"codepoint U+{ord(m.group(0)):04X}",
                confidence="high",
            ))

        for m in _ZERO_WIDTH_RE.finditer(content):
            if m.start() == 0 and ord(m.group(0)) == 0xFEFF:
                continue  # legitimate BOM at file start
            findings.append(Finding(
                scanner="obfuscation",
                severity=Severity.HIGH,
                category="hidden-characters",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary=f"Zero-width/invisible character U+{ord(m.group(0)):04X} found in source - "
                        "can hide content or make two identifiers look identical",
                evidence=f"codepoint U+{ord(m.group(0)):04X}",
                confidence="high",
            ))

        for m in _JS_PACKER_RE.finditer(content):
            findings.append(Finding(
                scanner="obfuscation",
                severity=Severity.HIGH,
                category="obfuscated-code",
                file=f.rel_path,
                line=line_of(content, m.start()),
                summary="JavaScript packer signature (eval(function(p,a,c,k,e,d))) - a common obfuscation/"
                        "malware pattern; legitimate code rarely ships pre-obfuscated",
                evidence=truncate(m.group(0)),
                confidence="medium",
            ))

        if is_lockfile_or_min:
            continue
        for m in _LONG_TOKEN_RE.finditer(content):
            context = content[max(0, m.start() - 60):m.start()]
            if _HASH_CONTEXT_RE.search(context):
                continue
            entropy = shannon_entropy(m.group("val"))
            if entropy >= _ENTROPY_THRESHOLD:
                findings.append(Finding(
                    scanner="obfuscation",
                    severity=Severity.LOW,
                    category="high-entropy-blob",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary=f"High-entropy string literal ({entropy:.1f} bits/char, {len(m.group('val'))} chars) - "
                            "could be an encoded payload, or could be a legitimate key/token/asset",
                    evidence=truncate(m.group("val"), 80),
                    confidence="low",
                ))
    return findings
