from __future__ import annotations

import json
import re

from ..models import Finding, ScanContext, Severity
from .common import line_of, truncate

_INSTALL_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"}
_SUSPICIOUS_SCRIPT_RE = re.compile(
    r"(?i)(\b(curl|wget)\s+\S+.*(\||>|&&).*)|(\bnode\s+-e\s)|(\bbash\s+-c\s)|(base64\s+(-d|--decode))"
)

_GIT_DEP_RE = re.compile(r"(?i)git\+(?:https?|ssh)://[^\s\"',]+")
_INSECURE_GIT_RE = re.compile(r"git\+http://[^\s\"',]+")
_DIRECT_URL_PY_DEP_RE = re.compile(r"(?im)^[\w.-]+\s*@\s*https?://\S+")


def _scan_package_json(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings
    if not isinstance(data, dict):
        return findings

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key, cmd in scripts.items():
            if key not in _INSTALL_SCRIPT_KEYS or not isinstance(cmd, str):
                continue
            idx = content.find(cmd)
            line = line_of(content, idx) if idx != -1 else None
            severity = Severity.HIGH if _SUSPICIOUS_SCRIPT_RE.search(cmd) else Severity.LOW
            findings.append(Finding(
                scanner="supply-chain",
                severity=severity,
                category="install-time-script",
                file=rel_path,
                line=line,
                summary=f"package.json runs a script on `{key}` (executes automatically on `npm install`)"
                        + (" and looks like it downloads/executes external content" if severity >= Severity.HIGH else ""),
                evidence=truncate(cmd),
                confidence="medium" if severity >= Severity.HIGH else "low",
            ))

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for dep_name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if spec.startswith("git+http://") or spec.startswith("git://"):
                idx = content.find(spec)
                findings.append(Finding(
                    scanner="supply-chain",
                    severity=Severity.MEDIUM,
                    category="insecure-dependency-source",
                    file=rel_path,
                    line=line_of(content, idx) if idx != -1 else None,
                    summary=f"Dependency `{dep_name}` is fetched over an unauthenticated/unencrypted "
                            f"transport ({spec}) - vulnerable to tampering in transit",
                    evidence=truncate(spec),
                    confidence="high",
                ))
    return findings


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        if f.content is None:
            continue
        name = f.rel_path.rsplit("/", 1)[-1]
        content = f.content

        if name == "package.json":
            findings.extend(_scan_package_json(f.rel_path, content))

        if name in ("requirements.txt", "requirements-dev.txt") or name.endswith(".txt") and "requirement" in name.lower():
            for m in _INSECURE_GIT_RE.finditer(content):
                findings.append(Finding(
                    scanner="supply-chain",
                    severity=Severity.MEDIUM,
                    category="insecure-dependency-source",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary="Python dependency fetched via unencrypted git+http:// - vulnerable to tampering",
                    evidence=truncate(m.group(0)),
                    confidence="high",
                ))
            for m in _DIRECT_URL_PY_DEP_RE.finditer(content):
                findings.append(Finding(
                    scanner="supply-chain",
                    severity=Severity.LOW,
                    category="direct-url-dependency",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary="Dependency installed from a direct URL rather than a package index - "
                            "confirm the source is trusted and pinned to a specific commit/hash",
                    evidence=truncate(m.group(0)),
                    confidence="low",
                ))

        if name in ("Cargo.toml",):
            if "[patch" in content and re.search(r"(?i)git\s*=", content):
                idx = content.find("[patch")
                findings.append(Finding(
                    scanner="supply-chain",
                    severity=Severity.MEDIUM,
                    category="dependency-source-override",
                    file=f.rel_path,
                    line=line_of(content, idx),
                    summary="Cargo [patch] section overrides a dependency with a git source - "
                            "confirm this isn't silently swapping in an untrusted fork",
                    evidence=None,
                    confidence="low",
                ))

        if name == "go.mod":
            for m in re.finditer(r"(?m)^replace\s+(\S+)\s*=>\s*(\S+)", content):
                findings.append(Finding(
                    scanner="supply-chain",
                    severity=Severity.LOW,
                    category="dependency-source-override",
                    file=f.rel_path,
                    line=line_of(content, m.start()),
                    summary=f"go.mod replaces `{m.group(1)}` with `{m.group(2)}` - confirm the replacement "
                            "is intentional and trusted",
                    evidence=truncate(m.group(0)),
                    confidence="low",
                ))
    return findings
