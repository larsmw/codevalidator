from __future__ import annotations

import stat

from ..models import Finding, ScanContext, Severity

_EXPECTED_EXECUTABLE_SUFFIXES = {
    ".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".exe", ".bin", ".out", ".app",
}
_EXPECTED_EXECUTABLE_NAMES = {"configure", "gradlew", "mvnw"}


def scan(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in ctx.files:
        mode = f.mode

        if mode & stat.S_ISUID:
            findings.append(Finding(
                scanner="permissions",
                severity=Severity.HIGH,
                category="setuid-bit",
                file=f.rel_path,
                summary="File has the setuid bit set - runs with the file owner's privileges regardless "
                        "of who executes it",
                confidence="high",
            ))
        if mode & stat.S_ISGID and not stat.S_ISDIR(mode):
            findings.append(Finding(
                scanner="permissions",
                severity=Severity.MEDIUM,
                category="setgid-bit",
                file=f.rel_path,
                summary="File has the setgid bit set",
                confidence="high",
            ))
        if mode & stat.S_IWOTH:
            findings.append(Finding(
                scanner="permissions",
                severity=Severity.MEDIUM,
                category="world-writable-file",
                file=f.rel_path,
                summary="File is world-writable - any local user could modify it",
                confidence="high",
            ))

        is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if is_executable:
            from pathlib import Path
            p = Path(f.rel_path)
            if p.suffix.lower() not in _EXPECTED_EXECUTABLE_SUFFIXES and p.name not in _EXPECTED_EXECUTABLE_NAMES:
                # a shebang makes an extension-less executable unsurprising
                has_shebang = f.content is not None and f.content.startswith("#!")
                if not has_shebang:
                    findings.append(Finding(
                        scanner="permissions",
                        severity=Severity.LOW,
                        category="unexpected-executable",
                        file=f.rel_path,
                        summary=f"File `{p.name}` is marked executable but doesn't look like a script "
                                "(no recognized extension, no shebang) - worth a second look",
                        confidence="low",
                    ))
    return findings
