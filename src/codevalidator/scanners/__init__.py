from __future__ import annotations

from typing import Callable

from ..models import Finding, ScanContext
from . import ci_and_hooks, dangerous_exec, network_exfil, obfuscation, permissions, secrets, supply_chain

ScannerFn = Callable[[ScanContext], list[Finding]]

ALL_SCANNERS: dict[str, ScannerFn] = {
    "secrets": secrets.scan,
    "dangerous-exec": dangerous_exec.scan,
    "network-exfil": network_exfil.scan,
    "obfuscation": obfuscation.scan,
    "supply-chain": supply_chain.scan,
    "ci-hooks": ci_and_hooks.scan,
    "permissions": permissions.scan,
}


def run_all(ctx: ScanContext, only: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for name, fn in ALL_SCANNERS.items():
        if only is not None and name not in only:
            continue
        findings.extend(fn(ctx))
    return findings
