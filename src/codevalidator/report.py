from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .models import Finding, Severity, TokenUsage

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;41m",  # bold, red bg
    Severity.HIGH: "\033[1;31m",      # bold red
    Severity.MEDIUM: "\033[33m",      # yellow
    Severity.LOW: "\033[36m",         # cyan
    Severity.INFO: "\033[2m",         # dim
}
_RESET = "\033[0m"


def dedupe_and_sort(findings: list[Finding]) -> list[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.scanner, f.category, f.file, f.line, f.summary)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: f.sort_key())
    return unique


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s.name.lower(): 0 for s in Severity}
    for f in findings:
        counts[f.severity.name.lower()] += 1
    return counts


def highest_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max(f.severity for f in findings)


def _usage_text_line(usage: TokenUsage | None) -> str | None:
    if usage is None or usage.calls == 0 and usage.failed_calls == 0:
        return None
    bits = [
        f"{usage.calls} call(s)",
        f"{usage.input_tokens:,} input tokens",
        f"{usage.output_tokens:,} output tokens",
        f"{usage.total_tokens:,} total",
    ]
    if usage.cached_input_tokens:
        bits.append(f"{usage.cached_input_tokens:,} cached (billed at a fraction of input rate)")
    if usage.failed_calls:
        bits.append(f"{usage.failed_calls} failed call(s) not counted")
    return f"LLM usage ({usage.provider}/{usage.model}): " + ", ".join(bits) + \
        " - check your provider's dashboard for actual cost, this tool doesn't estimate $."


def render_text(findings: list[Finding], repo_root: str, use_color: bool | None = None, usage: TokenUsage | None = None) -> str:
    if use_color is None:
        use_color = sys.stdout.isatty()

    lines = [f"codevalidator report - {repo_root}", ""]
    counts = summarize(findings)
    summary_bits = [f"{counts[s.name.lower()]} {s.name.lower()}" for s in reversed(list(Severity))]
    lines.append("summary: " + ", ".join(summary_bits))
    usage_line = _usage_text_line(usage)
    if usage_line:
        lines.append(usage_line)
    lines.append("")

    if not findings:
        lines.append("No findings. (A clean scan is evidence, not proof - nothing here catches everything.)")
        return "\n".join(lines)

    for f in findings:
        color = _SEVERITY_COLOR[f.severity] if use_color else ""
        reset = _RESET if use_color else ""
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"{color}[{f.severity.name}]{reset} {loc}  ({f.scanner}/{f.category}, confidence={f.confidence})")
        lines.append(f"  {f.summary}")
        if f.evidence:
            lines.append(f"  > {f.evidence}")
        lines.append("")

    return "\n".join(lines)


def render_json(findings: list[Finding], repo_root: str, usage: TokenUsage | None = None) -> str:
    llm_usage = None
    if usage is not None and (usage.calls or usage.failed_calls):
        llm_usage = {**asdict(usage), "total_tokens": usage.total_tokens,
                     "note": "raw token counts as reported by the API; no cost estimate - "
                             "check your provider's dashboard for pricing"}
    payload = {
        "repo_root": repo_root,
        "summary": summarize(findings),
        "llm_usage": llm_usage,
        "findings": [
            {**asdict(f), "severity": f.severity.name.lower()} for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(findings: list[Finding], repo_root: str, usage: TokenUsage | None = None) -> str:
    counts = summarize(findings)
    lines = [f"# codevalidator report - `{repo_root}`", ""]
    lines.append("| severity | count |")
    lines.append("|---|---|")
    for s in reversed(list(Severity)):
        lines.append(f"| {s.name.lower()} | {counts[s.name.lower()]} |")
    lines.append("")
    usage_line = _usage_text_line(usage)
    if usage_line:
        lines.append(f"_{usage_line}_")
        lines.append("")

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    for f in findings:
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        lines.append(f"### [{f.severity.name}] {loc}")
        lines.append(f"- **category**: {f.scanner}/{f.category}")
        lines.append(f"- **confidence**: {f.confidence}")
        lines.append(f"- {f.summary}")
        if f.evidence:
            lines.append(f"  ```\n  {f.evidence}\n  ```")
        lines.append("")
    return "\n".join(lines)
