from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Ordered so `severity >= Severity.HIGH` comparisons work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    scanner: str  # which scanner/source produced this, e.g. "secrets" or "llm"
    severity: Severity
    category: str  # short slug: "hardcoded-secret", "reverse-shell", "obfuscation", ...
    file: str  # repo-relative path
    summary: str
    line: int | None = None
    evidence: str | None = None  # short snippet, truncated - never the whole file
    confidence: str = "high"  # "high" | "medium" | "low"
    provider: str | None = None  # which LLM provider produced this (scanner == "llm" only)

    def sort_key(self):
        return (-int(self.severity), self.file, self.line or 0)


@dataclass
class ScannedFile:
    path: Path  # absolute path on disk
    rel_path: str  # posix-style path relative to repo root
    content: str | None  # None if binary / unreadable / too large
    size: int
    mode: int  # st_mode bits


@dataclass
class ScanContext:
    repo_root: Path
    files: list[ScannedFile] = field(default_factory=list)

    def by_name(self, *names: str) -> list[ScannedFile]:
        wanted = set(names)
        return [f for f in self.files if Path(f.rel_path).name in wanted]

    def with_suffix(self, *suffixes: str) -> list[ScannedFile]:
        wanted = set(suffixes)
        return [f for f in self.files if Path(f.rel_path).suffix in wanted]


@dataclass
class TokenUsage:
    """Raw token counts as reported by the LLM API - no cost estimate.

    Provider pricing changes over time and varies by account (volume
    discounts, enterprise rates), so a hardcoded $/token conversion here
    would drift out of date or simply be wrong. Report exactly what the API
    told us and let the user check it against their own provider dashboard.
    """

    provider: str
    model: str
    calls: int = 0
    failed_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0  # Anthropic prompt-cache reads, billed at a fraction of input rate

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens
