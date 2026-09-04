from __future__ import annotations

import math
from collections import Counter


def line_of(content: str, index: int) -> int:
    """1-indexed line number of a character offset."""
    return content.count("\n", 0, index) + 1


def line_text(content: str, index: int) -> str:
    start = content.rfind("\n", 0, index) + 1
    end = content.find("\n", index)
    if end == -1:
        end = len(content)
    return content[start:end]


def window_end(content: str, start: int, lines_forward: int = 2) -> int:
    """Offset `lines_forward` newlines after `start`, or end-of-content if there aren't that many."""
    pos = start
    for _ in range(lines_forward):
        idx = content.find("\n", pos)
        if idx == -1:
            return len(content)
        pos = idx + 1
    return pos


def truncate(s: str, n: int = 160) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
