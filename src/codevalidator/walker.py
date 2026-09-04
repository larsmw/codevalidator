from __future__ import annotations

import subprocess
from pathlib import Path

from .models import ScannedFile

DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", "vendor", ".tox", ".mypy_cache",
    ".pytest_cache", ".next", ".nuxt", "coverage", ".idea", ".vscode",
    "egg-info",
}

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip anything bigger; not source code we can usefully review


def _is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


def _git_tracked_files(root: Path) -> list[str] | None:
    """Ask git for tracked + untracked-but-not-ignored files. Returns None on any failure."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return [line for line in result.stdout.splitlines() if line]


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def _read_file(path: Path) -> tuple[str | None, int]:
    try:
        size = path.stat().st_size
    except OSError:
        return None, 0
    if size == 0 or size > MAX_FILE_BYTES:
        return None, size
    try:
        raw = path.read_bytes()
    except OSError:
        return None, size
    if _looks_binary(raw[:8192]):
        return None, size
    try:
        return raw.decode("utf-8"), size
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), size


def collect_files(repo_root: Path, extra_excludes: list[str] | None = None) -> list[ScannedFile]:
    repo_root = repo_root.resolve()
    extra_excludes = set(extra_excludes or [])

    rel_paths: list[str]
    tracked = _git_tracked_files(repo_root) if _is_git_repo(repo_root) else None
    if tracked is not None:
        rel_paths = tracked
    else:
        rel_paths = []
        for path in repo_root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in DEFAULT_EXCLUDE_DIRS for part in path.relative_to(repo_root).parts):
                continue
            rel_paths.append(path.relative_to(repo_root).as_posix())

    files: list[ScannedFile] = []
    for rel in rel_paths:
        parts = Path(rel).parts
        if any(part in DEFAULT_EXCLUDE_DIRS for part in parts):
            continue
        if any(rel == pat or Path(rel).match(pat) for pat in extra_excludes):
            continue
        abs_path = repo_root / rel
        if not abs_path.is_file():
            continue
        try:
            mode = abs_path.lstat().st_mode
        except OSError:
            continue
        content, size = _read_file(abs_path)
        files.append(ScannedFile(path=abs_path, rel_path=rel, content=content, size=size, mode=mode))
    return files
