"""Helpers that keep stored originals immutable and paths safe on Windows."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

_INVALID = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def safe_component(name: str | None, fallback: str = "Unknown") -> str:
    """Return a string usable as a single Windows/Linux path component."""
    name = (name or "").strip()
    name = _INVALID.sub("_", name).strip(" .")
    if not name:
        return fallback
    if name.upper().split(".")[0] in _RESERVED:
        name = f"_{name}"
    return name[:100]


def make_read_only(path: Path) -> None:
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def is_read_only(path: Path) -> bool:
    return not (os.stat(path).st_mode & stat.S_IWUSR)


def ensure_within(base: Path, candidate: Path) -> Path:
    """Guard against path traversal: candidate must resolve inside base."""
    base_r = base.resolve()
    cand_r = candidate.resolve()
    if base_r != cand_r and base_r not in cand_r.parents:
        raise ValueError(f"Path {candidate} escapes {base}")
    return cand_r
