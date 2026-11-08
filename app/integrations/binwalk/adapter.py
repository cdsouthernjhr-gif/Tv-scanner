"""Binwalk integration (optional, second opinion to the native scanner).

Supported:
* Binwalk v2.x (Python) — text table output is parsed.
* Binwalk v3.x (Rust)  — ``--log <file.json>`` JSON output is parsed.
* On Windows, Binwalk inside WSL2 (``wsl binwalk ...``) with automatic path
  translation ``C:\\x\\y`` → ``/mnt/c/x/y``.

Binwalk is only ever run on the analysis *working copy*, never with ``-e``
(extraction is done by the application's safe extractor).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

_ROW = re.compile(r"^(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$")


@dataclass
class BinwalkHit:
    offset: int
    description: str
    size: int | None = None


@dataclass
class BinwalkResult:
    version: str
    command: list[str]
    hits: list[BinwalkHit]
    raw: str


def to_wsl_path(p: str | Path) -> str:
    w = PureWindowsPath(str(p))
    if not w.drive:
        return str(p).replace("\\", "/")
    return f"/mnt/{w.drive[0].lower()}/" + "/".join(w.parts[1:])


def find_binwalk(configured: str | None = None) -> list[str] | None:
    """Command prefix to invoke binwalk, or None."""
    if configured:
        if configured.lower() == "wsl":
            return ["wsl", "binwalk"] if shutil.which("wsl") else None
        return [configured] if Path(configured).exists() or shutil.which(configured) else None
    exe = shutil.which("binwalk") or shutil.which("binwalk.exe")
    if exe:
        return [exe]
    if os.name == "nt" and shutil.which("wsl"):
        try:
            r = subprocess.run(["wsl", "which", "binwalk"], capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                return ["wsl", "binwalk"]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def version(prefix: list[str]) -> str:
    try:
        r = _run(prefix + ["--help"], 30)
        m = re.search(r"Binwalk v?(\d+\.\d+(?:\.\d+)?)", r.stdout + r.stderr)
        if m:
            return m.group(1)
        r = _run(prefix + ["--version"], 30)
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", r.stdout + r.stderr)
        return m.group(1) if m else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def parse_v2(text: str) -> list[BinwalkHit]:
    hits = []
    for line in text.splitlines():
        m = _ROW.match(line.strip())
        if m:
            hits.append(BinwalkHit(int(m.group(1)), m.group(2).strip()))
    return hits


def parse_v3(data) -> list[BinwalkHit]:
    """v3 log: list of {"Analysis": {"file_map": [{"offset","size","description",...}]}} (tolerant)."""
    hits = []
    items = data if isinstance(data, list) else [data]
    for it in items:
        fmap = (it.get("Analysis") or it.get("analysis") or {}).get("file_map") or it.get("file_map") or []
        for e in fmap:
            hits.append(BinwalkHit(int(e.get("offset", 0)), str(e.get("description") or e.get("name")),
                                   e.get("size")))
    return hits


def scan(path: str | Path, prefix: list[str], timeout: int = 900) -> BinwalkResult:
    ver = version(prefix)
    target = to_wsl_path(path) if prefix[0] == "wsl" else str(path)
    if ver.startswith("3"):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "bw.json"
            cmd = prefix + ["--log", to_wsl_path(log) if prefix[0] == "wsl" else str(log), target]
            r = _run(cmd, timeout)
            data = json.loads(log.read_text(encoding="utf-8")) if log.exists() else []
            return BinwalkResult(ver, cmd, parse_v3(data), (r.stdout + r.stderr)[-20000:])
    cmd = prefix + [target]
    r = _run(cmd, timeout)
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(f"binwalk failed: {r.stderr.strip()[-500:]}")
    return BinwalkResult(ver, cmd, parse_v2(r.stdout), r.stdout[-20000:])
