"""Ghidra headless integration.

Runs ``analyzeHeadless`` on ONE binary chosen by the operator (normally an ELF
extracted into the workspace), with a throw-away project in the workspace, and
collects a JSON summary written by ``scripts/TVISSummary.java``.

Command (documented Ghidra headless syntax)::

    analyzeHeadless <project_dir> <project_name> -import <file>
        -scriptPath <scripts> -postScript TVISSummary.java <out.json>
        -deleteProject -analysisTimeoutPerFile <seconds> [-processor <languageID>]

Ghidra is never run on the original firmware file and nothing is written back.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


@dataclass
class GhidraResult:
    command: list[str]
    summary: dict | None
    log_tail: str
    returncode: int


def find_headless(configured: str | None = None) -> str | None:
    candidates = []
    if configured:
        candidates.append(configured)
    home = os.environ.get("GHIDRA_INSTALL_DIR")
    if home:
        candidates += [str(Path(home) / "support" / "analyzeHeadless.bat"),
                       str(Path(home) / "support" / "analyzeHeadless")]
    candidates += ["analyzeHeadless", "analyzeHeadless.bat"]
    for c in candidates:
        if Path(c).is_file():
            return c
        w = shutil.which(c)
        if w:
            return w
    return None


def build_command(headless: str, binary: Path, project_dir: Path, out_json: Path, timeout_s: int,
                  processor: str | None = None, scripts_dir: Path = SCRIPTS_DIR) -> list[str]:
    cmd = [headless, str(project_dir), "tvis_tmp", "-import", str(binary), "-scriptPath", str(scripts_dir),
           "-postScript", "TVISSummary.java", str(out_json), "-deleteProject",
           "-analysisTimeoutPerFile", str(timeout_s)]
    if processor:
        cmd += ["-processor", processor]
    return cmd


def analyze(headless: str, binary: str | Path, workspace: Path, timeout_s: int = 600,
            processor: str | None = None) -> GhidraResult:
    binary = Path(binary).resolve()
    workspace = Path(workspace).resolve()
    if workspace not in binary.parents:
        raise ValueError("Ghidra may only be run on files inside the analysis workspace")
    proj = workspace / "ghidra_project"
    if proj.exists():
        shutil.rmtree(proj, ignore_errors=True)
    proj.mkdir(parents=True)
    out_json = workspace / f"ghidra_{binary.name}.json"
    out_json.unlink(missing_ok=True)
    cmd = build_command(headless, binary, proj, out_json, timeout_s, processor)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 300, stdin=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Ghidra timed out after {timeout_s + 300} s") from exc
    summary = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else None
    shutil.rmtree(proj, ignore_errors=True)
    return GhidraResult(cmd, summary, (p.stdout + p.stderr)[-6000:], p.returncode)
