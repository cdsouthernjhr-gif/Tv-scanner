"""Detection of optional external tools (Binwalk, 7-Zip, Ghidra, HxD, Tesseract, WSL).

Nothing is installed automatically; the app reports what is available so later
phases can enable/disable features honestly.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig

_CANDIDATES = {
    "binwalk": ["binwalk", "binwalk.exe"],
    "seven_zip": ["7z", "7z.exe", r"C:\Program Files\7-Zip\7z.exe"],
    "ghidra_headless": ["analyzeHeadless", "analyzeHeadless.bat"],
    "hxd": ["HxD.exe", r"C:\Program Files\HxD\HxD.exe"],
    "tesseract": ["tesseract", "tesseract.exe", r"C:\Program Files\Tesseract-OCR\tesseract.exe"],
    "wsl": ["wsl.exe"],
}
LABELS = {"binwalk": "Binwalk", "seven_zip": "7-Zip", "ghidra_headless": "Ghidra (headless)",
          "hxd": "HxD hex editor", "tesseract": "Tesseract OCR", "wsl": "WSL2"}


@dataclass
class ToolStatus:
    key: str
    label: str
    path: str | None

    @property
    def available(self) -> bool:
        return self.path is not None


def _resolve(candidate: str) -> str | None:
    if os.path.isabs(candidate):
        return candidate if Path(candidate).is_file() else None
    return shutil.which(candidate)


def detect_tools(config: AppConfig) -> list[ToolStatus]:
    out = []
    for key, candidates in _CANDIDATES.items():
        configured = config.get(f"tools.{key}")
        found = None
        for c in ([configured] if configured else []) + candidates:
            found = _resolve(c)
            if found:
                break
        out.append(ToolStatus(key, LABELS[key], found))
    return out
