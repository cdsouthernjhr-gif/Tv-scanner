"""Application configuration and filesystem layout.

Resolution order for the data directory:
1. ``TVIS_DATA_DIR`` environment variable (used by tests and portable installs).
2. ``%LOCALAPPDATA%\\TVIntelligenceScanner`` on Windows.
3. ``~/.tv_intelligence_scanner`` on other platforms (development only).

User settings live in ``<data_dir>/settings.json`` and are merged over
``config/default_config.json`` shipped with the application.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_NAME = "TV Intelligence Scanner"
APP_ID = "TVIntelligenceScanner"
APP_VERSION = "1.0.0"


def application_root() -> Path:
    """Directory holding bundled resources (works for source and PyInstaller builds)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[2]


def default_data_dir() -> Path:
    env = os.environ.get("TVIS_DATA_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_ID
    return Path.home() / ".tv_intelligence_scanner"


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class AppConfig:
    data_dir: Path
    values: dict[str, Any] = field(default_factory=dict)

    # ---- derived paths -------------------------------------------------
    @property
    def database_path(self) -> Path:
        return self.data_dir / "database" / "tv_intelligence.sqlite3"

    @property
    def firmware_library_dir(self) -> Path:
        custom = self.values.get("paths", {}).get("firmware_library")
        return Path(custom) if custom else self.data_dir / "TV_Firmware_Library"

    @property
    def projects_dir(self) -> Path:
        return self.data_dir / "storage" / "projects"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "storage" / "reports"

    @property
    def workspace_dir(self) -> Path:
        """Isolated working copies for analysis (never the originals)."""
        return self.data_dir / "storage" / "workspace"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def settings_path(self) -> Path:
        return self.data_dir / "settings.json"

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.values
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.values
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def ensure_directories(self) -> None:
        for p in (self.data_dir, self.database_path.parent, self.firmware_library_dir,
                  self.projects_dir, self.reports_dir, self.workspace_dir, self.logs_dir):
            p.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps(self.values, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "AppConfig":
        data_dir = Path(data_dir) if data_dir else default_data_dir()
        defaults_file = application_root() / "config" / "default_config.json"
        values: dict = {}
        if defaults_file.exists():
            values = json.loads(defaults_file.read_text(encoding="utf-8"))
        settings = data_dir / "settings.json"
        if settings.exists():
            try:
                values = _deep_merge(values, json.loads(settings.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                # Corrupt user settings must not prevent start-up; defaults are used.
                pass
        cfg = cls(data_dir=data_dir, values=values)
        cfg.ensure_directories()
        return cfg
