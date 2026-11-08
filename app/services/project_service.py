"""TV project registration and manual identification data."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

from app.database.connection import Database
from app.security.audit import AuditLogger

TV_TYPES = ["", "LED/LCD", "OLED", "QLED", "Mini-LED", "Plasma", "CRT", "Projector", "Other"]
PLATFORMS = ["", "Unknown", "Android TV", "Google TV", "Tizen", "webOS", "VIDAA",
             "Linux (generic)", "Roku TV", "Fire TV", "Saphi", "Proprietary / non-smart"]

# Fields that matter for identification and how much each contributes.
_IDENT_WEIGHTS = {
    "manufacturer": 0.25, "model_number": 0.30, "chassis": 0.10, "mainboard": 0.15,
    "product_code": 0.05, "serial_number": 0.05, "screen_size_inches": 0.05, "platform": 0.05,
}
MANUAL_FACTOR = 0.8   # manual (unverified) values count for 80 % of their weight


@dataclass
class TVProject:
    name: str
    manufacturer: str | None = None
    model_number: str | None = None
    serial_number: str | None = None
    product_code: str | None = None
    chassis: str | None = None
    mainboard: str | None = None
    pcb_revision: str | None = None
    screen_size_inches: float | None = None
    tv_type: str | None = None
    platform: str | None = None
    firmware_version: str | None = None
    panel_model: str | None = None
    notes: str | None = None
    id: int | None = None
    identification_status: str = "unknown"
    identification_confidence: float = 0.0
    identification_source: str = "manual"
    created_at: str | None = None
    updated_at: str | None = None

    @classmethod
    def from_row(cls, row) -> "TVProject":
        names = {f.name for f in fields(cls)}
        return cls(**{k: row[k] for k in row.keys() if k in names})


EDITABLE = ["name", "manufacturer", "model_number", "serial_number", "product_code", "chassis",
            "mainboard", "pcb_revision", "screen_size_inches", "tv_type", "platform",
            "firmware_version", "panel_model", "notes"]


def _clean(v: Any) -> Any:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


def _norm(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:g}"
    return str(v).strip().upper()


def assess_identification(p: TVProject, evidence_values: dict[str, set[str]] | None = None
                          ) -> tuple[str, float, str]:
    """Return (status, confidence, source).

    ``evidence_values`` maps field -> values the operator accepted from evidence
    (OCR of labels/menus). A field counts as evidence-backed only while the
    project's current value equals an accepted value; otherwise it is manual.

    * manual values count for 80 % of their weight;
    * 'verified' requires manufacturer AND model to be evidence-backed;
    * source is 'manual', 'evidence' or 'mixed'.
    """
    evidence_values = evidence_values or {}
    score, backed, manual = 0.0, set(), set()
    for f, w in _IDENT_WEIGHTS.items():
        v = _clean(getattr(p, f))
        if v in (None, ""):
            continue
        if _norm(v) in {_norm(x) for x in evidence_values.get(f, set())}:
            backed.add(f)
            score += w
        else:
            manual.add(f)
            score += w * MANUAL_FACTOR
    if {"manufacturer", "model_number"} <= backed:
        status = "verified"
    elif p.manufacturer and p.model_number:
        status = "identified"
    elif p.manufacturer or p.model_number or p.mainboard or p.chassis:
        status = "partial"
    else:
        status = "unknown"
    source = "evidence" if backed and not manual else "mixed" if backed else "manual"
    return status, round(min(score, 1.0), 2), source


class ProjectService:
    def __init__(self, db: Database, audit: AuditLogger):
        self.db = db
        self.audit = audit

    def create(self, project: TVProject) -> TVProject:
        for f in EDITABLE:
            setattr(project, f, _clean(getattr(project, f)))
        if not project.name:
            raise ValueError("Project name is required")
        if project.screen_size_inches is not None:
            project.screen_size_inches = float(project.screen_size_inches)
            if not 5 <= project.screen_size_inches <= 300:
                raise ValueError("Screen size must be between 5 and 300 inches")
        (project.identification_status, project.identification_confidence,
         project.identification_source) = assess_identification(project)
        cols = EDITABLE + ["identification_status", "identification_confidence", "identification_source"]
        with self.db.transaction() as c:
            cur = c.execute(
                f"INSERT INTO tv_projects({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                tuple(getattr(project, k) for k in cols))
            project.id = cur.lastrowid
            c.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                      " VALUES (?, 'registration', 'Project registered', strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                      (project.id,))
        self.audit.record("project.create", "tv_project", project.id, name=project.name)
        return self.get(project.id)

    def update(self, project_id: int, **changes: Any) -> TVProject:
        current = self.get(project_id)
        for k, v in changes.items():
            if k not in EDITABLE:
                raise ValueError(f"Field {k!r} is not editable")
            setattr(current, k, _clean(v))
        if not current.name:
            raise ValueError("Project name is required")
        if current.screen_size_inches is not None:
            current.screen_size_inches = float(current.screen_size_inches)
        self._save(current)
        self.audit.record("project.update", "tv_project", project_id, fields=sorted(changes))
        return self.get(project_id)

    def evidence_values(self, project_id: int) -> dict[str, set[str]]:
        rows = self.db.query("SELECT field, value FROM identification_candidates"
                             " WHERE project_id=? AND status='accepted' AND evidence_id IS NOT NULL",
                             (project_id,))  # catalog matches are not physical evidence
        out: dict[str, set[str]] = {}
        for r in rows:
            out.setdefault(r["field"], set()).add(r["value"])
        return out

    def reassess(self, project_id: int) -> TVProject:
        """Recompute status/confidence after evidence was accepted or rejected."""
        self._save(self.get(project_id))
        return self.get(project_id)

    def _save(self, current: TVProject) -> None:
        (current.identification_status, current.identification_confidence,
         current.identification_source) = assess_identification(current, self.evidence_values(current.id))
        cols = EDITABLE + ["identification_status", "identification_confidence", "identification_source"]
        self.db.execute(
            f"UPDATE tv_projects SET {', '.join(f'{c}=?' for c in cols)},"
            " updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
            tuple(getattr(current, c) for c in cols) + (current.id,))

    def get(self, project_id: int) -> TVProject:
        row = self.db.query_one("SELECT * FROM tv_projects WHERE id=?", (project_id,))
        if row is None:
            raise KeyError(f"Project {project_id} not found")
        return TVProject.from_row(row)

    def list(self) -> list[TVProject]:
        return [TVProject.from_row(r) for r in
                self.db.query("SELECT * FROM tv_projects ORDER BY id DESC")]

    def delete(self, project_id: int) -> None:
        self.db.execute("DELETE FROM tv_projects WHERE id=?", (project_id,))
        self.audit.record("project.delete", "tv_project", project_id)

    @staticmethod
    def as_dict(p: TVProject) -> dict:
        return asdict(p)
