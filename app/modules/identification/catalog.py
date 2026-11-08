"""Local TV model catalog and model matching.

The catalog (manufacturers, tv_models, tv_chassis, mainboards, display_panels)
starts empty: it is filled only from TV projects whose identification the
operator has confirmed ("Save to catalog"). No model data is invented or
pre-seeded. Matching compares a project (or OCR'd model string) with catalog
entries using OCR-tolerant normalisation.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from app.database.connection import Database
from app.security.audit import AuditLogger
from app.services.project_service import TVProject

_CONFUSABLE = str.maketrans({"O": "0", "Q": "0", "I": "1", "L": "1", "S": "5", "B": "8", "Z": "2"})


def canonical(code: str | None) -> str:
    """Upper-case, drop separators, fold OCR-confusable characters."""
    if not code:
        return ""
    return re.sub(r"[^A-Z0-9]", "", code.upper()).translate(_CONFUSABLE)


@dataclass
class ModelMatch:
    tv_model_id: int
    manufacturer: str | None
    model_number: str
    chassis: str | None
    mainboard: str | None
    pcb_revision: str | None
    panel_model: str | None
    screen_size_inches: float | None
    score: float              # 0..1
    reasons: list[str]

    @property
    def level(self) -> str:
        if self.score >= 0.95:
            return "exact"
        if self.score >= 0.8:
            return "close"
        return "weak"


class CatalogService:
    def __init__(self, db: Database, audit: AuditLogger):
        self.db = db
        self.audit = audit

    # ---- upserts ---------------------------------------------------------------
    def _manufacturer_id(self, c, name: str | None) -> int | None:
        if not name:
            return None
        row = c.execute("SELECT id FROM manufacturers WHERE name=? COLLATE NOCASE", (name,)).fetchone()
        return row[0] if row else c.execute("INSERT INTO manufacturers(name) VALUES (?)", (name,)).lastrowid

    def save_project(self, p: TVProject) -> int:
        """Add/update a catalog entry from a project. Requires manufacturer + model."""
        if not (p.manufacturer and p.model_number):
            raise ValueError("Manufacturer and model number are required to save to the catalog")
        with self.db.transaction() as c:
            mid = self._manufacturer_id(c, p.manufacturer)
            chassis_id = board_id = panel_id = None
            if p.chassis:
                c.execute("INSERT OR IGNORE INTO tv_chassis(manufacturer_id, chassis_code) VALUES (?,?)",
                          (mid, p.chassis))
                chassis_id = c.execute("SELECT id FROM tv_chassis WHERE manufacturer_id IS ? AND chassis_code=?",
                                       (mid, p.chassis)).fetchone()[0]
            if p.mainboard:
                c.execute("INSERT OR IGNORE INTO mainboards(manufacturer_id, board_number, pcb_revision)"
                          " VALUES (?,?,?)", (mid, p.mainboard, p.pcb_revision))
                board_id = c.execute("SELECT id FROM mainboards WHERE board_number=? AND pcb_revision IS ?",
                                     (p.mainboard, p.pcb_revision)).fetchone()[0]
            if p.panel_model:
                c.execute("INSERT OR IGNORE INTO display_panels(vendor, panel_model, size_inches,"
                          " source_reference) VALUES (NULL,?,?,?)",
                          (p.panel_model, p.screen_size_inches, f"tv_project:{p.id}"))
                panel_id = c.execute("SELECT id FROM display_panels WHERE vendor IS NULL AND panel_model=?",
                                     (p.panel_model,)).fetchone()[0]
            row = c.execute("SELECT id FROM tv_models WHERE manufacturer_id IS ? AND model_number=?",
                            (mid, p.model_number)).fetchone()
            vals = (p.product_code, chassis_id, board_id, panel_id, p.screen_size_inches, p.tv_type)
            if row:
                tid = row[0]
                c.execute("UPDATE tv_models SET product_code=COALESCE(?,product_code),"
                          " chassis_id=COALESCE(?,chassis_id), mainboard_id=COALESCE(?,mainboard_id),"
                          " panel_id=COALESCE(?,panel_id), screen_size_inches=COALESCE(?,screen_size_inches),"
                          " tv_type=COALESCE(?,tv_type) WHERE id=?", vals + (tid,))
            else:
                tid = c.execute("INSERT INTO tv_models(manufacturer_id, model_number, product_code, chassis_id,"
                                " mainboard_id, panel_id, screen_size_inches, tv_type, notes)"
                                " VALUES (?,?,?,?,?,?,?,?,?)",
                                (mid, p.model_number) + vals + (f"From TV project #{p.id}",)).lastrowid
            c.execute("UPDATE tv_projects SET tv_model_id=? WHERE id=?", (tid, p.id))
        self.audit.record("catalog.save", "tv_model", tid, project_id=p.id)
        return tid

    # ---- matching --------------------------------------------------------------
    def _rows(self):
        return self.db.query(
            "SELECT m.id, mf.name AS manufacturer, m.model_number, ch.chassis_code AS chassis,"
            " mb.board_number AS mainboard, mb.pcb_revision, dp.panel_model, m.screen_size_inches"
            " FROM tv_models m LEFT JOIN manufacturers mf ON mf.id=m.manufacturer_id"
            " LEFT JOIN tv_chassis ch ON ch.id=m.chassis_id LEFT JOIN mainboards mb ON mb.id=m.mainboard_id"
            " LEFT JOIN display_panels dp ON dp.id=m.panel_id")

    def find_matches(self, model_number: str | None = None, manufacturer: str | None = None,
                     mainboard: str | None = None, chassis: str | None = None,
                     min_score: float = 0.6, limit: int = 10) -> list[ModelMatch]:
        """Score catalog entries. Model similarity dominates; board/chassis agreement
        adds evidence; a different manufacturer is a strong penalty.
        For unknown TVs (no model) matching runs on mainboard/chassis alone."""
        q_model, q_board, q_ch = canonical(model_number), canonical(mainboard), canonical(chassis)
        if not (q_model or q_board or q_ch):
            return []
        out = []
        for r in self._rows():
            reasons, parts = [], []
            if q_model:
                sim = difflib.SequenceMatcher(None, q_model, canonical(r["model_number"])).ratio()
                parts.append((sim, 0.7))
                reasons.append(f"model similarity {sim:.0%}")
            if q_board and r["mainboard"]:
                sim = 1.0 if q_board == canonical(r["mainboard"]) else 0.0
                parts.append((sim, 0.2 if q_model else 0.7))
                reasons.append("mainboard matches" if sim else "mainboard differs")
            if q_ch and r["chassis"]:
                sim = 1.0 if q_ch == canonical(r["chassis"]) else 0.0
                parts.append((sim, 0.1 if q_model else 0.3))
                reasons.append("chassis matches" if sim else "chassis differs")
            if not parts:
                continue
            score = sum(s * w for s, w in parts) / sum(w for _, w in parts)
            if manufacturer and r["manufacturer"]:
                if manufacturer.strip().lower() != r["manufacturer"].lower():
                    score *= 0.5
                    reasons.append("different manufacturer")
                else:
                    reasons.append("same manufacturer")
            if score >= min_score:
                out.append(ModelMatch(r["id"], r["manufacturer"], r["model_number"], r["chassis"],
                                      r["mainboard"], r["pcb_revision"], r["panel_model"],
                                      r["screen_size_inches"], round(score, 3), reasons))
        return sorted(out, key=lambda m: -m.score)[:limit]

    def count(self) -> int:
        return self.db.scalar("SELECT COUNT(*) FROM tv_models")
