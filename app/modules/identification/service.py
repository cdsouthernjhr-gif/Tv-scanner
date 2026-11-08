"""Identification orchestration: preprocess → OCR → candidates / markings → review.

Flow
----
1. ``run_ocr(evidence_id)`` preprocesses the stored image (preset chosen by
   evidence type, optional crop/rotation), runs OCR, stores the raw result in
   ``ocr_results`` and ``scan_evidence.ocr_text``.
2. Text is parsed into ``identification_candidates`` and tokens are scanned for
   chip/PCB markings (``marking_detections``). Everything starts as *pending*.
3. The operator accepts/rejects candidates. Accepting writes the value into the
   project and marks it evidence-backed; confirming a marking creates a
   ``hardware_components`` row (verified_by_user=1).

Nothing from OCR reaches the project without an explicit operator decision.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import cv2

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.identification.catalog import CatalogService, ModelMatch
from app.modules.identification.parsers import Candidate, drop_prefix_fragments, extract_candidates
from app.modules.visual_scanner import markings as mk
from app.modules.visual_scanner import preprocess as pp
from app.modules.visual_scanner.ocr import OcrEngine, OcrResult, PaddleOcrEngine, TesseractEngine
from app.security.audit import AuditLogger
from app.services.evidence_service import EvidenceService
from app.services.external_tools import detect_tools
from app.services.project_service import ProjectService

log = logging.getLogger(__name__)

# Evidence types where text is laid out as blocks/tables rather than sparse labels.
_BLOCK_TYPES = {"system_info_menu"}
# Evidence types whose OCR should be scanned for markings, and whether unknown
# part-number-like strings are kept.
_MARKING_SCAN = {"chip": True, "mainboard": False, "power_supply": False, "tcon": False,
                 "other": False, "panel_label": False}
# project fields a candidate may be written to
ACCEPTABLE_FIELDS = {"manufacturer", "model_number", "serial_number", "product_code", "chassis",
                     "mainboard", "pcb_revision", "screen_size_inches", "platform",
                     "firmware_version", "panel_model"}


@dataclass
class OcrRunSummary:
    evidence_id: int
    ocr_result_id: int
    engine: str
    preset: str
    psm: int
    mean_confidence: float
    text: str
    candidates: list[Candidate] = field(default_factory=list)
    markings: list[mk.Detection] = field(default_factory=list)
    quality: dict = field(default_factory=dict)
    processed_image: object = None   # numpy array used for OCR (for UI overlay)
    tokens: list = field(default_factory=list)


class IdentificationService:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger,
                 projects: ProjectService, evidence: EvidenceService, catalog: CatalogService):
        self.config, self.db, self.audit = config, db, audit
        self.projects, self.evidence, self.catalog = projects, evidence, catalog
        self._engines: dict[str, OcrEngine] | None = None

    # ---- engines ---------------------------------------------------------------
    def engines(self) -> dict[str, OcrEngine]:
        if self._engines is None:
            tess_path = next((t.path for t in detect_tools(self.config) if t.key == "tesseract"), None)
            self._engines = {"tesseract": TesseractEngine(tess_path), "paddleocr": PaddleOcrEngine()}
        return self._engines

    def available_engines(self) -> list[str]:
        return [n for n, e in self.engines().items() if e.available()]

    def engine(self, name: str | None = None) -> OcrEngine:
        names = self.available_engines()
        if not names:
            raise RuntimeError("No OCR engine available. Install Tesseract OCR (see docs/INSTALL_WINDOWS.md).")
        if name and name not in names:
            raise RuntimeError(f"OCR engine {name!r} is not available")
        return self.engines()[name or names[0]]

    # ---- processing -----------------------------------------------------------
    def process(self, evidence_id: int, preset: str | None = None,
                crop_rect: tuple[int, int, int, int] | None = None, rotation: float = 0.0):
        ev = self.evidence.get(evidence_id)
        preset = preset or pp.PRESET_FOR_EVIDENCE.get(ev.evidence_type, "label")
        img = pp.load_image(ev.stored_path)
        steps: list[dict] = []
        if rotation:
            img = pp.rotate(img, rotation)
            steps.append({"op": "rotate", "args": {"degrees": rotation}})
        res = pp.run_pipeline(img, preset, crop_rect)
        return ev, preset, res.image, steps + res.steps

    def save_processed(self, evidence_id: int, preset: str | None = None,
                       crop_rect: tuple[int, int, int, int] | None = None, rotation: float = 0.0):
        ev, preset, img, steps = self.process(evidence_id, preset, crop_rect, rotation)
        ok, buf = cv2.imencode(".png", img)
        if not ok:
            raise IOError("PNG encoding failed")
        h, w = img.shape[:2]
        return self.evidence.add_derived(ev.id, buf.tobytes(), [{"preset": preset}] + steps, w, h)

    # ---- OCR ------------------------------------------------------------------------
    def run_ocr(self, evidence_id: int, preset: str | None = None, engine: str | None = None,
                psm: int | None = None, crop_rect: tuple[int, int, int, int] | None = None,
                rotation: float = 0.0, auto: bool = True, language: str = "eng") -> OcrRunSummary:
        """Run OCR on one evidence image.

        With ``auto`` (and no explicit preset) several preprocessing/page-layout
        variants are tried. Every trial is stored in ``ocr_results``; candidates
        and markings are collected from all trials (each keeps a link to the
        trial that produced it) so a code split by one variant is still found
        whole by another. The summary reports the best-scoring trial.
        """
        eng = self.engine(engine)
        ev = self.evidence.get(evidence_id)
        default_preset = preset or pp.PRESET_FOR_EVIDENCE.get(ev.evidence_type, "label")
        default_psm = psm or (6 if ev.evidence_type in _BLOCK_TYPES else 11)
        trials = [(default_preset, default_psm)]
        if auto and preset is None:
            trials += [("none", default_psm), ("binarize", default_psm),
                       (default_preset, 6 if default_psm == 11 else 11), ("none", 6 if default_psm == 11 else 11)]

        runs: list[tuple[OcrResult, str, int, object, int]] = []
        for pr, ps in dict.fromkeys(trials):
            _, _, img, _steps = self.process(evidence_id, pr, crop_rect, rotation)
            try:
                r = eng.recognize(img, language=language, psm=ps)
            except Exception as exc:
                log.warning("OCR trial %s/psm%s failed: %s", pr, ps, exc)
                continue
            rid = self.db.execute(
                "INSERT INTO ocr_results(evidence_id, engine, preset, language, text, mean_confidence,"
                " tokens_json, duration_ms) VALUES (?,?,?,?,?,?,?,?)",
                (ev.id, eng.version(), f"{pr}/psm{ps}", language, r.text, r.mean_confidence,
                 json.dumps(r.tokens_as_dicts()), r.duration_ms))
            runs.append((r, pr, ps, img, rid))
        if not runs:
            raise RuntimeError("OCR failed for all preprocessing variants")

        def _score(r: OcrResult) -> float:  # empty/near-empty text is not a "good" result
            return r.mean_confidence * min(1.0, len(r.text) / 20 + 0.5)
        best = max(runs, key=lambda x: _score(x[0]))
        result, used_preset, used_psm, img, best_rid = best
        self.db.execute("UPDATE scan_evidence SET ocr_text=? WHERE id=?", (result.text, ev.id))

        # candidates from all trials: best confidence per field/value, remembering the trial
        merged: dict[tuple, tuple[Candidate, int]] = {}
        for r, _pr, _ps, _img, rid in runs:
            for cand in extract_candidates(r.lines()):
                k = (cand.field, cand.value)
                if k not in merged or cand.confidence > merged[k][0].confidence:
                    merged[k] = (cand, rid)
        kept = drop_prefix_fragments([c for c, _ in merged.values()])
        cands = sorted(kept, key=lambda c: (c.field, -c.confidence))
        for cand in cands:
            rid = merged[(cand.field, cand.value)][1]
            self.db.execute(
                "INSERT OR IGNORE INTO identification_candidates(project_id, field, value, confidence,"
                " method, evidence_id, ocr_result_id, source_line) VALUES (?,?,?,?,?,?,?,?)",
                (ev.project_id, cand.field, cand.value, cand.confidence, cand.method, ev.id, rid,
                 cand.source_line))

        dets: list[mk.Detection] = []
        if ev.evidence_type in _MARKING_SCAN:
            md: dict[tuple, tuple[mk.Detection, int]] = {}
            for r, _pr, _ps, _img, rid in runs:
                for d in mk.detect(r, include_unrecognised=_MARKING_SCAN[ev.evidence_type]):
                    k = (d.kind, d.normalized)
                    if k not in md or d.confidence > md[k][0].confidence:
                        md[k] = (d, rid)
            # an unrecognised marking that is a fragment of a recognised one is noise
            recognised = [d.normalized for d, _ in md.values() if d.rule_id]
            for k, (d, rid) in list(md.items()):
                if d.rule_id is None and any(d.normalized in rn for rn in recognised):
                    del md[k]
            dets = sorted((d for d, _ in md.values()), key=lambda d: -d.confidence)
            for d in dets:
                rid = md[(d.kind, d.normalized)][1]
                self.db.execute(
                    "INSERT OR IGNORE INTO marking_detections(project_id, evidence_id, ocr_result_id, kind,"
                    " raw_text, normalized, rule_id, candidate_vendor, candidate_type, note, confidence,"
                    " bbox_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev.project_id, ev.id, rid, d.kind, d.raw_text, d.normalized, d.rule_id, d.vendor,
                     d.type, d.note, d.confidence, json.dumps(d.bbox)))
                # PCB numbers are also identification candidates for the 'mainboard' field
                if d.kind == "pcb" and d.rule_id:
                    self.db.execute(
                        "INSERT OR IGNORE INTO identification_candidates(project_id, field, value, confidence,"
                        " method, evidence_id, ocr_result_id, source_line) VALUES (?,?,?,?,?,?,?,?)",
                        (ev.project_id, "mainboard", d.normalized, d.confidence, f"pcb_rule:{d.rule_id}",
                         ev.id, rid, d.raw_text))

        quality = pp.quality_report(pp.load_image(ev.stored_path))
        self.db.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                        " VALUES (?, 'ocr', ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                        (ev.project_id, f"OCR evidence #{ev.id}: {len(cands)} candidates, "
                                        f"{len(dets)} markings, conf {result.mean_confidence:.0%}"))
        self.audit.record("ocr.run", "scan_evidence", ev.id, ocr_result_id=best_rid, engine=eng.version(),
                          trials=len(runs), best=f"{used_preset}/psm{used_psm}", candidates=len(cands),
                          markings=len(dets))
        return OcrRunSummary(ev.id, best_rid, eng.version(), used_preset, used_psm, result.mean_confidence,
                             result.text, cands, dets, quality, img, result.tokens)

    def run_ocr_for_project(self, project_id: int, only_new: bool = True) -> list[OcrRunSummary]:
        out = []
        for ev in self.evidence.list_for_project(project_id):
            if ev.parent_evidence_id is not None:
                continue  # derived copies are OCR'd explicitly from the Visual Scanner
            if only_new and self.db.scalar("SELECT COUNT(*) FROM ocr_results WHERE evidence_id=?", (ev.id,)):
                continue
            out.append(self.run_ocr(ev.id))
        return out

    # ---- review: candidates ---------------------------------------------------------
    def candidates(self, project_id: int, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM identification_candidates WHERE project_id=?"
        params: list = [project_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        return [dict(r) for r in self.db.query(sql + " ORDER BY field, confidence DESC", tuple(params))]

    def aggregated_candidates(self, project_id: int) -> list[dict]:
        """Combine identical values found in several images: P = 1 - Π(1 - p_i), capped at 0.99."""
        groups: dict[tuple, dict] = {}
        for c in self.candidates(project_id):
            if c["status"] == "rejected":
                continue
            g = groups.setdefault((c["field"], c["value"]), {
                "field": c["field"], "value": c["value"], "evidence_ids": set(), "methods": set(),
                "miss": 1.0, "status": c["status"], "ids": []})
            g["miss"] *= (1 - c["confidence"])
            if c["evidence_id"]:
                g["evidence_ids"].add(c["evidence_id"])
            g["methods"].add(c["method"])
            g["ids"].append(c["id"])
            if c["status"] == "accepted":
                g["status"] = "accepted"
        out = []
        for g in groups.values():
            out.append({"field": g["field"], "value": g["value"], "confidence": round(min(0.99, 1 - g["miss"]), 3),
                        "evidence_count": len(g["evidence_ids"]), "methods": sorted(g["methods"]),
                        "status": g["status"], "candidate_ids": g["ids"]})
        return sorted(out, key=lambda x: (x["field"], -x["confidence"]))

    def accept_candidate(self, candidate_id: int):
        c = self.db.query_one("SELECT * FROM identification_candidates WHERE id=?", (candidate_id,))
        if c is None:
            raise KeyError(candidate_id)
        if c["field"] not in ACCEPTABLE_FIELDS:
            raise ValueError(f"Field {c['field']} cannot be applied to a project")
        value = c["value"]
        if c["field"] == "screen_size_inches":
            value = float(value)
        with self.db.transaction() as tx:
            # every candidate with the same field+value is accepted; other values for that field rejected
            tx.execute("UPDATE identification_candidates SET status='accepted',"
                       " decided_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')"
                       " WHERE project_id=? AND field=? AND value=?", (c["project_id"], c["field"], c["value"]))
            tx.execute("UPDATE identification_candidates SET status='rejected',"
                       " decided_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')"
                       " WHERE project_id=? AND field=? AND value<>? AND status<>'rejected'",
                       (c["project_id"], c["field"], c["value"]))
        project = self.projects.update(c["project_id"], **{c["field"]: value})
        self.audit.record("candidate.accept", "tv_project", c["project_id"], field=c["field"],
                          value=c["value"], candidate_id=candidate_id, evidence_id=c["evidence_id"])
        return project

    def reject_candidate(self, candidate_id: int):
        c = self.db.query_one("SELECT * FROM identification_candidates WHERE id=?", (candidate_id,))
        if c is None:
            raise KeyError(candidate_id)
        self.db.execute("UPDATE identification_candidates SET status='rejected',"
                        " decided_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?", (candidate_id,))
        self.audit.record("candidate.reject", "tv_project", c["project_id"], field=c["field"],
                          value=c["value"], candidate_id=candidate_id)
        return self.projects.reassess(c["project_id"])

    # ---- review: markings -----------------------------------------------------------
    def markings(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM marking_detections WHERE project_id=? ORDER BY kind, confidence DESC", (project_id,))]

    def confirm_marking(self, marking_id: int, part_number: str | None = None,
                        manufacturer: str | None = None, component_type: str | None = None) -> int:
        """Operator confirms what the chip/board is. Creates a hardware_components row."""
        m = self.db.query_one("SELECT * FROM marking_detections WHERE id=?", (marking_id,))
        if m is None:
            raise KeyError(marking_id)
        from app.modules.hardware_analyzer.service import category_for
        part = (part_number or m["normalized"]).strip().upper()
        ctype = category_for(component_type or m["candidate_type"]) if (component_type or m["candidate_type"]) \
            else ("board" if m["kind"] == "pcb" else "other")
        vendor = manufacturer if manufacturer is not None else m["candidate_vendor"]
        ev_type = self.db.scalar("SELECT evidence_type FROM scan_evidence WHERE id=?", (m["evidence_id"],))
        board = {"mainboard": "mainboard", "power_supply": "power_supply", "tcon": "tcon",
                 "panel_label": "panel"}.get(ev_type, "other")
        source = f"evidence #{m['evidence_id']} OCR; rule {m['rule_id'] or 'none'}"
        with self.db.transaction() as tx:
            hid = tx.execute(
                "INSERT INTO hardware_components(project_id, component_type, component_name, manufacturer,"
                " part_number, evidence_id, confidence, verified_by_user, source_reference, board)"
                " VALUES (?,?,?,?,?,?,?,1,?,?)",
                (m["project_id"], ctype, m["candidate_type"] or ctype, vendor, part, m["evidence_id"],
                 m["confidence"], source, board)).lastrowid
            tx.execute("UPDATE marking_detections SET status='confirmed', hardware_component_id=? WHERE id=?",
                       (hid, marking_id))
        self.audit.record("marking.confirm", "tv_project", m["project_id"], marking_id=marking_id,
                          part_number=part, hardware_component_id=hid)
        return hid

    def reject_marking(self, marking_id: int) -> None:
        m = self.db.query_one("SELECT project_id FROM marking_detections WHERE id=?", (marking_id,))
        if m is None:
            raise KeyError(marking_id)
        self.db.execute("UPDATE marking_detections SET status='rejected' WHERE id=?", (marking_id,))
        self.audit.record("marking.reject", "tv_project", m["project_id"], marking_id=marking_id)

    # ---- catalog -----------------------------------------------------------------------
    def find_catalog_matches(self, project_id: int) -> list[ModelMatch]:
        p = self.projects.get(project_id)
        return self.catalog.find_matches(p.model_number, p.manufacturer, p.mainboard, p.chassis)

    def apply_catalog_match(self, project_id: int, match: ModelMatch) -> int:
        """Turn a catalog entry's data into *candidates* (method catalog_match) for review."""
        n = 0
        for fld in ("manufacturer", "model_number", "chassis", "mainboard", "pcb_revision", "panel_model",
                    "screen_size_inches"):
            val = getattr(match, fld)
            if val in (None, ""):
                continue
            val = f"{val:g}" if isinstance(val, float) else str(val)
            if self.db.scalar("SELECT 1 FROM identification_candidates WHERE project_id=? AND field=?"
                              " AND value=? AND method='catalog_match'", (project_id, fld, val)):
                continue
            n += 1
            self.db.execute(
                "INSERT OR IGNORE INTO identification_candidates(project_id, field, value, confidence, method,"
                " evidence_id, source_line) VALUES (?,?,?,?,?,NULL,?)",
                (project_id, fld, val, round(match.score * 0.9, 3), "catalog_match",
                 f"catalog tv_model #{match.tv_model_id}: {'; '.join(match.reasons)}"))
        self.audit.record("catalog.apply_match", "tv_project", project_id, tv_model_id=match.tv_model_id)
        return n
