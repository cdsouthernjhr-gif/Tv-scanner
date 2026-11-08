"""PDF technical reports (ReportLab).

Phase 1 produces the *TV Identification Report*: project data, its
provenance/confidence, evidence images with SHA-256, and associated firmware.
Every report is hashed and registered in ``technical_reports``.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Image as RLImage, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from app.core.config import APP_NAME, APP_VERSION, AppConfig
from app.database.connection import Database
from app.modules.firmware_library.library import FirmwareLibrary
from app.security.audit import AuditLogger
from app.security.file_protection import safe_component
from app.security.hashing import sha256_file
from app.services.evidence_service import EVIDENCE_TYPES, EvidenceService
from app.services.project_service import ProjectService


def _p(text, style):
    return Paragraph(escape("" if text is None else str(text)), style)


class PdfReportGenerator:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger,
                 projects: ProjectService, evidence: EvidenceService, library: FirmwareLibrary):
        self.config, self.db, self.audit = config, db, audit
        self.projects, self.evidence, self.library = projects, evidence, library

    def _table(self, rows, col_widths, header=True):
        t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
        style = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                      ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        else:
            style += [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef6"))]
        t.setStyle(TableStyle(style))
        return t

    def generate_identification_report(self, project_id: int, output: Path | None = None) -> Path:
        project = self.projects.get(project_id)
        evidence = self.evidence.list_for_project(project_id)
        firmware = self.library.list(project_id=project_id)
        now = _dt.datetime.now(_dt.timezone.utc)

        if output is None:
            out_dir = self.config.reports_dir / str(project_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            output = out_dir / (f"TV_Identification_{safe_component(project.name)}_"
                                f"{now.strftime('%Y%m%d_%H%M%S')}.pdf")
        output = Path(output)

        ss = getSampleStyleSheet()
        small = ParagraphStyle("small", parent=ss["BodyText"], fontSize=8, leading=10)
        mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=7)
        story = [
            Paragraph(f"{APP_NAME} &mdash; TV Identification Report", ss["Title"]),
            _p(f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')} | Application v{APP_VERSION}"
               f" | Project ID {project.id}", small),
            Spacer(1, 6 * mm),
            Paragraph("1. Identification summary", ss["Heading2"]),
        ]
        fields = [
            ("Project name", project.name), ("Manufacturer", project.manufacturer),
            ("Model", project.model_number), ("Serial number", project.serial_number),
            ("Product code", project.product_code), ("Chassis", project.chassis),
            ("Mainboard", project.mainboard), ("PCB revision", project.pcb_revision),
            ("Screen size (in)", project.screen_size_inches), ("TV type", project.tv_type),
            ("Platform / OS", project.platform), ("Firmware version", project.firmware_version),
            ("Panel model / ID", project.panel_model),
            ("Identification status", project.identification_status),
            ("Identification confidence", f"{project.identification_confidence:.0%}"),
            ("Data source", project.identification_source),
            ("Registered", project.created_at), ("Last updated", project.updated_at),
        ]
        story.append(self._table([[_p(k, small), _p(v if v not in (None, "") else "— not determined —", small)]
                                  for k, v in fields], [55 * mm, 115 * mm], header=False))
        story.append(Spacer(1, 3 * mm))
        story.append(_p("Note: 'manual' values were typed by the operator and are not independently verified "
                        "(they count for 80% of their weight). 'evidence' values were read from the images "
                        "below by OCR and accepted by the operator; 'mixed' means both. Status 'verified' "
                        "requires manufacturer and model to be evidence-backed. "
                        "Fields marked 'not determined' had no supporting evidence.", small))
        if project.notes:
            story += [Spacer(1, 3 * mm), _p(f"Notes: {project.notes}", small)]

        story.append(Paragraph("2. Evidence images", ss["Heading2"]))
        if not evidence:
            story.append(_p("No evidence images recorded.", small))
        for ev in evidence:
            rows = [[_p("Type", small), _p(EVIDENCE_TYPES.get(ev.evidence_type, ev.evidence_type), small)],
                    [_p("Original file", small), _p(ev.original_filename, small)],
                    [_p("SHA-256", small), _p(ev.sha256, mono)],
                    [_p("Dimensions", small), _p(f"{ev.width} x {ev.height} px, {ev.file_size:,} bytes", small)],
                    [_p("Added", small), _p(ev.created_at, small)]]
            if ev.description:
                rows.append([_p("Description", small), _p(ev.description, small)])
            story.append(self._table(rows, [35 * mm, 135 * mm], header=False))
            path = Path(ev.stored_path)
            if path.exists() and ev.width and ev.height:
                max_w, max_h = 160 * mm, 90 * mm
                scale = min(max_w / ev.width, max_h / ev.height, 1.0)
                try:
                    story.append(RLImage(str(path), width=ev.width * scale, height=ev.height * scale))
                except Exception as exc:  # unsupported encoding for ReportLab
                    story.append(_p(f"[image could not be embedded: {exc}]", small))
            else:
                story.append(_p("[stored image missing]", small))
            story.append(Spacer(1, 5 * mm))

        story.append(Paragraph("3. Firmware associated with this project", ss["Heading2"]))
        if firmware:
            rows = [[_p(h, small) for h in ("File", "Category", "Format", "Size", "Integrity", "SHA-256")]]
            for fw in firmware:
                rows.append([_p(fw.original_filename, small), _p(fw.category, small),
                             _p(fw.detected_format, small), _p(f"{fw.file_size:,}", small),
                             _p(fw.verification_status, small), _p(fw.sha256, mono)])
            story.append(self._table(rows, [32 * mm, 18 * mm, 30 * mm, 18 * mm, 18 * mm, 54 * mm]))
            story.append(_p("'hash_ok' only means the stored copy matches the hash recorded at import. "
                            "It is NOT a statement of authenticity or compatibility.", small))
        else:
            story.append(_p("No firmware files associated.", small))

        # ---- Phase 2: OCR evidence, candidates, markings, confirmed hardware ----------
        story.append(Paragraph("4. OCR & identification evidence", ss["Heading2"]))
        ocr_rows = self.db.query(
            "SELECT o.* FROM ocr_results o JOIN scan_evidence e ON e.id=o.evidence_id WHERE e.project_id=?"
            " AND o.id IN (SELECT MAX(o2.id) FROM ocr_results o2 GROUP BY o2.evidence_id) ORDER BY o.evidence_id",
            (project_id,))
        if ocr_rows:
            rows = [[_p(h, small) for h in ("Evidence", "Engine", "Preset", "Mean conf.", "Text (excerpt)")]]
            for o in ocr_rows:
                ev_text = self.db.scalar("SELECT ocr_text FROM scan_evidence WHERE id=?", (o["evidence_id"],))
                rows.append([_p(f"#{o['evidence_id']}", small), _p(o["engine"], small), _p(o["preset"], small),
                             _p(f"{o['mean_confidence']:.0%}", small), _p((ev_text or "")[:400], mono)])
            story.append(self._table(rows, [16 * mm, 28 * mm, 26 * mm, 18 * mm, 82 * mm]))
        else:
            story.append(_p("No OCR has been run for this project.", small))
        cands = self.db.query("SELECT * FROM identification_candidates WHERE project_id=?"
                              " ORDER BY field, status, confidence DESC", (project_id,))
        if cands:
            story += [Spacer(1, 3 * mm), _p("Identification candidates (accepted values are applied to the "
                                            "project; rejected/pending values are listed for transparency):", small)]
            rows = [[_p(h, small) for h in ("Field", "Value", "Conf.", "Method", "Evidence", "Status")]]
            for c in cands:
                rows.append([_p(c["field"], small), _p(c["value"], mono), _p(f"{c['confidence']:.0%}", small),
                             _p(c["method"], small), _p(f"#{c['evidence_id']}" if c["evidence_id"] else "catalog", small),
                             _p(c["status"], small)])
            story.append(self._table(rows, [30 * mm, 50 * mm, 14 * mm, 34 * mm, 18 * mm, 24 * mm]))
        marks = self.db.query("SELECT * FROM marking_detections WHERE project_id=? ORDER BY kind, confidence DESC",
                              (project_id,))
        story.append(Paragraph("5. Chip & PCB markings", ss["Heading2"]))
        if marks:
            rows = [[_p(h, small) for h in ("Kind", "Marking", "Vendor (convention)", "Type", "Conf.", "Status")]]
            for m in marks:
                rows.append([_p(m["kind"], small), _p(m["normalized"], mono), _p(m["candidate_vendor"] or "—", small),
                             _p(m["candidate_type"] or "unrecognised", small), _p(f"{m['confidence']:.0%}", small),
                             _p(m["status"], small)])
            story.append(self._table(rows, [14 * mm, 40 * mm, 36 * mm, 46 * mm, 14 * mm, 20 * mm]))
            story.append(_p("Vendor/type come from part-number numbering conventions and are not a specification. "
                            "Only 'confirmed' markings were verified by the operator.", small))
        else:
            story.append(_p("No markings detected.", small))
        hw = self.db.query("SELECT * FROM hardware_components WHERE project_id=? ORDER BY id", (project_id,))
        if hw:
            story += [Spacer(1, 3 * mm), _p("Confirmed hardware components:", small)]
            rows = [[_p(h, small) for h in ("Type", "Part number", "Manufacturer", "Evidence", "Source")]]
            for h in hw:
                rows.append([_p(h["component_type"], small), _p(h["part_number"], mono), _p(h["manufacturer"], small),
                             _p(f"#{h['evidence_id']}" if h["evidence_id"] else "", small),
                             _p(h["source_reference"], small)])
            story.append(self._table(rows, [36 * mm, 36 * mm, 32 * mm, 16 * mm, 50 * mm]))

        story += [PageBreak(), Paragraph("6. Audit trail", ss["Heading2"])]
        audit_rows = [[_p(h, small) for h in ("Time (UTC)", "Actor", "Action")]]
        for e in reversed(self.audit.entries("tv_project", project_id, limit=50)):
            audit_rows.append([_p(e["ts"], small), _p(e["actor"], small), _p(e["action"], small)])
        story.append(self._table(audit_rows, [50 * mm, 40 * mm, 80 * mm]))

        def _footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.drawString(15 * mm, 10 * mm, f"{APP_NAME} — project {project.id} — page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(str(output), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                                topMargin=15 * mm, bottomMargin=18 * mm,
                                title=f"TV Identification Report - {project.name}", author=APP_NAME)
        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

        digest = sha256_file(output)
        rid = self.db.execute(
            "INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
            " VALUES (?, 'tv_identification', 'pdf', ?, ?)", (project_id, str(output), digest))
        self.audit.record("report.generate", "tv_project", project_id, report_id=rid,
                          path=str(output), sha256=digest)
        return output

    def list_reports(self, project_id: int | None = None) -> list[dict]:
        if project_id is None:
            rows = self.db.query("SELECT * FROM technical_reports ORDER BY id DESC")
        else:
            rows = self.db.query("SELECT * FROM technical_reports WHERE project_id=? ORDER BY id DESC",
                                 (project_id,))
        return [dict(r) for r in rows]
