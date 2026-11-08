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
            ("Identification status", project.identification_status),
            ("Identification confidence", f"{project.identification_confidence:.0%}"),
            ("Data source", project.identification_source),
            ("Registered", project.created_at), ("Last updated", project.updated_at),
        ]
        story.append(self._table([[_p(k, small), _p(v if v not in (None, "") else "— not determined —", small)]
                                  for k, v in fields], [55 * mm, 115 * mm], header=False))
        story.append(Spacer(1, 3 * mm))
        story.append(_p("Note: values with data source 'manual' were entered by the operator and have "
                        "not been independently verified. Confidence for manual data is capped at 80%. "
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

        story += [PageBreak(), Paragraph("4. Audit trail", ss["Heading2"])]
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
