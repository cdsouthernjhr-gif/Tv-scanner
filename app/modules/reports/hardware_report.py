"""Hardware Report (PDF) and component exports (CSV, JSON, XLSX).

The PDF covers the specification's Hardware, Motherboard and Chipset reports:
board summary, per-component identification with evidence image, every
specification fact with its source and confidence, warnings, and the
datasheets used. Each output is hashed and registered in ``technical_reports``.
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image as RLImage, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import APP_NAME, APP_VERSION, AppConfig
from app.database.connection import Database
from app.modules.hardware_analyzer.decoders import format_bits, format_bytes
from app.modules.hardware_analyzer.service import CATEGORIES, SUMMARY_LABELS, HardwareAnalyzer, category_for
from app.security.audit import AuditLogger
from app.security.file_protection import safe_component
from app.security.hashing import sha256_file
from app.services.evidence_service import EvidenceService
from app.services.project_service import ProjectService

STATUS_TEXT = {
    "datasheet_exact": "Datasheet match (exact part number)",
    "datasheet_family": "Datasheet match (same family — variant to be checked)",
    "decoded": "Decoded from vendor part-numbering scheme",
    "vendor_only": "Vendor/family from numbering convention only",
    "unidentified": "Not identified",
    "not_analyzed": "Not analysed yet",
}
EXPORT_COLUMNS = ["id", "board", "position", "category", "part_number", "manufacturer", "quantity", "match_status",
                  "confidence", "specification", "evidence_id", "datasheet_id", "source_reference", "verified_by_user"]


def _p(text, style):
    return Paragraph(escape("" if text is None else str(text)), style)


def display_value(attr: str, value: str, unit: str | None) -> str:
    try:
        if attr == "density_bits":
            return format_bits(int(value))
        if attr == "capacity_bytes":
            return format_bytes(int(value))
    except ValueError:
        pass
    return f"{value} {unit}" if unit else value


class HardwareReportGenerator:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger, projects: ProjectService,
                 evidence: EvidenceService, hardware: HardwareAnalyzer):
        self.config, self.db, self.audit = config, db, audit
        self.projects, self.evidence, self.hardware = projects, evidence, hardware

    def _out(self, project_id: int, ext: str, kind: str) -> Path:
        p = self.projects.get(project_id)
        d = self.config.reports_dir / str(project_id)
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return d / f"{kind}_{safe_component(p.name)}_{ts}.{ext}"

    def _register(self, project_id: int, path: Path, fmt: str, rtype: str = "hardware") -> Path:
        digest = sha256_file(path)
        rid = self.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                              " VALUES (?,?,?,?,?)", (project_id, rtype, fmt, str(path), digest))
        self.audit.record("report.generate", "tv_project", project_id, report_id=rid, format=fmt, type=rtype,
                          sha256=digest)
        return path

    # ---- data model shared by all formats --------------------------------------------
    def rows(self, project_id: int) -> list[dict]:
        out = []
        for c in self.hardware.list(project_id):
            row = {k: c.get(k) for k in EXPORT_COLUMNS if k in c}
            row["category"] = category_for(c["component_type"])
            row["facts"] = [{"attribute": f["attribute"], "value": f["value"], "unit": f["unit"],
                             "display": display_value(f["attribute"], f["value"], f["unit"]),
                             "source_type": f["source_type"], "source_reference": f["source_reference"],
                             "confidence": f["confidence"]} for f in self.hardware.facts(c["id"])]
            row["warnings"] = json.loads(c["analysis_warnings"] or "[]")
            out.append(row)
        return out

    # ---- exports ------------------------------------------------------------------------
    def export_json(self, project_id: int, path: Path | None = None) -> Path:
        path = Path(path or self._out(project_id, "json", "Hardware"))
        p = self.projects.get(project_id)
        payload = {"generator": f"{APP_NAME} {APP_VERSION}",
                   "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                   "project": {"id": p.id, "name": p.name, "manufacturer": p.manufacturer, "model": p.model_number,
                               "mainboard": p.mainboard},
                   "board_summary": self.hardware.board_summary(project_id),
                   "components": self.rows(project_id)}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return self._register(project_id, path, "json")

    def export_csv(self, project_id: int, path: Path | None = None) -> Path:
        """One row per specification fact (components without facts get one row) — keeps provenance."""
        path = Path(path or self._out(project_id, "csv", "Hardware"))
        cols = EXPORT_COLUMNS + ["fact_attribute", "fact_value", "fact_source_type", "fact_source_reference",
                                 "fact_confidence"]
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # BOM: Excel opens UTF-8 correctly
            w = csv.writer(fh)
            w.writerow(cols)
            for r in self.rows(project_id):
                base = [r.get(k) for k in EXPORT_COLUMNS]
                if not r["facts"]:
                    w.writerow(base + [""] * 5)
                for f in r["facts"]:
                    w.writerow(base + [f["attribute"], f["display"], f["source_type"], f["source_reference"],
                                       f["confidence"]])
        return self._register(project_id, path, "csv")

    def export_xlsx(self, project_id: int, path: Path | None = None) -> Path:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        path = Path(path or self._out(project_id, "xlsx", "Hardware"))
        wb = Workbook()
        ws = wb.active
        ws.title = "Components"
        ws.append(EXPORT_COLUMNS + ["warnings"])
        for r in self.rows(project_id):
            ws.append([r.get(k) for k in EXPORT_COLUMNS] + ["; ".join(r["warnings"])])
        fs = wb.create_sheet("Specifications")
        fs.append(["component_id", "part_number", "attribute", "value", "source_type", "source_reference",
                   "confidence"])
        for r in self.rows(project_id):
            for f in r["facts"]:
                fs.append([r["id"], r["part_number"], f["attribute"], f["display"], f["source_type"],
                           f["source_reference"], f["confidence"]])
        ss = wb.create_sheet("Board summary")
        for k, v in self.hardware.board_summary(project_id).items():
            ss.append([k, v["text"] if isinstance(v, dict) else ", ".join(v) if isinstance(v, list) else v])
        for sheet in (ws, fs, ss):
            for cell in sheet[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="1F3A5F")
            for col in sheet.columns:
                width = max(len(str(c.value or "")) for c in col)
                sheet.column_dimensions[col[0].column_letter].width = min(60, max(10, width + 2))
            sheet.freeze_panes = "A2"
        wb.save(path)
        return self._register(project_id, path, "xlsx")

    # ---- PDF ---------------------------------------------------------------------------
    def generate_pdf(self, project_id: int, path: Path | None = None) -> Path:
        path = Path(path or self._out(project_id, "pdf", "Hardware_Report"))
        p = self.projects.get(project_id)
        ss = getSampleStyleSheet()
        small = ParagraphStyle("s", parent=ss["BodyText"], fontSize=8, leading=10)
        mono = ParagraphStyle("m", parent=small, fontName="Courier", fontSize=7)
        warn = ParagraphStyle("w", parent=small, textColor=colors.HexColor("#8a5a00"))

        def table(rows, widths, header=True):
            t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
            st = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
            st += ([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)] if header
                   else [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef6"))])
            t.setStyle(TableStyle(st))
            return t

        now = _dt.datetime.now(_dt.timezone.utc)
        story = [Paragraph(f"{APP_NAME} &mdash; Hardware Report", ss["Title"]),
                 _p(f"Project #{p.id} {p.name} | {p.manufacturer or '?'} {p.model_number or ''} | generated "
                    f"{now.strftime('%Y-%m-%d %H:%M UTC')} | v{APP_VERSION}", small), Spacer(1, 4 * mm),
                 _p("Every specification value below lists its source: 'datasheet' (text of a datasheet in the local "
                    "library, with page), 'decoder' (vendor part-numbering scheme; confirm with datasheet), "
                    "'marking_rule' (numbering convention: vendor/family only) or 'user' (entered by the operator "
                    "with a reference). Values without evidence are reported as not identified.", small)]

        # 1. Motherboard / board summary
        story.append(Paragraph("1. Motherboard summary", ss["Heading2"]))
        s = self.hardware.board_summary(project_id)
        labels = SUMMARY_LABELS
        rows = []
        for key, label in labels:
            v = s[key]
            if isinstance(v, dict):
                v = v["text"] + ("\n" + "\n".join(v["chips"]) if v["chips"] else "")
            elif isinstance(v, list):
                v = "\n".join(v) or "—"
            rows.append([_p(label, small), Paragraph(escape(str(v)).replace("\n", "<br/>"), small)])
        story.append(table(rows, [40 * mm, 140 * mm], header=False))

        # 2. Chipset / component list
        story.append(Paragraph("2. Components", ss["Heading2"]))
        comps = self.rows(project_id)
        if not comps:
            story.append(_p("No components recorded. Confirm markings in the Visual Scanner or add components "
                            "in the Hardware Analyzer.", small))
        else:
            rows = [[_p(h, small) for h in ("#", "Board/pos.", "Category", "Part number", "Manufacturer", "Qty",
                                            "Identification", "Conf.")]]
            for r in comps:
                rows.append([_p(r["id"], small), _p(f"{r['board'] or ''} {r['position'] or ''}", small),
                             _p(CATEGORIES.get(r["category"], r["category"]), small), _p(r["part_number"], mono),
                             _p(r["manufacturer"] or "—", small), _p(r["quantity"], small),
                             _p(STATUS_TEXT.get(r["match_status"], r["match_status"]), small),
                             _p(f"{(r['confidence'] or 0):.0%}", small)])
            story.append(table(rows, [9 * mm, 22 * mm, 22 * mm, 32 * mm, 26 * mm, 9 * mm, 48 * mm, 12 * mm]))

        # 3. Details
        story.append(Paragraph("3. Component details", ss["Heading2"]))
        for r in comps:
            block = [Paragraph(escape(f"#{r['id']} {r['part_number'] or '(no part number)'} — "
                                      f"{CATEGORIES.get(r['category'], r['category'])}"), ss["Heading4"])]
            if r["facts"]:
                frows = [[_p(h, small) for h in ("Attribute", "Value", "Source", "Reference", "Conf.")]]
                for f in r["facts"]:
                    frows.append([_p(f["attribute"], small), _p(f["display"], small), _p(f["source_type"], small),
                                  _p(f["source_reference"], small), _p(f"{f['confidence']:.0%}", small)])
                block.append(table(frows, [28 * mm, 40 * mm, 20 * mm, 78 * mm, 12 * mm]))
            else:
                block.append(_p("No specification evidence.", small))
            for w in r["warnings"]:
                block.append(_p("WARNING: " + w, warn))
            if r["datasheet_id"]:
                ds = self.db.query_one("SELECT * FROM datasheets WHERE id=?", (r["datasheet_id"],))
                if ds:
                    block.append(_p(f"Datasheet #{ds['id']}: {ds['title'] or ds['original_filename']} "
                                    f"(SHA-256 {ds['sha256'][:16]}…; source: {ds['source_url'] or 'not recorded'})",
                                    small))
            if r["evidence_id"]:
                try:
                    ev = self.evidence.get(r["evidence_id"])
                    if ev.width and ev.height and Path(ev.stored_path).exists():
                        sc = min(70 * mm / ev.width, 45 * mm / ev.height, 1.0)
                        block.append(RLImage(ev.stored_path, width=ev.width * sc, height=ev.height * sc))
                        block.append(_p(f"Evidence #{ev.id} ({ev.original_filename}, SHA-256 {ev.sha256[:16]}…)", small))
                except Exception as exc:
                    block.append(_p(f"[evidence image unavailable: {exc}]", small))
            block.append(Spacer(1, 4 * mm))
            story.append(KeepTogether(block))

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.drawString(15 * mm, 10 * mm, f"{APP_NAME} — Hardware Report — project {p.id} — page {doc.page}")
            canvas.restoreState()

        SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                          bottomMargin=18 * mm, title=f"Hardware Report - {p.name}", author=APP_NAME
                          ).build(story, onFirstPage=footer, onLaterPages=footer)
        return self._register(project_id, path, "pdf")
