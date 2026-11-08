"""Firmware Analysis Report (PDF + JSON)."""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, PolyLine, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import APP_NAME, APP_VERSION, AppConfig
from app.database.connection import Database
from app.modules.firmware_analyzer.service import FirmwareAnalyzer
from app.modules.firmware_library.library import FirmwareLibrary
from app.security.audit import AuditLogger
from app.security.file_protection import safe_component
from app.security.hashing import sha256_file

CAT_COLORS = {"filesystem": "#2e7d32", "kernel": "#c62828", "bootloader": "#6a1b9a", "compressed": "#1565c0",
              "archive": "#00838f", "executable": "#ef6c00", "devicetree": "#5d4037", "partition_table": "#37474f",
              "image": "#ad1457", "signature": "#f9a825"}


def _p(t, st):
    return Paragraph(escape("" if t is None else str(t)), st)


def structure_drawing(file_size: int, components: list[dict], entropy_blocks: list[float], width: float,
                      height: float = 60 * mm) -> Drawing:
    """Top: entropy curve (0–8). Bottom: top-level components as coloured bars along the file."""
    d = Drawing(width, height)
    plot_h = height * 0.55
    bar_y, bar_h = 6, height * 0.25
    d.add(Rect(0, bar_y + bar_h + 8, width, plot_h, fillColor=colors.HexColor("#f4f6f9"), strokeColor=colors.grey,
               strokeWidth=0.3))
    base = bar_y + bar_h + 8
    if entropy_blocks:
        n = len(entropy_blocks)
        pts = []
        for i, e in enumerate(entropy_blocks):
            pts += [width * i / max(1, n - 1), base + plot_h * e / 8.0]
        d.add(PolyLine(pts, strokeColor=colors.HexColor("#1f3a5f"), strokeWidth=0.8))
        y79 = base + plot_h * 7.9 / 8
        d.add(Line(0, y79, width, y79, strokeColor=colors.red, strokeWidth=0.3, strokeDashArray=[2, 2]))
        d.add(String(2, y79 + 2, "7.9 (compressed/encrypted)", fontSize=5, fillColor=colors.red))
    d.add(Rect(0, bar_y, width, bar_h, fillColor=colors.HexColor("#eeeeee"), strokeColor=colors.grey, strokeWidth=0.3))
    for c in components:
        if c["source"] != "native" or c["details"].get("parent_offset") is not None or not file_size:
            continue
        size = c["size"] or max(1, file_size // 400)
        x = width * c["offset"] / file_size
        w = max(0.8, width * size / file_size)
        d.add(Rect(x, bar_y, min(w, width - x), bar_h, strokeWidth=0,
                   fillColor=colors.HexColor(CAT_COLORS.get(c["category"], "#9e9e9e"))))
    d.add(String(0, 0, "0x0", fontSize=5))
    d.add(String(width - 30, 0, f"{file_size:#x}", fontSize=5))
    return d


class FirmwareReportGenerator:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger, library: FirmwareLibrary,
                 firmware: FirmwareAnalyzer):
        self.config, self.db, self.audit, self.library, self.firmware = config, db, audit, library, firmware

    def _run(self, firmware_id: int, run_id: int | None) -> dict:
        run = (dict(self.db.query_one("SELECT * FROM firmware_analysis_runs WHERE id=?", (run_id,)))
               if run_id else self.firmware.latest_run(firmware_id))
        if not run:
            raise ValueError("Firmware has not been analysed yet")
        return run

    def _out(self, rec, ext: str) -> Path:
        d = self.config.reports_dir / ("firmware_" + str(rec.id))
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return d / f"Firmware_Analysis_{safe_component(Path(rec.original_filename).stem)}_{ts}.{ext}"

    def _register(self, rec, path: Path, fmt: str, rtype: str = "firmware_analysis") -> Path:
        digest = sha256_file(path)
        rid = self.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                              " VALUES (?,?,?,?,?)", (rec.project_id, rtype, fmt, str(path), digest))
        self.audit.record("report.generate", "firmware_file", rec.id, report_id=rid, format=fmt, sha256=digest)
        return path

    def data(self, firmware_id: int, run_id: int | None = None) -> dict:
        rec = self.library.get(firmware_id)
        run = self._run(firmware_id, run_id)
        F = self.firmware
        rid = run["id"]
        return {"generator": f"{APP_NAME} {APP_VERSION}",
                "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "firmware": asdict(rec), "run": run, "metadata": F.metadata(rid), "components": F.components(rid),
                "signature_scan": F.result(rid, "signature_scan"), "entropy": F.result(rid, "entropy"),
                "strings": F.result(rid, "strings"), "binwalk": F.result(rid, "binwalk"),
                "extraction": F.result(rid, "extraction"), "config_discovery": F.result(rid, "config_discovery"),
                "files": F.files(rid), "ghidra": F.result(rid, "ghidra")}

    def export_json(self, firmware_id: int, run_id: int | None = None) -> Path:
        rec = self.library.get(firmware_id)
        path = self._out(rec, "json")
        path.write_text(json.dumps(self.data(firmware_id, run_id), indent=2, default=str, ensure_ascii=False),
                        encoding="utf-8")
        return self._register(rec, path, "json")

    def generate_pdf(self, firmware_id: int, run_id: int | None = None) -> Path:
        d = self.data(firmware_id, run_id)
        rec = self.library.get(firmware_id)
        path = self._out(rec, "pdf")
        ss = getSampleStyleSheet()
        sm = ParagraphStyle("s", parent=ss["BodyText"], fontSize=8, leading=10)
        mono = ParagraphStyle("m", parent=sm, fontName="Courier", fontSize=7)
        W = 180 * mm

        def table(rows, widths, header=True):
            t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
            st = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
            st += ([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)] if header
                   else [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef6"))])
            t.setStyle(TableStyle(st))
            return t

        run = d["run"]
        story = [Paragraph(f"{APP_NAME} &mdash; Firmware Analysis Report", ss["Title"]),
                 _p(f"Generated {d['generated_at']} | v{APP_VERSION} | analysis run #{run['id']} "
                    f"({run['status']}, {run['started_at']} to {run['finished_at']})", sm), Spacer(1, 3 * mm)]
        story.append(Paragraph("1. File and integrity", ss["Heading2"]))
        unchanged = {1: "YES — SHA-256 identical before and after analysis", 0: "NO — investigate immediately",
                     None: "not recorded"}[run["original_unchanged"]]
        rows = [("File", rec.original_filename), ("Size", f"{rec.file_size:,} bytes"), ("SHA-256", rec.sha256),
                ("Library copy", rec.stored_path), ("Category / source", f"{rec.category} / {rec.download_url or 'local import'}"),
                ("Manufacturer / model / board", f"{rec.manufacturer or '?'} / {rec.model_number or '?'} / {rec.mainboard or '?'}"),
                ("Original unchanged", unchanged), ("Analysed copy", run["working_copy"])]
        story.append(table([[_p(k, sm), _p(v, mono if k == "SHA-256" else sm)] for k, v in rows],
                           [45 * mm, 135 * mm], header=False))

        story.append(Paragraph("2. Structure and entropy", ss["Heading2"]))
        ent = d["entropy"] or {}
        story.append(structure_drawing(rec.file_size, d["components"], ent.get("blocks", []), W))
        story.append(_p("Upper plot: Shannon entropy per block (0–8 bits/byte). Lower bar: top-level components "
                        "(green filesystem, red kernel, purple bootloader, blue compressed, teal archive, orange "
                        "executable, grey other).", sm))
        if ent:
            story.append(_p(f"Overall entropy {ent['overall']} bits/byte, chi-square {ent['chi_square']}, "
                            f"block size {ent['block_size']:,} B.", sm))
        for ind in ent.get("indicators", []):
            story.append(_p("ENCRYPTION INDICATOR: " + ind, sm))

        story.append(Paragraph("3. Metadata (each value with its source)", ss["Heading2"]))
        if d["metadata"]:
            rows = [[_p(h, sm) for h in ("Attribute", "Value", "Source", "Conf.")]]
            for m in d["metadata"]:
                rows.append([_p(m["attribute"], sm), _p(m["value"][:300], sm), _p(m["source"][:200], sm),
                             _p(f"{m['confidence']:.0%}", sm)])
            story.append(table(rows, [32 * mm, 62 * mm, 72 * mm, 14 * mm]))
        else:
            story.append(_p("No metadata could be established.", sm))

        story.append(Paragraph("4. Embedded components", ss["Heading2"]))
        native = [c for c in d["components"] if c["source"] == "native"]
        rows = [[_p(h, sm) for h in ("Offset", "Size", "Type", "Validated", "Description")]]
        for c in native[:300]:
            depth = "  " if c["details"].get("parent_offset") is not None else ""
            rows.append([_p(f"{c['offset']:#x}", mono), _p(f"{c['size']:,}" if c["size"] else "?", sm),
                         _p(depth + c["type"], sm), _p("yes" if c["validated"] else "plausible", sm),
                         _p(c["description"][:200], sm)])
        story.append(table(rows, [22 * mm, 22 * mm, 22 * mm, 16 * mm, 98 * mm]))
        if len(native) > 300:
            story.append(_p(f"… {len(native) - 300} more components in the JSON export.", sm))
        sc = d["signature_scan"] or {}
        story.append(_p(f"Candidates rejected by validation: {sc.get('rejected_candidates')}. "
                        f"Binwalk: {d['binwalk']}", sm))

        story.append(Paragraph("5. Extraction (workspace only)", ss["Heading2"]))
        ex = d["extraction"] or []
        if ex:
            rows = [[_p(h, sm) for h in ("Offset", "Type", "Status", "Method", "Files", "Note")]]
            for e in ex:
                rows.append([_p(f"{e['offset']:#x}", mono), _p(e["component_type"], sm), _p(e["status"], sm),
                             _p(e["method"], sm), _p(e["files"], sm),
                             _p((e["message"] + (f" {len(e['skipped_links'])} link(s) not created." if e["skipped_links"] else ""))[:200], sm)])
            story.append(table(rows, [22 * mm, 20 * mm, 18 * mm, 28 * mm, 12 * mm, 80 * mm]))
        else:
            story.append(_p("Extraction was not performed.", sm))
        cd = d["config_discovery"] or {}
        if cd.get("sensitive_files"):
            story.append(_p("Sensitive material present (contents not reproduced): " +
                            ", ".join(cd["sensitive_files"][:40]), sm))
        if cd.get("config_files"):
            story.append(_p(f"Configuration files ({len(cd['config_files'])}): " + ", ".join(cd["config_files"][:60]), mono))

        st = d["strings"] or {}
        if st:
            story.append(Paragraph("6. Strings of interest", ss["Heading2"]))
            story.append(_p(f"{st['total']:,} printable strings (6+ chars). Full list: {st.get('dump_path')}", sm))
            rows = [[_p(h, sm) for h in ("Category", "Offset", "Value")]]
            for cat in ("kernel_version", "uboot_version", "busybox_version", "toolchain", "android_property",
                        "firmware_version", "build_date", "partition_name", "url", "crypto_keyword"):
                for h in st["hits"].get(cat, [])[:8]:
                    rows.append([_p(cat, sm), _p(f"{h['offset']:#x}", mono), _p(h["value"][:150], mono)])
            if len(rows) > 1:
                story.append(table(rows, [32 * mm, 22 * mm, 126 * mm]))
        if d["ghidra"]:
            g = d["ghidra"]
            story.append(Paragraph("7. Ghidra (headless) summary", ss["Heading2"]))
            story.append(_p(json.dumps(g.get("summary") or {"error": g.get("log_tail", "")[-400:]})[:3000], mono))

        story += [PageBreak(), Paragraph("Notes", ss["Heading2"]),
                  _p("Findings describe the file's structure; they do not establish that the firmware is authentic or "
                     "compatible with any TV. Encryption statements are indicators based on entropy and the absence of "
                     "recognised formats. Version values carry the source they were read from; file-name based values "
                     "are the weakest evidence.", sm)]

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.drawString(15 * mm, 10 * mm, f"{APP_NAME} — Firmware Analysis — {rec.original_filename} — "
                                                 f"page {doc.page}")
            canvas.restoreState()
        SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                          bottomMargin=18 * mm, title=f"Firmware Analysis - {rec.original_filename}",
                          author=APP_NAME).build(story, onFirstPage=footer, onLaterPages=footer)
        return self._register(rec, path, "pdf")
