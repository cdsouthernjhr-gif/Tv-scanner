"""Report Center: the 10 technical reports of the specification in all 5 export formats.

Every report is first built as a format-neutral ``ReportDoc`` (sections of
key/value pairs, tables, text and evidence images). Renderers turn it into
HTML (self-contained, images embedded), JSON, CSV, XLSX and — for reports that
have no dedicated layout — PDF. Reports with a dedicated PDF layout (TV
identification, hardware, firmware analysis, OS, service menu, firmware search,
compatibility, upgrade) keep using it.

Every generated file is hashed and registered in ``technical_reports``.
"""
from __future__ import annotations

import base64
import csv
import datetime as _dt
import html
import io
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.core.config import APP_NAME, APP_VERSION
from app.modules.hardware_analyzer.decoders import format_bytes
from app.modules.hardware_analyzer.service import CATEGORIES, SUMMARY_LABELS, category_for
from app.modules.reports.hardware_report import STATUS_TEXT, display_value
from app.security.file_protection import safe_component
from app.security.hashing import sha256_file

REPORT_TYPES = {
    "tv_identification": ("TV Identification Report", "project"),
    "hardware": ("Hardware Report", "project"),
    "motherboard": ("Motherboard Report", "project"),
    "chipset": ("Chipset Report", "project"),
    "firmware_analysis": ("Firmware Analysis Report", "firmware"),
    "operating_system": ("Operating System Report", "project"),
    "service_menu": ("Service Menu Report", "project"),
    "firmware_search": ("Firmware Search Report", "search_session"),
    "firmware_compatibility": ("Firmware Compatibility Report", "compatibility"),
    "firmware_upgrade": ("Firmware Upgrade Report", "upgrade_session"),
}
FORMATS = ("pdf", "xlsx", "csv", "json", "html")


@dataclass
class Section:
    heading: str
    kind: str                         # kv | table | text | images
    data: object
    note: str = ""


@dataclass
class ReportDoc:
    report_type: str
    title: str
    subject: str
    project_id: int | None
    generated_at: str
    sections: list[Section] = field(default_factory=list)

    def kv(self, heading, pairs, note=""):
        self.sections.append(Section(heading, "kv", [[str(k), "" if v is None else str(v)] for k, v in pairs], note))

    def table(self, heading, columns, rows, note=""):
        self.sections.append(Section(heading, "table", {"columns": list(columns),
                                                        "rows": [["" if c is None else str(c) for c in r] for r in rows]},
                                     note))

    def text(self, heading, text, note=""):
        self.sections.append(Section(heading, "text", str(text), note))

    def images(self, heading, items, note=""):
        self.sections.append(Section(heading, "images", items, note))


class ReportCenter:
    def __init__(self, ctx):
        self.ctx = ctx

    # ---- builders ----------------------------------------------------------------------------------
    def _doc(self, rtype, subject, pid) -> ReportDoc:
        return ReportDoc(rtype, REPORT_TYPES[rtype][0], subject, pid,
                         _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    def _project_kv(self, d: ReportDoc, pid: int):
        p = self.ctx.projects.get(pid)
        d.kv("TV", [("Project", f"#{p.id} {p.name}"), ("Manufacturer", p.manufacturer), ("Model", p.model_number),
                    ("Serial number", p.serial_number), ("Product code", p.product_code), ("Chassis", p.chassis),
                    ("Mainboard", p.mainboard), ("PCB revision", p.pcb_revision), ("Panel", p.panel_model),
                    ("Screen size (in)", p.screen_size_inches), ("Platform", p.platform),
                    ("Firmware version", p.firmware_version), ("Identification status", p.identification_status),
                    ("Identification confidence", f"{p.identification_confidence:.0%}"),
                    ("Data source", p.identification_source)],
             note="Empty values were not determined; 'manual' values are not independently verified.")
        return p

    def build(self, rtype: str, subject_id: int) -> ReportDoc:
        if rtype not in REPORT_TYPES:
            raise ValueError(f"unknown report type {rtype}")
        return getattr(self, "_b_" + rtype)(subject_id)

    def _b_tv_identification(self, pid):
        d = self._doc("tv_identification", f"project #{pid}", pid)
        self._project_kv(d, pid)
        evs = self.ctx.evidence.list_for_project(pid)
        d.images("Evidence images", [{"path": e.stored_path, "caption": f"#{e.id} {e.evidence_type} — {e.original_filename} "
                                      f"(SHA-256 {e.sha256[:16]}…)"} for e in evs])
        cands = self.ctx.identification.candidates(pid)
        d.table("Identification candidates", ["Field", "Value", "Confidence", "Method", "Evidence", "Status"],
                [[c["field"], c["value"], f"{c['confidence']:.0%}", c["method"], c["evidence_id"], c["status"]] for c in cands],
                note="Only 'accepted' values were applied to the project.")
        fws = self.ctx.library.list(project_id=pid)
        d.table("Firmware of this TV", ["ID", "File", "Category", "Format", "Size", "Integrity", "SHA-256"],
                [[f.id, f.original_filename, f.category, f.detected_format, f.file_size, f.verification_status, f.sha256]
                 for f in fws])
        return d

    def _components_rows(self, pid, cats=None, board=None):
        rows = []
        for c in self.ctx.hardware.list(pid):
            cat = category_for(c["component_type"])
            if (cats and cat not in cats) or (board and c["board"] != board):
                continue
            facts = self.ctx.hardware.facts(c["id"])
            spec = "; ".join(f"{f['attribute']}={display_value(f['attribute'], f['value'], f['unit'])} [{f['source_type']}]"
                             for f in facts)
            rows.append([c["id"], c["board"], c["position"], CATEGORIES.get(cat, cat), c["part_number"], c["manufacturer"],
                         c["quantity"], STATUS_TEXT.get(c["match_status"], c["match_status"]), f"{(c['confidence'] or 0):.0%}",
                         spec, c["evidence_id"], c["source_reference"]])
        return rows

    COMP_COLS = ["ID", "Board", "Position", "Category", "Part number", "Manufacturer", "Qty", "Identification",
                 "Confidence", "Specification (source)", "Evidence", "Source reference"]

    def _summary_pairs(self, pid):
        s = self.ctx.hardware.board_summary(pid)
        out = []
        for k, label in SUMMARY_LABELS:
            v = s[k]
            out.append((label, v["text"] if isinstance(v, dict) else "; ".join(v) if isinstance(v, list) else v))
        return out

    def _b_hardware(self, pid):
        d = self._doc("hardware", f"project #{pid}", pid)
        self._project_kv(d, pid)
        d.kv("Board summary", self._summary_pairs(pid),
             note="Totals only when every chip of the class has capacity evidence.")
        d.table("Components", self.COMP_COLS, self._components_rows(pid))
        return d

    def _b_motherboard(self, pid):
        d = self._doc("motherboard", f"project #{pid}", pid)
        p = self.ctx.projects.get(pid)
        d.kv("Mainboard", [("Mainboard", p.mainboard or "not identified"), ("PCB revision", p.pcb_revision or "not identified"),
                           ("Chassis", p.chassis or "not identified")] +
             [x for x in self._summary_pairs(pid) if x[0] not in ("Mainboard", "PCB revision")])
        d.table("Components on the mainboard", self.COMP_COLS, self._components_rows(pid, board="mainboard"))
        d.table("Other boards (PSU, T-Con, panel)", self.COMP_COLS,
                [r for r in self._components_rows(pid) if r[1] in ("power_supply", "tcon", "panel")])
        return d

    def _b_chipset(self, pid):
        d = self._doc("chipset", f"project #{pid}", pid)
        d.table("Chipsets and memory", self.COMP_COLS,
                self._components_rows(pid, cats={"soc", "gpu", "ram", "flash", "wifi", "bluetooth", "wifi_bt", "audio", "tcon"}))
        rows = []
        for c in self.ctx.hardware.list(pid):
            for f in self.ctx.hardware.facts(c["id"]):
                rows.append([c["part_number"], f["attribute"], display_value(f["attribute"], f["value"], f["unit"]),
                             f["source_type"], f["source_reference"], f"{f['confidence']:.0%}"])
        d.table("Specification facts", ["Part", "Attribute", "Value", "Source", "Reference", "Confidence"], rows,
                note="decoder = vendor part-numbering scheme (confirm with datasheet); datasheet = local datasheet text.")
        return d

    def _b_firmware_analysis(self, fid):
        data = self.ctx.firmware_reports.data(fid)
        fw, run = data["firmware"], data["run"]
        d = self._doc("firmware_analysis", f"firmware #{fid}", fw["project_id"])
        d.kv("File and integrity", [("File", fw["original_filename"]), ("Size", f"{fw['file_size']:,} B"),
                                    ("SHA-256", fw["sha256"]), ("Category", fw["category"]),
                                    ("Analysis run", f"#{run['id']} {run['status']} {run['started_at']}"),
                                    ("Original unchanged", {1: "YES (SHA-256 identical before/after)", 0: "NO"}.get(
                                        run["original_unchanged"], "n/a"))])
        d.table("Metadata", ["Attribute", "Value", "Source", "Confidence"],
                [[m["attribute"], m["value"], m["source"], f"{m['confidence']:.0%}"] for m in data["metadata"]])
        d.table("Components", ["Offset", "Size", "Type", "Category", "Validated", "Source", "Description"],
                [[hex(c["offset"]), c["size"], c["type"], c["category"], "yes" if c["validated"] else "-", c["source"],
                  c["description"]] for c in data["components"]])
        ent = data["entropy"] or {}
        d.text("Entropy / encryption indicators", "\n".join(ent.get("indicators") or ["none"]) +
               f"\nOverall entropy {ent.get('overall')} bits/byte, chi-square {ent.get('chi_square')}")
        d.table("Extraction", ["Offset", "Type", "Status", "Method", "Files", "Note"],
                [[hex(e["offset"]), e["component_type"], e["status"], e["method"], e["files"], e["message"]]
                 for e in (data["extraction"] or [])])
        d.table("Extracted files", ["Path", "Size", "Kind", "SHA-256"],
                [[f["rel_path"], f["size"], f["kind"], f["sha256"]] for f in data["files"][:5000]])
        return d

    def _b_operating_system(self, pid):
        d = self._doc("operating_system", f"project #{pid}", pid)
        s = self.ctx.software.summary(pid)
        rows = []
        for cat in ("os", "os_version", "kernel", "build", "firmware_version", "bootloader", "device_info"):
            for v in s.get(cat) or [{"value": "not determined", "confidence": 0, "sources": []}]:
                rows.append([cat, v["value"], f"{v['confidence']:.0%}", " | ".join(v["sources"])])
        d.table("Summary", ["Item", "Value", "Confidence", "Sources"], rows)
        if s["conflicts"]:
            d.text("Conflicts", "\n".join(s["conflicts"]))
        d.table("All software facts", ["Category", "Name", "Detail", "Source", "Reference", "Confidence"],
                [[f["category"], f["name"], f["value"], f["source_type"], f["source_ref"], f"{f['confidence']:.0%}"]
                 for f in self.ctx.software.facts(pid)])
        d.table("Device sessions", ["ID", "Connector", "Target", "Authorisation", "Status", "Time"],
                [[x["id"], x["connector"], x["target"], x["authorization_note"], x["status"], x["started_at"]]
                 for x in self.ctx.software.device_sessions(pid)])
        return d

    def _b_service_menu(self, pid):
        d = self._doc("service_menu", f"project #{pid}", pid)
        recs = self.ctx.service_menus.applicable(self.ctx.projects.get(pid))
        d.table("Applicable documented menus", ["ID", "Category", "Access", "Function", "Availability", "Risk", "Backup",
                                                "Documentation", "Applies because"],
                [[r["id"], r["menu_category"], r["access_procedure"], r["function_description"], r["access_availability"],
                  r["configuration_risk"], r["backup_mechanism"], r["official_documentation"], r["applies_because"]]
                 for r in recs], note="Only manufacturer-documented procedures; the application never changes TV settings.")
        d.table("Service actions", ["ID", "Setting", "Old", "New", "Status", "Backup", "Confirmed by", "Confirmed at", "Result"],
                [[a["id"], a["setting"], a["old_value"], a["new_value"], a["status"], a["backup_evidence"], a["confirmed_by"],
                  a["confirmed_at"], a["result"]] for a in self.ctx.service_menus.actions(pid)])
        return d

    def _b_firmware_search(self, sid):
        sess = [s for s in self.ctx.finder.sessions() if s["id"] == sid]
        if not sess:
            raise KeyError(sid)
        s = sess[0]
        d = self._doc("firmware_search", f"search #{sid}", s["project_id"])
        crit = json.loads(s["criteria_json"])
        d.kv("Search", [("Started", s["started_at"]), ("Finished", s["finished_at"]), ("Providers", s["providers"]),
                        ("Results", s["result_count"])] +
             [(k, f"{v} ({(crit.get('sources') or {}).get(k, '')})") for k, v in crit.items() if v and k != "sources"])
        from app.modules.reports.search_report import COLUMNS
        d.table("Results", COLUMNS, [[r.get(c) for c in COLUMNS] for r in self.ctx.finder.results(sid)],
                note="A search result is not a verified firmware.")
        return d

    def _b_firmware_compatibility(self, cid):
        c = self.ctx.compatibility.get(cid)
        d = self._doc("firmware_compatibility", f"compatibility #{cid}", c["project_id"])
        d.kv("Result", [("Verdict", c["verdict"]), ("Score", int(c["score"] or 0)), ("Candidate firmware", c["firmware_id"]),
                        ("Baseline firmware", c["baseline_firmware_id"]), ("Time", c["created_at"])])
        d.text("Reasons", "\n".join(c["reasons"]))
        d.table("Criteria", ["Criterion", "TV", "Firmware", "Status", "Hard", "Evidence"],
                [[x["criterion"], x["tv_value"], x["fw_value"], x["status"], "yes" if x["hard"] else "", x["evidence"]]
                 for x in c["criteria"]])
        return d

    def _b_firmware_upgrade(self, sid):
        s = self.ctx.upgrades.session(sid)
        prof = self.ctx.upgrades.profile(s["profile_id"])
        d = self._doc("firmware_upgrade", f"upgrade session #{sid}", s["project_id"])
        d.kv("Session", [("Method", prof["method"]), ("Profile verified", f"{bool(prof['verified'])} {prof['verified_by'] or ''}"),
                         ("Documentation", prof["documentation_ref"]), ("Target firmware", s["target_firmware_id"]),
                         ("From version", s["source_firmware_version"]), ("Status", s["status"]),
                         ("Executable", bool(s["executable"]))])
        d.table("Steps", ["Step", "Status", "Details"],
                [[k, v.get("status"), json.dumps({x: y for x, y in v.items() if x != "status"}, default=str)[:3000]]
                 for k, v in s["steps"].items()])
        d.text("Log", s["log"] or "")
        return d

    # ---- renderers --------------------------------------------------------------------------------------
    @staticmethod
    def render_json(doc: ReportDoc, path: Path) -> None:
        payload = {"generator": f"{APP_NAME} {APP_VERSION}", **asdict(doc)}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    @staticmethod
    def render_csv(doc: ReportDoc, path: Path) -> None:
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow([doc.title, doc.subject, doc.generated_at, f"{APP_NAME} {APP_VERSION}"])
            for s in doc.sections:
                w.writerow([])
                w.writerow([f"## {s.heading}"] + ([s.note] if s.note else []))
                if s.kind == "kv":
                    w.writerows(s.data)
                elif s.kind == "table":
                    w.writerow(s.data["columns"])
                    w.writerows(s.data["rows"])
                elif s.kind == "text":
                    for line in str(s.data).splitlines():
                        w.writerow([line])
                elif s.kind == "images":
                    for im in s.data:
                        w.writerow([im["caption"], im["path"]])

    @staticmethod
    def render_xlsx(doc: ReportDoc, path: Path) -> None:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        wb = Workbook()
        info = wb.active
        info.title = "Report"
        for row in ([doc.title], ["Subject", doc.subject], ["Generated", doc.generated_at],
                    ["Generator", f"{APP_NAME} {APP_VERSION}"]):
            info.append(row)
        info["A1"].font = Font(bold=True, size=14)
        used = {"Report"}
        for s in doc.sections:
            name = "".join(ch for ch in s.heading if ch not in "[]:*?/\\")[:28] or "Section"
            base, i = name, 2
            while name in used:
                name = f"{base[:25]} {i}"
                i += 1
            used.add(name)
            ws = wb.create_sheet(name)
            header = None
            if s.kind == "kv":
                header = ["Item", "Value"]
                rows = s.data
            elif s.kind == "table":
                header, rows = s.data["columns"], s.data["rows"]
            elif s.kind == "images":
                header, rows = ["Caption", "Stored path"], [[im["caption"], im["path"]] for im in s.data]
            else:
                rows = [[ln] for ln in str(s.data).splitlines()] or [[""]]
            if header:
                ws.append(header)
                for c in ws[1]:
                    c.font = Font(bold=True, color="FFFFFF")
                    c.fill = PatternFill("solid", fgColor="1F3A5F")
                ws.freeze_panes = "A2"
            for r in rows:
                ws.append([str(x)[:32000] for x in r])
            if s.note:
                ws.append([])
                ws.append([s.note])
            for col in ws.columns:
                width = max((len(str(c.value or "")) for c in col), default=8)
                ws.column_dimensions[col[0].column_letter].width = min(70, max(10, width + 2))
        wb.save(path)

    @staticmethod
    def _img_data_uri(path: str) -> str | None:
        try:
            from PIL import Image
            with Image.open(path) as im:
                im = im.convert("RGB")
                im.thumbnail((900, 900))
                buf = io.BytesIO()
                im.save(buf, "JPEG", quality=82)
            return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
        except Exception:
            return None

    def render_html(self, doc: ReportDoc, path: Path) -> None:
        e = html.escape
        out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
               "<meta name='viewport' content='width=device-width, initial-scale=1'>",
               f"<title>{e(doc.title)}</title><style>",
               ":root{--bg:#fff;--fg:#1b1f24;--muted:#5b6573;--line:#d8dee6;--head:#1f3a5f;--note:#7a5a00}",
               "@media (prefers-color-scheme: dark){:root{--bg:#14181f;--fg:#e6e9ef;--muted:#9aa6b8;--line:#2c3647;--head:#2b5797;--note:#f0d48a}}",
               "body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0 auto;max-width:1200px;padding:24px 16px}",
               "h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:2px solid var(--line);padding-bottom:4px}",
               ".meta,.note{color:var(--muted)}.note{color:var(--note);font-size:13px}",
               ".wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}",
               "th{background:var(--head);color:#fff;text-align:left}th,td{border:1px solid var(--line);padding:4px 6px;vertical-align:top}",
               "td{word-break:break-word}pre{white-space:pre-wrap;background:rgba(127,127,127,.08);padding:8px;border-radius:6px}",
               "figure{display:inline-block;margin:8px;max-width:420px}figure img{max-width:100%;border:1px solid var(--line)}",
               "figcaption{font-size:12px;color:var(--muted)}</style></head><body>",
               f"<h1>{e(doc.title)}</h1><div class='meta'>{e(doc.subject)} · generated {e(doc.generated_at)} · "
               f"{e(APP_NAME)} {e(APP_VERSION)}</div>"]
        for s in doc.sections:
            out.append(f"<h2>{e(s.heading)}</h2>")
            if s.note:
                out.append(f"<p class='note'>{e(s.note)}</p>")
            if s.kind == "kv":
                out.append("<div class='wrap'><table>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>"
                                                                for k, v in s.data) + "</table></div>")
            elif s.kind == "table":
                if not s.data["rows"]:
                    out.append("<p class='meta'>No entries.</p>")
                    continue
                out.append("<div class='wrap'><table><tr>" + "".join(f"<th>{e(c)}</th>" for c in s.data["columns"]) + "</tr>")
                for r in s.data["rows"]:
                    out.append("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>")
                out.append("</table></div>")
            elif s.kind == "text":
                out.append(f"<pre>{e(str(s.data))}</pre>")
            elif s.kind == "images":
                if not s.data:
                    out.append("<p class='meta'>No evidence images.</p>")
                for im in s.data:
                    uri = self._img_data_uri(im["path"])
                    body = f"<img alt='{e(im['caption'])}' src='{uri}'>" if uri else "<p>[image unavailable]</p>"
                    out.append(f"<figure>{body}<figcaption>{e(im['caption'])}</figcaption></figure>")
        out.append("</body></html>")
        path.write_text("\n".join(out), encoding="utf-8")

    def render_pdf_generic(self, doc: ReportDoc, path: Path) -> None:
        from xml.sax.saxutils import escape
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        ss = getSampleStyleSheet()
        sm = ParagraphStyle("s", parent=ss["BodyText"], fontSize=7, leading=9)
        P = lambda t: Paragraph(escape(str(t))[:3000], sm)      # noqa: E731
        width = 277 * mm
        story = [Paragraph(f"{APP_NAME} &mdash; {escape(doc.title)}", ss["Title"]),
                 P(f"{doc.subject} | {doc.generated_at} | v{APP_VERSION}"), Spacer(1, 3 * mm)]
        for s in doc.sections:
            story.append(Paragraph(escape(s.heading), ss["Heading2"]))
            if s.note:
                story.append(P(s.note))
            if s.kind in ("kv", "table", "images"):
                if s.kind == "kv":
                    cols, rows = ["Item", "Value"], s.data
                elif s.kind == "table":
                    cols, rows = s.data["columns"], s.data["rows"][:1000]
                else:
                    cols, rows = ["Caption", "Stored path"], [[i["caption"], i["path"]] for i in s.data]
                if not rows:
                    story.append(P("No entries."))
                    continue
                t = Table([[P(c) for c in cols]] + [[P(c) for c in r] for r in rows],
                          colWidths=[width / len(cols)] * len(cols), repeatRows=1)
                t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                                       ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
                story.append(t)
            else:
                for line in str(s.data).splitlines()[:400]:
                    story.append(P(line))
        SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm, topMargin=10 * mm,
                          bottomMargin=10 * mm, title=doc.title, author=APP_NAME).build(story)

    # ---- entry point -------------------------------------------------------------------------------------
    def _dedicated_pdf(self, rtype, sid):
        c = self.ctx
        return {"tv_identification": lambda: c.reports.generate_identification_report(sid),
                "hardware": lambda: c.hardware_reports.generate_pdf(sid),
                "firmware_analysis": lambda: c.firmware_reports.generate_pdf(sid),
                "operating_system": lambda: c.software_reports.os_report_pdf(sid),
                "service_menu": lambda: c.software_reports.service_report_pdf(sid),
                "firmware_search": lambda: c.search_reports.generate_pdf(sid),
                "firmware_compatibility": lambda: c.upgrade_reports.compatibility_pdf(sid),
                "firmware_upgrade": lambda: c.upgrade_reports.upgrade_pdf(sid)}.get(rtype)

    def generate(self, rtype: str, subject_id: int, fmt: str) -> Path:
        fmt = fmt.lower()
        if fmt not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        if fmt == "pdf" and self._dedicated_pdf(rtype, subject_id):
            return self._dedicated_pdf(rtype, subject_id)()     # registers itself
        doc = self.build(rtype, subject_id)
        d = self.ctx.config.reports_dir / (str(doc.project_id) if doc.project_id else "general")
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        path = d / f"{safe_component(doc.title.replace(' ', '_'))}_{safe_component(doc.subject.replace(' ', '_'))}_{ts}.{fmt}"
        {"json": self.render_json, "csv": self.render_csv, "xlsx": self.render_xlsx, "html": self.render_html,
         "pdf": self.render_pdf_generic}[fmt](doc, path)
        digest = sha256_file(path)
        rid = self.ctx.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                                  " VALUES (?,?,?,?,?)", (doc.project_id, rtype, fmt, str(path), digest))
        self.ctx.audit.record("report.generate", "technical_report", rid, type=rtype, format=fmt, subject=doc.subject)
        return path

    def subjects(self, rtype: str) -> list[tuple[int, str]]:
        """Choices for the subject of a report type (id, label)."""
        kind = REPORT_TYPES[rtype][1]
        c = self.ctx
        if kind == "project":
            return [(p.id, f"#{p.id} {p.name} — {p.manufacturer or '?'} {p.model_number or ''}") for p in c.projects.list()]
        if kind == "firmware":
            return [(f.id, f"#{f.id} {f.original_filename}") for f in c.library.list() if c.firmware.latest_run(f.id)]
        if kind == "search_session":
            return [(s["id"], f"search #{s['id']} {s['started_at']} ({s['result_count']} results)") for s in c.finder.sessions()]
        if kind == "compatibility":
            return [(r["id"], f"#{r['id']} firmware #{r['firmware_id']} {r['verdict']}")
                    for r in c.db.query("SELECT * FROM firmware_compatibility ORDER BY id DESC")]
        return [(r["id"], f"session #{r['id']} {r['method']} {r['status']}")
                for r in c.db.query("SELECT * FROM firmware_upgrade_sessions ORDER BY id DESC")]
