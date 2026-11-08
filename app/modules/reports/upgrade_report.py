"""Firmware Compatibility Report and Firmware Upgrade Report (PDF + JSON)."""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import APP_NAME, APP_VERSION
from app.security.file_protection import safe_component
from app.security.hashing import sha256_file

VERDICT_COLOR = {"VERIFIED COMPATIBLE": "#2e7d32", "LIKELY COMPATIBLE": "#558b2f", "POSSIBLE MATCH": "#f9a825",
                 "INCOMPATIBLE": "#c62828", "INSUFFICIENT EVIDENCE": "#616161"}


def _p(t, st):
    return Paragraph(escape("" if t is None else str(t)), st)


def _table(rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
    return t


class UpgradeReportGenerator:
    def __init__(self, ctx):
        self.ctx = ctx

    def _out(self, pid, kind, ext):
        p = self.ctx.projects.get(pid)
        d = self.ctx.config.reports_dir / str(pid)
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return d / f"{kind}_{safe_component(p.name)}_{ts}.{ext}"

    def _register(self, pid, path, rtype, fmt):
        digest = sha256_file(path)
        rid = self.ctx.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                                  " VALUES (?,?,?,?,?)", (pid, rtype, fmt, str(path), digest))
        self.ctx.audit.record("report.generate", "tv_project", pid, report_id=rid, type=rtype, format=fmt)
        return path

    def _styles(self):
        ss = getSampleStyleSheet()
        return ss, ParagraphStyle("s", parent=ss["BodyText"], fontSize=8, leading=10)

    # ---- compatibility -----------------------------------------------------------------------------
    def compatibility_pdf(self, compatibility_id: int) -> Path:
        c = self.ctx.compatibility.get(compatibility_id)
        pid = c["project_id"]
        p = self.ctx.projects.get(pid)
        fw = self.ctx.library.get(c["firmware_id"])
        path = self._out(pid, "Compatibility", "pdf")
        ss, sm = self._styles()
        verdict = ParagraphStyle("v", parent=ss["Heading1"], textColor=colors.HexColor(VERDICT_COLOR[c["verdict"]]))
        story = [Paragraph(f"{APP_NAME} &mdash; Firmware Compatibility Report", ss["Title"]),
                 _p(f"TV: project #{pid} {p.name} — {p.manufacturer or '?'} {p.model_number or '?'}, board "
                    f"{p.mainboard or '?'}, panel {p.panel_model or '?'} | Candidate: firmware #{fw.id} "
                    f"{fw.original_filename} (SHA-256 {fw.sha256[:16]}…) | Baseline: "
                    f"{('firmware #' + str(c['baseline_firmware_id'])) if c['baseline_firmware_id'] else 'none'} | "
                    f"{c['created_at']} | v{APP_VERSION}", sm), Spacer(1, 3 * mm),
                 Paragraph(f"{c['verdict']} (score {int(c['score'] or 0)})", verdict)]
        for r in c["reasons"]:
            story.append(_p("• " + r, sm))
        story.append(Paragraph("Criteria", ss["Heading2"]))
        rows = [[_p(h, sm) for h in ("Criterion", "TV", "Firmware", "Status", "Evidence")]]
        for x in c["criteria"]:
            rows.append([_p(x["criterion"] + (" (hard)" if x["hard"] and x["status"] == "mismatch" else ""), sm),
                         _p(x["tv_value"], sm), _p(x["fw_value"], sm), _p(x["status"], sm), _p(x["evidence"], sm)])
        story.append(_table(rows, [28 * mm, 32 * mm, 36 * mm, 20 * mm, 64 * mm]))
        story.append(Spacer(1, 3 * mm))
        story.append(_p("A verdict is only as good as the evidence: 'unknown' criteria were not proven either way. "
                        "Only VERIFIED COMPATIBLE allows execution in the Upgrade Manager, and only through a verified "
                        "official method.", sm))
        SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                          bottomMargin=15 * mm, title="Firmware Compatibility Report", author=APP_NAME).build(story)
        return self._register(pid, path, "firmware_compatibility", "pdf")

    # ---- upgrade -----------------------------------------------------------------------------------
    def upgrade_data(self, sid: int) -> dict:
        s = self.ctx.upgrades.session(sid)
        return {"generator": f"{APP_NAME} {APP_VERSION}", "session": {k: v for k, v in s.items() if k != "steps_json"},
                "profile": self.ctx.upgrades.profile(s["profile_id"]) if s["profile_id"] else None,
                "target_firmware": self.ctx.library.get(s["target_firmware_id"]).__dict__}

    def upgrade_json(self, sid: int) -> Path:
        d = self.upgrade_data(sid)
        pid = d["session"]["project_id"]
        path = self._out(pid, "Upgrade", "json")
        path.write_text(json.dumps(d, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        return self._register(pid, path, "firmware_upgrade", "json")

    def upgrade_pdf(self, sid: int) -> Path:
        d = self.upgrade_data(sid)
        s, prof, fw = d["session"], d["profile"], d["target_firmware"]
        pid = s["project_id"]
        p = self.ctx.projects.get(pid)
        path = self._out(pid, "Upgrade", "pdf")
        ss, sm = self._styles()
        story = [Paragraph(f"{APP_NAME} &mdash; Firmware Upgrade Report", ss["Title"]),
                 _p(f"Session #{sid} | TV project #{pid} {p.name} — {p.manufacturer} {p.model_number} | "
                    f"method {prof['method']} (profile #{prof['id']}, verified: {'yes, ' + str(prof['verified_by']) if prof['verified'] else 'NO'}) | "
                    f"target firmware #{fw['id']} {fw['original_filename']} SHA-256 {fw['sha256']} | "
                    f"from version {s['source_firmware_version'] or '?'} | status {s['status']}", sm),
                 _p(f"Documentation: {prof['documentation_ref']}", sm), Spacer(1, 3 * mm),
                 Paragraph("Steps", ss["Heading2"])]
        rows = [[_p(h, sm) for h in ("Step", "Status", "Details")]]
        for name, st in s["steps"].items():
            detail = {k: v for k, v in st.items() if k != "status"}
            rows.append([_p(name, sm), _p(st.get("status"), sm), _p(json.dumps(detail, default=str)[:1500], sm)])
        story.append(_table(rows, [28 * mm, 24 * mm, 128 * mm]))
        story += [Paragraph("Log", ss["Heading2"]), _p(s["log"] or "", sm),
                  Spacer(1, 3 * mm),
                  _p("This application never writes to the TV, its flash memory, partitions or bootloader. With the "
                     "Official USB method it only prepares the USB medium exactly as documented and verifies the copy; "
                     "the TV's own updater performs the installation.", sm)]
        SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                          bottomMargin=15 * mm, title="Firmware Upgrade Report", author=APP_NAME).build(story)
        return self._register(pid, path, "firmware_upgrade", "pdf")
