"""Operating System Report and Service Menu Report (PDF + JSON)."""
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

LABELS = {"os": "Operating system", "os_version": "OS version", "kernel": "Kernel", "build": "Build",
          "firmware_version": "Firmware version", "bootloader": "Bootloader", "device_info": "Device information"}


def _p(t, st):
    return Paragraph(escape("" if t is None else str(t)), st)


def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(st))
    return t


class SoftwareReportGenerator:
    def __init__(self, config, db, audit, projects, software, service_menus):
        self.config, self.db, self.audit = config, db, audit
        self.projects, self.software, self.service_menus = projects, software, service_menus

    def _out(self, pid: int, kind: str, ext: str) -> Path:
        p = self.projects.get(pid)
        d = self.config.reports_dir / str(pid)
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return d / f"{kind}_{safe_component(p.name)}_{ts}.{ext}"

    def _register(self, pid, path, rtype, fmt):
        digest = sha256_file(path)
        rid = self.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                              " VALUES (?,?,?,?,?)", (pid, rtype, fmt, str(path), digest))
        self.audit.record("report.generate", "tv_project", pid, report_id=rid, type=rtype, format=fmt)
        return path

    def _doc(self, path, title, story):
        SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                          bottomMargin=15 * mm, title=title, author=APP_NAME).build(story)

    # ---- OS report ------------------------------------------------------------------------------
    def os_report_data(self, pid: int) -> dict:
        p = self.projects.get(pid)
        return {"generator": f"{APP_NAME} {APP_VERSION}", "project": {"id": p.id, "name": p.name,
                "manufacturer": p.manufacturer, "model": p.model_number},
                "summary": self.software.summary(pid), "facts": self.software.facts(pid),
                "device_sessions": self.software.device_sessions(pid)}

    def os_report_json(self, pid: int) -> Path:
        path = self._out(pid, "Operating_System", "json")
        path.write_text(json.dumps(self.os_report_data(pid), indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return self._register(pid, path, "operating_system", "json")

    def os_report_pdf(self, pid: int) -> Path:
        d = self.os_report_data(pid)
        path = self._out(pid, "Operating_System", "pdf")
        ss = getSampleStyleSheet()
        sm = ParagraphStyle("s", parent=ss["BodyText"], fontSize=8, leading=10)
        s = d["summary"]
        story = [Paragraph(f"{APP_NAME} &mdash; Operating System Report", ss["Title"]),
                 _p(f"Project #{d['project']['id']} {d['project']['name']} | {d['project']['manufacturer'] or '?'} "
                    f"{d['project']['model'] or ''} | {_dt.datetime.now(_dt.timezone.utc):%Y-%m-%d %H:%M UTC}", sm),
                 Spacer(1, 3 * mm),
                 _p("Sources: firmware_analysis (analysed firmware files), fingerprint (OS indicator rules), "
                    "system_menu_ocr (photos of the System Information screen), operator (entered with reference), "
                    "upnp / adb (authorised read-only device queries). No access method was assumed to exist.", sm),
                 Paragraph("1. Summary", ss["Heading2"])]
        rows = [[_p(h, sm) for h in ("Item", "Value", "Confidence", "Sources")]]
        for cat, label in LABELS.items():
            vals = s.get(cat) or []
            if not vals:
                rows.append([_p(label, sm), _p("not determined", sm), _p("", sm), _p("no evidence", sm)])
            for v in vals[:6]:
                rows.append([_p(label, sm), _p(v["value"], sm), _p(f"{v['confidence']:.0%}", sm),
                             _p("; ".join(v["sources"])[:400], sm)])
        story.append(_table(rows, [30 * mm, 50 * mm, 18 * mm, 82 * mm]))
        for c in s.get("conflicts", []):
            story.append(_p("CONFLICT: " + c, sm))
        story.append(_p("Counts: " + ", ".join(f"{k.replace('_count', '')} {v}" for k, v in s.items()
                                                if k.endswith("_count")), sm))
        for cat, title in (("application", "2. Installed applications"), ("library", "3. System libraries"),
                           ("driver", "4. Hardware drivers / kernel modules"),
                           ("network_interface", "5. Network interfaces"), ("display", "6. Display configuration"),
                           ("audio", "7. Audio configuration")):
            facts = [f for f in d["facts"] if f["category"] == cat]
            story.append(Paragraph(title, ss["Heading2"]))
            if not facts:
                story.append(_p("No evidence found.", sm))
                continue
            rows = [[_p(h, sm) for h in ("Name", "Detail", "Source")]]
            for f in facts[:200]:
                rows.append([_p(f["name"], sm), _p(f["value"], sm), _p(f"{f['source_type']}: {f['source_ref']}"[:200], sm)])
            story.append(_table(rows, [50 * mm, 50 * mm, 80 * mm]))
            if len(facts) > 200:
                story.append(_p(f"… {len(facts) - 200} more in the JSON export", sm))
        if d["device_sessions"]:
            story.append(Paragraph("8. Device communication sessions", ss["Heading2"]))
            rows = [[_p(h, sm) for h in ("#", "Connector", "Target", "Authorisation", "Status", "Time")]]
            for x in d["device_sessions"]:
                rows.append([_p(x["id"], sm), _p(x["connector"], sm), _p(x["target"], sm),
                             _p(x["authorization_note"], sm), _p(x["status"], sm), _p(x["started_at"], sm)])
            story.append(_table(rows, [10 * mm, 20 * mm, 40 * mm, 60 * mm, 20 * mm, 30 * mm]))
        self._doc(path, "Operating System Report", story)
        return self._register(pid, path, "operating_system", "pdf")

    # ---- Service menu report ----------------------------------------------------------------------------
    def service_report_pdf(self, pid: int) -> Path:
        proj = self.projects.get(pid)
        recs = self.service_menus.applicable(proj)
        acts = self.service_menus.actions(pid)
        path = self._out(pid, "Service_Menu", "pdf")
        ss = getSampleStyleSheet()
        sm = ParagraphStyle("s", parent=ss["BodyText"], fontSize=8, leading=10)
        story = [Paragraph(f"{APP_NAME} &mdash; Service Menu Report", ss["Title"]),
                 _p(f"Project #{pid} {proj.name} | {proj.manufacturer or '?'} {proj.model_number or ''} "
                    f"chassis {proj.chassis or '?'} | {_dt.datetime.now(_dt.timezone.utc):%Y-%m-%d %H:%M UTC}", sm),
                 Spacer(1, 3 * mm),
                 _p("Only procedures documented and sanctioned by the manufacturer are listed; each record cites its "
                    "official documentation. This application does not change TV settings; changes are performed by "
                    "the technician following the documentation and recorded below.", sm),
                 Paragraph("1. Applicable documented menus", ss["Heading2"])]
        if recs:
            rows = [[_p(h, sm) for h in ("Category", "Access / function", "Availability", "Risk", "Backup", "Documentation")]]
            for r in recs:
                rows.append([_p(r["menu_category"], sm),
                             _p(f"{r['access_procedure'] or '—'} | {r['function_description'] or ''}", sm),
                             _p(r["access_availability"], sm), _p(r["configuration_risk"], sm),
                             _p(r["backup_mechanism"] or "none documented", sm),
                             _p(f"{r['official_documentation']} ({r['source_type']}); applies: {r['applies_because']}", sm)])
            story.append(_table(rows, [26 * mm, 50 * mm, 22 * mm, 12 * mm, 22 * mm, 48 * mm]))
        else:
            story.append(_p("No documented service-menu records apply to this TV (manufacturer/model/chassis). "
                            "Add records from the manufacturer's service manual.", sm))
        story.append(Paragraph("2. Service actions (factory-setting changes)", ss["Heading2"]))
        if acts:
            rows = [[_p(h, sm) for h in ("#", "Setting", "Old -> new", "Status", "Backup", "Confirmed", "Result")]]
            for a in acts:
                rows.append([_p(a["id"], sm), _p(a["setting"], sm), _p(f"{a['old_value'] or '?'} -> {a['new_value']}", sm),
                             _p(a["status"], sm), _p(a["backup_evidence"] or ("required" if a["backup_required"] else "n/a"), sm),
                             _p(f"{a['confirmed_by'] or ''} {a['confirmed_at'] or ''}", sm), _p(a["result"], sm)])
            story.append(_table(rows, [8 * mm, 30 * mm, 30 * mm, 18 * mm, 36 * mm, 30 * mm, 28 * mm]))
        else:
            story.append(_p("No service actions recorded.", sm))
        self._doc(path, "Service Menu Report", story)
        return self._register(pid, path, "service_menu", "pdf")
