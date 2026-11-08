"""Firmware Search Report (PDF / CSV / JSON) for one search session."""
from __future__ import annotations

import csv
import datetime as _dt
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import APP_NAME, APP_VERSION
from app.security.hashing import sha256_file

COLUMNS = ["id", "match_status", "compatibility_score", "risk_assessment", "title", "version", "manufacturer",
           "supported_models", "supported_mainboards", "file_size", "file_format", "source_type", "source_site",
           "provider", "url", "download_url", "published_at", "sha256", "sha256_source", "signature_status",
           "verification_status", "distribution_status", "firmware_id", "query", "searched_at"]


def _p(t, st):
    return Paragraph(escape("" if t is None else str(t)), st)


class SearchReportGenerator:
    def __init__(self, config, db, audit, finder):
        self.config, self.db, self.audit, self.finder = config, db, audit, finder

    def _session(self, sid: int) -> dict:
        r = self.db.query_one("SELECT * FROM search_sessions WHERE id=?", (sid,))
        if r is None:
            raise KeyError(sid)
        return dict(r)

    def _out(self, sid: int, ext: str) -> Path:
        d = self.config.reports_dir / "searches"
        d.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return d / f"Firmware_Search_{sid}_{ts}.{ext}"

    def _register(self, sess: dict, path: Path, fmt: str) -> Path:
        digest = sha256_file(path)
        rid = self.db.execute("INSERT INTO technical_reports(project_id, report_type, format, file_path, sha256)"
                              " VALUES (?, 'firmware_search', ?, ?, ?)", (sess["project_id"], fmt, str(path), digest))
        self.audit.record("report.generate", "search_session", sess["id"], report_id=rid, format=fmt)
        return path

    def export_json(self, sid: int) -> Path:
        sess = self._session(sid)
        path = self._out(sid, "json")
        rows = self.finder.results(sid)
        for r in rows:
            r["match_details"] = json.loads(r.pop("match_details_json") or "{}")
            r["raw"] = json.loads(r.pop("raw_json") or "{}")
        payload = {"generator": f"{APP_NAME} {APP_VERSION}", "session": {**sess,
                   "criteria": json.loads(sess["criteria_json"]), "queries": json.loads(sess["queries_json"] or "[]"),
                   "errors": json.loads(sess["errors_json"] or "{}")}, "results": rows}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return self._register(sess, path, "json")

    def export_csv(self, sid: int) -> Path:
        sess = self._session(sid)
        path = self._out(sid, "csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for r in self.finder.results(sid):
                w.writerow([r.get(c) for c in COLUMNS])
        return self._register(sess, path, "csv")

    def generate_pdf(self, sid: int) -> Path:
        sess = self._session(sid)
        path = self._out(sid, "pdf")
        rows = self.finder.results(sid)
        crit = json.loads(sess["criteria_json"])
        ss = getSampleStyleSheet()
        sm = ParagraphStyle("s", parent=ss["BodyText"], fontSize=7, leading=9)
        story = [Paragraph(f"{APP_NAME} &mdash; Firmware Search Report", ss["Title"]),
                 _p(f"Search #{sid} | started {sess['started_at']} | finished {sess['finished_at']} | "
                    f"providers: {sess['providers']} | v{APP_VERSION}", sm), Spacer(1, 3 * mm),
                 Paragraph("Search criteria", ss["Heading2"])]
        crow = [[_p(k, sm), _p(v, sm), _p((crit.get("sources") or {}).get(k, ""), sm)]
                for k, v in crit.items() if v and k != "sources"]
        if crow:
            t = Table([[_p("Criterion", sm), _p("Value", sm), _p("Origin", sm)]] + crow,
                      colWidths=[40 * mm, 80 * mm, 120 * mm])
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef6"))]))
            story.append(t)
        errs = json.loads(sess["errors_json"] or "{}")
        if errs:
            story.append(_p("Provider notes: " + " | ".join(f"{k}: {'; '.join(v)[:300]}" for k, v in errs.items()), sm))
        story += [Paragraph(f"Results ({len(rows)})", ss["Heading2"]),
                  _p("A search result is NOT a verified firmware. 'VERIFIED MATCH' is only possible after download, "
                     "hash verification and analysis that confirms the model. Risk 'Critical' results should not be "
                     "used.", sm)]
        head = ["#", "Verdict", "Score", "Risk", "Firmware / title", "Version", "Source", "URL", "Published",
                "SHA-256", "Verification"]
        data = [[_p(h, sm) for h in head]]
        for r in rows:
            data.append([_p(r["id"], sm), _p(r["match_status"], sm), _p(int(r["compatibility_score"] or 0), sm),
                         _p((r["risk_assessment"] or "")[:160], sm), _p(r["title"], sm), _p(r["version"], sm),
                         _p(f"{r['provider']} ({r['source_site']})", sm), _p(r["download_url"] or r["url"], sm),
                         _p((r["published_at"] or "")[:10], sm),
                         _p((r["sha256"] or "none published")[:20] + ("…" if r["sha256"] else ""), sm),
                         _p(r["verification_status"], sm)])
        t = Table(data, colWidths=[9 * mm, 24 * mm, 11 * mm, 38 * mm, 38 * mm, 16 * mm, 26 * mm, 50 * mm, 16 * mm,
                                   22 * mm, 30 * mm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
        story.append(t)
        SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm,
                          topMargin=12 * mm, bottomMargin=12 * mm, title=f"Firmware Search {sid}",
                          author=APP_NAME).build(story)
        return self._register(sess, path, "pdf")
