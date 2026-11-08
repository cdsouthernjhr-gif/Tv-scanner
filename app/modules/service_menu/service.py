"""Factory & Service Menu database and safe service-action workflow.

* Every record must cite official documentation (a document in the local
  library + page, or a reference such as the manufacturer's service-manual
  title/section or official web page). Undocumented records are rejected.
* The database stores *documented, manufacturer-sanctioned* access procedures
  and functions. It contains no code for password guessing, brute force or
  bypassing authentication, and records whose procedure describes such
  methods are refused.
* Changing factory settings is a documented workflow: plan → backup (when the
  documentation names a backup mechanism) → explicit confirmation → performed.
  The application itself never changes TV settings.
"""
from __future__ import annotations

import csv
import fnmatch
import json
import re
from pathlib import Path

from app.security.audit import current_actor

MENU_CATEGORIES = ["Factory Menu", "Service Menu", "Hotel Mode", "Panel Configuration", "Picture Settings",
                   "Audio Settings", "Tuner Settings", "Network Diagnostics", "Firmware Information",
                   "Hardware Diagnostics", "Official Factory Reset Documentation"]
RISK_LEVELS = ["low", "medium", "high", "critical"]
SOURCE_TYPES = ["official_document", "official_web", "manufacturer_training"]
FIELDS = ["manufacturer", "model_pattern", "chassis", "platform", "firmware_version", "region", "menu_category",
          "access_procedure", "function_description", "official_documentation", "source_type", "document_id",
          "document_page", "access_availability", "configuration_risk", "backup_mechanism", "notes"]
_FORBIDDEN = re.compile(r"(?i)\b(brute[- ]?force|password (list|guess|crack)|try (all|every) (code|password|pin)s?|"
                        r"bypass(ing)? (the )?(password|authenti\w+|pin|lock)|crack(ed|ing)?|exploit)\b")
PASSAGE_KEYWORDS = ["service mode", "service menu", "factory mode", "factory menu", "hotel mode", "design mode",
                    "engineering mode", "adjustment mode", "service remote", "factory reset", "initial setting",
                    "self diagnosis", "self-diagnosis", "white balance adjustment", "option code"]


class ServiceMenuDB:
    def __init__(self, db, audit, datasheets=None):
        self.db, self.audit, self.datasheets = db, audit, datasheets

    # ---- validation -------------------------------------------------------------------------
    def validate(self, rec: dict) -> dict:
        r = {k: (rec.get(k).strip() if isinstance(rec.get(k), str) else rec.get(k)) for k in FIELDS}
        if not r["manufacturer"]:
            raise ValueError("manufacturer is required")
        if r["menu_category"] not in MENU_CATEGORIES:
            raise ValueError(f"menu_category must be one of: {', '.join(MENU_CATEGORIES)}")
        r["source_type"] = r["source_type"] or "official_document"
        if r["source_type"] not in SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {SOURCE_TYPES}")
        if r["document_id"]:
            if self.db.query_one("SELECT id FROM datasheets WHERE id=?", (r["document_id"],)) is None:
                raise ValueError(f"document #{r['document_id']} is not in the document library")
            if not r["official_documentation"]:
                d = self.db.query_one("SELECT title, original_filename FROM datasheets WHERE id=?", (r["document_id"],))
                r["official_documentation"] = (d["title"] or d["original_filename"]) + \
                    (f", p.{r['document_page']}" if r["document_page"] else "")
        if not r["official_documentation"] or len(r["official_documentation"]) < 8:
            raise ValueError("official_documentation is required: cite the manufacturer's service manual (title, "
                             "section/page) or official web page. Undocumented procedures are not accepted.")
        r["configuration_risk"] = (r["configuration_risk"] or "").lower() or "high"
        if r["configuration_risk"] not in RISK_LEVELS:
            raise ValueError(f"configuration_risk must be one of {RISK_LEVELS}")
        for k in ("access_procedure", "function_description", "notes"):
            if r[k] and _FORBIDDEN.search(r[k]):
                raise ValueError(f"{k} describes password guessing / bypass methods — not accepted. Only procedures "
                                 "documented and sanctioned by the manufacturer may be stored.")
        if r["model_pattern"] and len(r["model_pattern"]) > 80:
            raise ValueError("model_pattern too long")
        return r

    # ---- CRUD -----------------------------------------------------------------------------------
    def add(self, rec: dict) -> int:
        r = self.validate(rec)
        cols = FIELDS + ["created_by", "created_at", "updated_at"]
        rid = self.db.execute(
            f"INSERT INTO service_menus({','.join(cols)}) VALUES ({','.join('?' * len(FIELDS))}, ?,"
            " strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            tuple(r[k] for k in FIELDS) + (current_actor(),))
        self.audit.record("service_menu.add", "service_menu", rid, manufacturer=r["manufacturer"],
                          category=r["menu_category"])
        return rid

    def update(self, rid: int, rec: dict) -> None:
        r = self.validate({**self.get(rid), **rec})
        self.db.execute(f"UPDATE service_menus SET {', '.join(f'{k}=?' for k in FIELDS)},"
                        " updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                        tuple(r[k] for k in FIELDS) + (rid,))
        self.audit.record("service_menu.update", "service_menu", rid)

    def delete(self, rid: int) -> None:
        if self.db.scalar("SELECT COUNT(*) FROM service_actions WHERE service_menu_id=?", (rid,)):
            raise ValueError("record is referenced by service actions and cannot be deleted")
        self.db.execute("DELETE FROM service_menus WHERE id=?", (rid,))
        self.audit.record("service_menu.delete", "service_menu", rid)

    def get(self, rid: int) -> dict:
        r = self.db.query_one("SELECT * FROM service_menus WHERE id=?", (rid,))
        if r is None:
            raise KeyError(rid)
        return dict(r)

    def list(self, manufacturer: str | None = None, category: str | None = None, text: str | None = None) -> list[dict]:
        sql, p = "SELECT * FROM service_menus WHERE 1=1", []
        if manufacturer:
            sql += " AND manufacturer=? COLLATE NOCASE"
            p.append(manufacturer)
        if category:
            sql += " AND menu_category=?"
            p.append(category)
        if text:
            sql += " AND (model_pattern LIKE ? OR function_description LIKE ? OR chassis LIKE ? OR platform LIKE ?)"
            p += [f"%{text}%"] * 4
        return [dict(r) for r in self.db.query(sql + " ORDER BY manufacturer, menu_category, id", tuple(p))]

    def applicable(self, project) -> list[dict]:
        """Records that apply to a project, with the reason for each."""
        out = []
        if not project.manufacturer:
            return out
        for r in self.list(manufacturer=project.manufacturer):
            why = [f"manufacturer {r['manufacturer']}"]
            if r["model_pattern"]:
                if not project.model_number or not fnmatch.fnmatch(project.model_number.upper(), r["model_pattern"].upper()):
                    continue
                why.append(f"model {project.model_number} matches {r['model_pattern']}")
            if r["chassis"]:
                if not project.chassis or project.chassis.upper() != r["chassis"].upper():
                    continue
                why.append(f"chassis {r['chassis']}")
            if r["platform"] and project.platform and r["platform"].lower() != project.platform.lower():
                continue
            r["applies_because"] = "; ".join(why)
            r["specificity"] = len(why)
            out.append(r)
        return sorted(out, key=lambda r: -r["specificity"])

    # ---- import / export -----------------------------------------------------------------------------
    def export_json(self, path: Path) -> int:
        rows = [{k: r[k] for k in FIELDS} for r in self.list()]
        Path(path).write_text(json.dumps({"format": "tvis-service-menus-1", "records": rows}, indent=2,
                                         ensure_ascii=False), encoding="utf-8")
        return len(rows)

    def export_csv(self, path: Path) -> int:
        rows = self.list()
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        return len(rows)

    def import_file(self, path: Path) -> tuple[int, list[str]]:
        path = Path(path)
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            records = data["records"] if isinstance(data, dict) else data
        elif path.suffix.lower() == ".csv":
            with open(path, encoding="utf-8-sig") as fh:
                records = list(csv.DictReader(fh))
        else:
            raise ValueError("Import supports .json and .csv")
        ok, rejected = 0, []
        for i, rec in enumerate(records, 1):
            rec = {k: (v if v != "" else None) for k, v in rec.items()}
            for k in ("document_id", "document_page"):
                if rec.get(k) is not None:
                    rec[k] = int(rec[k])
            try:
                self.add(rec)
                ok += 1
            except (ValueError, KeyError) as exc:
                rejected.append(f"record {i}: {exc}")
        self.audit.record("service_menu.import", details_file=str(path), imported=ok, rejected=len(rejected))
        return ok, rejected

    # ---- service-manual search ------------------------------------------------------------------------------
    def find_passages(self, document_id: int, keywords: list[str] | None = None, width: int = 220) -> list[dict]:
        kws = [k.lower() for k in (keywords or PASSAGE_KEYWORDS)]
        out = []
        for row in self.db.query("SELECT page, text FROM datasheet_pages WHERE datasheet_id=? ORDER BY page", (document_id,)):
            low = row["text"].lower()
            for kw in kws:
                pos = low.find(kw)
                if pos >= 0:
                    a = max(0, pos - width // 3)
                    out.append({"page": row["page"], "keyword": kw,
                                "excerpt": re.sub(r"\s+", " ", row["text"][a:a + width]).strip()})
        return out

    # ---- service actions (factory-setting changes) -----------------------------------------------------------
    def plan_action(self, project_id: int, service_menu_id: int, setting: str, new_value: str, reason: str,
                    old_value: str | None = None) -> int:
        rec = self.get(service_menu_id)
        if not setting.strip() or not new_value.strip() or len(reason.strip()) < 5:
            raise ValueError("setting, new value and a reason are required")
        backup = 1 if rec["backup_mechanism"] else 0
        aid = self.db.execute("INSERT INTO service_actions(project_id, service_menu_id, setting, old_value, new_value,"
                              " reason, backup_required) VALUES (?,?,?,?,?,?,?)",
                              (project_id, service_menu_id, setting.strip(), old_value, new_value.strip(),
                               reason.strip(), backup))
        self.audit.record("service_action.plan", "tv_project", project_id, action_id=aid, setting=setting,
                          new_value=new_value, risk=rec["configuration_risk"])
        return aid

    def action(self, aid: int) -> dict:
        r = self.db.query_one("SELECT * FROM service_actions WHERE id=?", (aid,))
        if r is None:
            raise KeyError(aid)
        return dict(r)

    def actions(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT a.*, m.menu_category, m.configuration_risk, m.backup_mechanism, m.official_documentation"
            " FROM service_actions a JOIN service_menus m ON m.id=a.service_menu_id WHERE a.project_id=? ORDER BY a.id",
            (project_id,))]

    def record_backup(self, aid: int, evidence: str, evidence_id: int | None = None) -> None:
        a = self.action(aid)
        if a["status"] != "planned":
            raise ValueError(f"action is {a['status']}")
        if not evidence or len(evidence.strip()) < 5:
            raise ValueError("Describe the backup (e.g. 'settings exported to USB, file X, photo #12')")
        self.db.execute("UPDATE service_actions SET status='backed_up', backup_evidence=?, backup_evidence_id=? WHERE id=?",
                        (evidence.strip(), evidence_id, aid))
        self.audit.record("service_action.backup", "tv_project", a["project_id"], action_id=aid)

    def confirmation_phrase(self, aid: int) -> str:
        return f"CHANGE {self.action(aid)['setting']}"

    def confirm(self, aid: int, typed: str, confirmed_by: str | None = None) -> None:
        a = self.action(aid)
        if a["backup_required"] and a["status"] != "backed_up":
            raise ValueError("The documentation names a backup mechanism — record the backup first.")
        if a["status"] not in ("planned", "backed_up"):
            raise ValueError(f"action is {a['status']}")
        if typed.strip() != self.confirmation_phrase(aid):
            raise ValueError(f"Type exactly: {self.confirmation_phrase(aid)}")
        self.db.execute("UPDATE service_actions SET status='confirmed', confirmed_by=?,"
                        " confirmed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                        (confirmed_by or current_actor(), aid))
        self.audit.record("service_action.confirm", "tv_project", a["project_id"], action_id=aid)

    def mark_performed(self, aid: int, result: str) -> None:
        a = self.action(aid)
        if a["status"] != "confirmed":
            raise ValueError("Only confirmed actions can be marked as performed")
        if not result or len(result.strip()) < 3:
            raise ValueError("Describe the result")
        self.db.execute("UPDATE service_actions SET status='performed', result=?,"
                        " performed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?", (result.strip(), aid))
        self.audit.record("service_action.performed", "tv_project", a["project_id"], action_id=aid, result=result)

    def cancel(self, aid: int, reason: str = "") -> None:
        a = self.action(aid)
        if a["status"] == "performed":
            raise ValueError("A performed action cannot be cancelled")
        self.db.execute("UPDATE service_actions SET status='cancelled', result=? WHERE id=?", (reason or "cancelled", aid))
        self.audit.record("service_action.cancel", "tv_project", a["project_id"], action_id=aid)
