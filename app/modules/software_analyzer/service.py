"""Software & Operating System Analyzer.

Sources (each fact keeps its own):
* firmware_analysis — metadata + extracted files of the project's analysed firmware (Phase 4)
* fingerprint       — OS rules applied to extracted files / strings (indicators)
* system_menu_ocr   — OCR text of 'System information menu' evidence photos (Phase 2)
* operator          — values typed by the technician with a reference (e.g. Settings > About)
* upnp / adb        — authorised read-only device queries (see connectors.py)

Re-analysis replaces firmware/fingerprint/OCR facts; operator and device facts
are kept (they are observations from other sessions).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.modules.software_analyzer import connectors as dev
from app.modules.software_analyzer import inventory as inv

CATEGORIES = ["os", "os_version", "kernel", "build", "firmware_version", "bootloader", "application", "library",
              "driver", "network_interface", "display", "audio", "device_info", "other"]
SUMMARY_CATS = ["os", "os_version", "kernel", "build", "firmware_version", "bootloader", "device_info"]
_META_MAP = {
    "os_family": ("os", None), "os_name": ("os", None), "os_pretty_name": ("os_version", "os-release {}"),
    "os_version_id": ("os_version", "os-release VERSION_ID {}"), "android_version": ("os_version", "Android {}"),
    "kernel_version": ("kernel", None), "build_id": ("build", None), "build_number": ("build", None),
    "build_fingerprint": ("build", None), "build_date": ("build", "built {}"), "firmware_version": ("firmware_version", None),
    "bootloader": ("bootloader", None), "userland": ("other", None), "toolchain": ("other", "toolchain {}"),
    "product_model": ("device_info", "model {}"), "board_platform": ("device_info", "platform {}"),
    "hardware": ("device_info", "hardware {}"), "product_brand": ("device_info", "brand {}"),
    "product_manufacturer": ("device_info", "manufacturer {}"), "signing": ("other", None),
}
_MENU_PATTERNS = [
    ("os_version", re.compile(r"(?i)\bandroid(?: tv)?(?: os)?\s*version\s*[:=]?\s*(\d+(?:\.\d+)*)"), "Android {}"),
    ("kernel", re.compile(r"(?i)\bkernel(?: version)?\s*[:=]?\s*(\d+\.\d+(?:\.\d+)?\S*)"), None),
    ("build", re.compile(r"(?i)\bbuild(?: number| no\.?| id)?\s*[:=]\s*([A-Za-z0-9._\-]{3,60})"), None),
    ("firmware_version", re.compile(r"(?i)\b(?:software|firmware|s/w|sw)\s*(?:version|ver\.?)?\s*[:=]?\s*([A-Za-z0-9._\-]{3,60})"), None),
    ("bootloader", re.compile(r"(?i)\b(?:boot ?loader|u-?boot)(?: version)?\s*[:=]\s*([A-Za-z0-9._\-]{2,40})"), None),
    ("display", re.compile(r"\b(\d{3,4}\s*[x×]\s*\d{3,4})\b"), "resolution {}"),
    ("device_info", re.compile(r"(?i)\b(?:wired|ethernet|wi-?fi|wireless)?\s*mac(?: address)?\s*[:=]\s*((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})"),
     "MAC {}"),
]


class SoftwareAnalyzer:
    def __init__(self, db, audit, projects, library, firmware):
        self.db, self.audit, self.projects, self.library, self.firmware = db, audit, projects, library, firmware

    # ---- storage --------------------------------------------------------------------------
    def _add(self, tx, pid, category, name, value, source_type, ref, conf, fid=None):
        tx.execute("INSERT INTO software_facts(project_id, category, name, value, source_type, source_ref, confidence,"
                   " firmware_id) VALUES (?,?,?,?,?,?,?,?)", (pid, category, str(name)[:300],
                                                              None if value is None else str(value)[:1000],
                                                              source_type, ref[:500], round(conf, 3), fid))

    def facts(self, project_id: int, category: str | None = None) -> list[dict]:
        sql, p = "SELECT * FROM software_facts WHERE project_id=?", [project_id]
        if category:
            sql += " AND category=?"
            p.append(category)
        return [dict(r) for r in self.db.query(sql + " ORDER BY category, confidence DESC, id", tuple(p))]

    def add_operator_fact(self, project_id: int, category: str, name: str, value: str | None, reference: str) -> None:
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        if not reference or len(reference.strip()) < 3:
            raise ValueError("A reference is required (e.g. 'Settings > Device > About' or 'photo evidence #4')")
        self.projects.get(project_id)
        with self.db.transaction() as tx:
            self._add(tx, project_id, category, name, value, "operator", reference.strip(), 0.8)
        self.audit.record("software.fact_add", "tv_project", project_id, category=category, name=name)

    # ---- analysis -------------------------------------------------------------------------------
    def analyze(self, project_id: int) -> dict:
        self.projects.get(project_id)
        with self.db.transaction() as tx:
            tx.execute("DELETE FROM software_facts WHERE project_id=? AND source_type IN "
                       "('firmware_analysis','fingerprint','system_menu_ocr')", (project_id,))
            n_fw = self._from_firmware(tx, project_id)
            n_ocr = self._from_system_menu(tx, project_id)
        self.db.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                        " VALUES (?, 'software', ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                        (project_id, f"Software analysis: {n_fw} firmware, {n_ocr} system-menu photo(s)"))
        self.audit.record("software.analyze", "tv_project", project_id, firmware=n_fw, menu_photos=n_ocr)
        return self.summary(project_id)

    def _from_firmware(self, tx, pid) -> int:
        n = 0
        for fw in self.library.list(project_id=pid):
            run = self.firmware.latest_run(fw.id)
            if not run:
                continue
            n += 1
            ref = f"firmware #{fw.id} {fw.original_filename}, run #{run['id']}"
            keywords, props = set(), {}
            for m in self.firmware.metadata(run["id"]):
                attr = m["attribute"]
                if attr == "platform_mention":
                    keywords.add(m["value"])
                    continue
                if attr in _META_MAP:
                    cat, fmt = _META_MAP[attr]
                    val = fmt.format(m["value"]) if fmt else m["value"]
                    self._add(tx, pid, cat, val, None, "firmware_analysis", f"{ref}: {m['source']}", m["confidence"], fw.id)
                if attr.startswith(("android", "build", "product")):
                    props[attr] = m["value"]
            st = self.firmware.result(run["id"], "strings") or {}
            for h in st.get("hits", {}).get("platform_keyword", []):
                keywords.add(h["value"])
            files_rows = [f for f in self.firmware.files(run["id"]) if f["kind"] != "symlink"]
            files = [f["rel_path"] for f in files_rows]
            try:
                root = self.firmware.run_dir(run["id"]) / "extracted"
            except KeyError:
                continue
            items = inv.applications(files, root) + inv.libraries(files) + inv.drivers(files) + inv.config_facts(files, root)
            pkgs = {i.name for i in items if i.category == "application"}
            for i in items:
                self._add(tx, pid, i.category, i.name, i.value, "firmware_analysis", f"{ref}: {i.source_ref}",
                          i.confidence, fw.id)
            for i in inv.fingerprint(files, root, keywords, props, pkgs):
                self._add(tx, pid, "os", i.name, i.value, "fingerprint", f"{ref}: {i.source_ref}", i.confidence, fw.id)
        return n

    def _from_system_menu(self, tx, pid) -> int:
        n = 0
        rows = self.db.query("SELECT e.id, e.ocr_text, (SELECT mean_confidence FROM ocr_results o WHERE o.evidence_id=e.id"
                             " ORDER BY o.id DESC LIMIT 1) AS conf FROM scan_evidence e WHERE e.project_id=? AND"
                             " e.evidence_type='system_info_menu' AND e.ocr_text IS NOT NULL", (pid,))
        for r in rows:
            n += 1
            conf = 0.8 * (r["conf"] or 0.6)
            for line in (r["ocr_text"] or "").splitlines():
                for cat, rx, fmt in _MENU_PATTERNS:
                    m = rx.search(line)
                    if m:
                        val = fmt.format(m.group(1)) if fmt else m.group(1)
                        self._add(tx, pid, cat, val, line.strip()[:120], "system_menu_ocr",
                                  f"System information photo, evidence #{r['id']}", conf)
                        break
        return n

    # ---- summary ------------------------------------------------------------------------------------
    def summary(self, project_id: int) -> dict:
        facts = self.facts(project_id)
        out: dict = {}
        for cat in SUMMARY_CATS:
            vals: dict[str, dict] = {}
            for f in facts:
                if f["category"] != cat:
                    continue
                v = vals.setdefault(f["name"], {"value": f["name"], "confidence": 0.0, "sources": []})
                v["confidence"] = max(v["confidence"], f["confidence"])
                v["sources"].append(f"{f['source_type']}: {f['source_ref']}")
            out[cat] = sorted(vals.values(), key=lambda x: -x["confidence"])
        for cat in ("application", "library", "driver", "network_interface", "display", "audio"):
            out[cat + "_count"] = len({f["name"] for f in facts if f["category"] == cat})
        # contradictions: different OS families each supported with >= 0.6
        families = {"Android", "Tizen", "webOS", "VIDAA", "Roku OS"}
        strong = sorted({o["value"].split(" ")[0] if o["value"].startswith("Android") else o["value"]
                         for o in out["os"] if o["confidence"] >= 0.6} & (families | {"Android"}))
        out["conflicts"] = ([f"Evidence for several operating systems: {', '.join(strong)} — check whether the firmware "
                             "belongs to this TV"] if len(strong) > 1 else [])
        out["os_best"] = out["os"][0]["value"] if out["os"] else "not determined"
        return out

    # ---- device connectors --------------------------------------------------------------------------------
    def _session(self, project_id, connector, target, note, status, commands=None, output=None) -> int:
        sid = self.db.execute("INSERT INTO device_sessions(project_id, connector, target, authorization_note, status,"
                              " commands_json, output_json, finished_at) VALUES (?,?,?,?,?,?,?,"
                              " strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                              (project_id, connector, target, note, status, json.dumps(commands or []),
                               json.dumps(output or {})[:2_000_000]))
        self.audit.record(f"device.{connector}", "tv_project", project_id, session_id=sid, target=target, status=status)
        return sid

    def upnp_discover(self, authorization_note: str, timeout: float = 3.0, **kw) -> list[dict]:
        note = dev.require_authorization(authorization_note)
        devices = dev.ssdp_discover(timeout, **kw)
        out = []
        for d in devices:
            try:
                d.info = dev.fetch_description(d.location)
            except Exception as exc:
                d.info = {"error": str(exc)[:200]}
            out.append({"location": d.location, "server": d.server, "usn": d.usn, **d.info})
        self._session(None, "upnp", "LAN multicast", note, "discovered", ["M-SEARCH upnp:rootdevice"], {"devices": out})
        return out

    def record_upnp_device(self, project_id: int, device: dict, authorization_note: str) -> int:
        note = dev.require_authorization(authorization_note)
        sid = self._session(project_id, "upnp", device.get("location"), note, "linked", ["device description"], device)
        with self.db.transaction() as tx:
            for k, label in (("manufacturer", "manufacturer"), ("modelName", "model name"),
                             ("modelNumber", "model number"), ("friendlyName", "friendly name"),
                             ("serialNumber", "serial number"), ("modelDescription", "description")):
                if device.get(k):
                    self._add(tx, project_id, "device_info", f"{label} {device[k]}", None, "upnp",
                              f"UPnP description {device.get('location')} (session #{sid})", 0.85)
            if device.get("server"):
                self._add(tx, project_id, "os", device["server"], "UPnP SERVER header (self-reported)", "upnp",
                          f"session #{sid}", 0.5)
        return sid

    def adb_collect(self, project_id: int, target: str, authorization_note: str, adb_path: str | None = None,
                    queries: list[str] | None = None) -> int:
        note = dev.require_authorization(authorization_note)
        adb = adb_path or dev.find_adb()
        if not adb:
            raise RuntimeError("adb not found. Install Android SDK Platform-Tools "
                               "(developer.android.com/tools/releases/platform-tools), extract it and add the "
                               "platform-tools folder to PATH, then restart the application.")
        queries = queries or list(dev.ADB_READ_ONLY)
        res = dev.adb_query(adb, target, queries)
        sid = self._session(project_id, "adb", target, note, "completed",
                            [" ".join(dev.ADB_READ_ONLY[q]) for q in queries], res)
        ref = f"ADB read-only session #{sid} ({target})"
        with self.db.transaction() as tx:
            props = dev.parse_getprop(res.get("properties", ""))
            for key, cat, fmt in (("ro.build.version.release", "os_version", "Android {}"),
                                  ("ro.build.display.id", "build", None), ("ro.build.fingerprint", "build", None),
                                  ("ro.product.model", "device_info", "model {}"),
                                  ("ro.product.manufacturer", "device_info", "manufacturer {}"),
                                  ("ro.board.platform", "device_info", "platform {}"),
                                  ("ro.bootloader", "bootloader", None)):
                if props.get(key):
                    self._add(tx, project_id, cat, fmt.format(props[key]) if fmt else props[key], key, "adb", ref, 0.9)
            if props:
                self._add(tx, project_id, "os", "Android", "device answered ADB getprop", "adb", ref, 0.95)
            if "android.software.leanback" in res.get("features", ""):
                self._add(tx, project_id, "os", "Android TV", "feature android.software.leanback", "adb", ref, 0.95)
            k = res.get("kernel", "")
            m = re.search(r"Linux \S+ (\d+\.\d+\.\d+\S*)", k)
            if m:
                self._add(tx, project_id, "kernel", m.group(1), k.strip()[:200], "adb", ref, 0.95)
            for line in (res.get("packages", "") + "\n" + res.get("third_party_packages", "")).splitlines():
                if line.startswith("package:"):
                    self._add(tx, project_id, "application", line[8:].strip(), "installed package", "adb", ref, 0.95)
            m = re.search(r"Physical size:\s*(\d+x\d+)", res.get("display", ""))
            if m:
                self._add(tx, project_id, "display", f"resolution {m.group(1)}", "wm size", "adb", ref, 0.9)
            for line in res.get("network", "").splitlines():
                parts = line.split()
                if parts and parts[0] != "lo":
                    self._add(tx, project_id, "network_interface", parts[0], " ".join(parts[1:3]), "adb", ref, 0.9)
            for line in res.get("drivers", "").splitlines():
                mod = line.split(" ")[0]
                if mod and not mod.startswith("ERROR"):
                    self._add(tx, project_id, "driver", mod, f"{inv.classify_driver(mod)} (loaded module)", "adb", ref, 0.9)
        return sid

    def device_sessions(self, project_id: int | None = None) -> list[dict]:
        if project_id is None:
            return [dict(r) for r in self.db.query("SELECT * FROM device_sessions ORDER BY id DESC")]
        return [dict(r) for r in self.db.query("SELECT * FROM device_sessions WHERE project_id=? ORDER BY id DESC",
                                               (project_id,))]
