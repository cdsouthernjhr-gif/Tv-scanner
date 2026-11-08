"""Hardware Analyzer: identify components, attach specifications with provenance,
summarise the board, and grow the local reference database.

Evidence hierarchy for a component (``match_status``)::

    datasheet_exact   – a local datasheet mentions this exact part number
    datasheet_family  – a datasheet covers the same base part (variant must be checked)
    decoded           – the vendor's documented numbering scheme decodes the part
    vendor_only       – only a vendor/family numbering convention matched
    unidentified      – nothing matched; no specification is claimed

Rules that keep results honest:
* Every specification value is a separate fact with source + confidence.
* No fact is derived from a part number containing characters that cannot
  appear in a part number (typical OCR misreads such as ')' or '|').
* Board totals (RAM, flash) are only computed when *every* chip of that class
  has a density fact; otherwise the summary says how many are missing.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.database.connection import Database
from app.modules.hardware_analyzer.datasheets import DatasheetLibrary, extract_facts, memory_family
from app.modules.hardware_analyzer.decoders import SpecFact, decode, format_bits, format_bytes
from app.modules.identification.catalog import canonical
from app.modules.visual_scanner import markings as mk
from app.security.audit import AuditLogger
from app.services.project_service import ProjectService

CATEGORIES = {
    "board": "PCB / board", "soc": "SoC / CPU", "ram": "RAM", "flash": "Flash memory", "gpu": "GPU",
    "wifi": "Wi-Fi", "bluetooth": "Bluetooth", "wifi_bt": "Wi-Fi / Bluetooth", "audio": "Audio",
    "tcon": "T-Con", "power_supply": "Power supply", "display_panel": "Display panel",
    "other": "Other",
}
BOARDS = ["mainboard", "power_supply", "tcon", "panel", "other"]

_TYPE_TO_CATEGORY = [
    (re.compile(r"power supply", re.I), "power_supply"),
    (re.compile(r"\bPCB\b|board|mainboard", re.I), "board"),
    (re.compile(r"DRAM", re.I), "ram"),
    (re.compile(r"NAND|NOR|SPI flash|eMMC|flash", re.I), "flash"),
    (re.compile(r"wi-?fi\s*/\s*bluetooth", re.I), "wifi_bt"),
    (re.compile(r"wi-?fi|network", re.I), "wifi"),
    (re.compile(r"bluetooth", re.I), "bluetooth"),
    (re.compile(r"audio", re.I), "audio"),
    (re.compile(r"T-Con or display driver|TV SoC, T-Con", re.I), "other"),   # ambiguous family
    (re.compile(r"T-?Con", re.I), "tcon"),
    (re.compile(r"SoC|scaler|CPU", re.I), "soc"),
    (re.compile(r"panel", re.I), "display_panel"),
]
_INVALID_PART_CHARS = re.compile(r"[^A-Z0-9\-./ ]")
_REV_SUFFIX = re.compile(r"\(\d+(\.\d+)?\)$")   # LG style "EAX67133404(1.0)"


def part_number_problem(part: str) -> bool:
    """True when the string contains characters that cannot be in a part number (OCR misreads)."""
    return bool(_INVALID_PART_CHARS.search(_REV_SUFFIX.sub("", part)))
_CATALOG_KIND = {"ram": "memory", "flash": "memory", "display_panel": "panel"}


def category_for(type_text: str | None) -> str:
    if not type_text:
        return "other"
    if type_text in CATEGORIES:
        return type_text
    for rx, cat in _TYPE_TO_CATEGORY:
        if rx.search(type_text):
            return cat
    return "other"


@dataclass
class ComponentAnalysis:
    component_id: int
    category: str
    part_number: str | None
    manufacturer: str | None
    match_status: str
    confidence: float
    facts: list[SpecFact] = field(default_factory=list)
    datasheet: dict | None = None
    warnings: list[str] = field(default_factory=list)
    specification: str = ""


SUMMARY_LABELS = [("mainboard", "Mainboard"), ("pcb_revision", "PCB revision"), ("boards", "Board part numbers"),
                  ("soc", "SoC / CPU"), ("gpu", "GPU"), ("ram", "RAM"), ("flash", "Flash"), ("wifi", "Wi-Fi"),
                  ("bluetooth", "Bluetooth"), ("wifi_bt", "Wi-Fi / BT module"), ("audio", "Audio"),
                  ("tcon", "T-Con"), ("power_supply", "Power supply"), ("panel", "Display panel")]


class HardwareAnalyzer:
    def __init__(self, db: Database, audit: AuditLogger, projects: ProjectService,
                 datasheets: DatasheetLibrary):
        self.db, self.audit, self.projects, self.datasheets = db, audit, projects, datasheets

    # ---- component CRUD ----------------------------------------------------------------
    def add_component(self, project_id: int, category: str, part_number: str | None,
                      manufacturer: str | None = None, board: str | None = "mainboard",
                      position: str | None = None, quantity: int = 1, evidence_id: int | None = None,
                      notes: str | None = None) -> int:
        """Manual entry. Confidence starts at 0.5 without evidence, 0.6 with an evidence image."""
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category {category!r}")
        if quantity < 1:
            raise ValueError("Quantity must be at least 1")
        self.projects.get(project_id)
        part = (part_number or "").strip().upper() or None
        cid = self.db.execute(
            "INSERT INTO hardware_components(project_id, component_type, component_name, manufacturer, part_number,"
            " evidence_id, confidence, verified_by_user, source_reference, board, position, quantity, notes)"
            " VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?)",
            (project_id, category, CATEGORIES[category], (manufacturer or "").strip() or None, part, evidence_id,
             0.6 if evidence_id else 0.5, "operator entry", board, (position or "").strip() or None,
             quantity, notes))
        self.audit.record("hardware.add", "tv_project", project_id, component_id=cid, part=part)
        return cid

    def update_component(self, component_id: int, **changes) -> None:
        allowed = {"component_type", "part_number", "manufacturer", "board", "position", "quantity", "notes",
                   "evidence_id"}
        bad = set(changes) - allowed
        if bad:
            raise ValueError(f"Not editable: {sorted(bad)}")
        if "component_type" in changes and changes["component_type"] not in CATEGORIES:
            raise ValueError("Unknown category")
        if not changes:
            return
        sets = ", ".join(f"{k}=?" for k in changes)
        self.db.execute(f"UPDATE hardware_components SET {sets}, match_status='not_analyzed' WHERE id=?",
                        tuple(changes.values()) + (component_id,))
        self.audit.record("hardware.update", "hardware_component", component_id, fields=sorted(changes))

    def delete_component(self, component_id: int) -> None:
        c = self.get(component_id)
        with self.db.transaction() as tx:
            tx.execute("DELETE FROM component_specs WHERE owner_kind='component' AND owner_id=?", (component_id,))
            tx.execute("UPDATE marking_detections SET hardware_component_id=NULL, status='pending'"
                       " WHERE hardware_component_id=?", (component_id,))
            tx.execute("DELETE FROM hardware_components WHERE id=?", (component_id,))
        self.audit.record("hardware.delete", "tv_project", c["project_id"], component_id=component_id)

    def get(self, component_id: int) -> dict:
        r = self.db.query_one("SELECT * FROM hardware_components WHERE id=?", (component_id,))
        if r is None:
            raise KeyError(component_id)
        return dict(r)

    def list(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM hardware_components WHERE project_id=? ORDER BY board, component_type, id", (project_id,))]

    def facts(self, owner_id: int, owner_kind: str = "component") -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM component_specs WHERE owner_kind=? AND owner_id=? ORDER BY attribute, confidence DESC",
            (owner_kind, owner_id))]

    def add_user_fact(self, component_id: int, attribute: str, value: str, unit: str | None,
                      reference: str) -> int:
        """Operator-entered specification (e.g. read from a paper datasheet). Reference is mandatory."""
        if not reference or not reference.strip():
            raise ValueError("A source reference is required for every specification value")
        self.get(component_id)
        fid = self.db.execute(
            "INSERT OR REPLACE INTO component_specs(owner_kind, owner_id, attribute, value, unit, source_type,"
            " source_reference, confidence) VALUES ('component',?,?,?,?,'user',?,0.9)",
            (component_id, attribute.strip(), value.strip(), unit, reference.strip()))
        self.audit.record("hardware.fact_add", "hardware_component", component_id, attribute=attribute)
        return fid

    # ---- analysis ------------------------------------------------------------------------
    def analyze(self, component_id: int) -> ComponentAnalysis:
        c = self.get(component_id)
        cat = category_for(c["component_type"])
        part = (c["part_number"] or "").strip().upper()
        warnings: list[str] = []
        facts: list[SpecFact] = []
        datasheet = None
        status = "unidentified"
        vendor = c["manufacturer"]
        part_ok = bool(part) and not part_number_problem(part)
        if not part:
            warnings.append("No part number recorded — nothing can be identified.")
        elif not part_ok:
            warnings.append(f"Part number '{part}' contains characters that do not occur in part numbers "
                            "(probable OCR misread). Correct it before analysis; no specification derived.")

        if part_ok:
            rule = mk.match(part)
            if rule:
                r, norm, _ = rule
                ref = f"marking rule {r.id}"
                if r.vendor:
                    facts.append(SpecFact("manufacturer", r.vendor, None, "marking_rule", ref, r.strength))
                facts.append(SpecFact("device_family", r.type, None, "marking_rule", ref, r.strength))
                if r.note:
                    warnings.append(r.note)
                status = "vendor_only"
                if cat == "other" and c["component_type"] not in CATEGORIES:
                    cat = category_for(r.type)
            dec = decode(part)
            if dec:
                facts.extend(dec[1])
                status = "decoded"
            ref_facts = self._reference_facts(part)
            if ref_facts:
                facts.extend(ref_facts)
                status = max(status, "decoded", key=_rank)
            matches = self.datasheets.find(part)
            if matches:
                best = matches[0]
                ds = self.datasheets.get(best.datasheet_id)
                datasheet = {"id": ds["id"], "title": ds["title"], "level": best.level,
                             "matched_part": best.matched_part, "page": best.page, "source_url": ds["source_url"]}
                ds_facts = extract_facts(self.datasheets.pages(best.datasheet_id), best.datasheet_id)
                if best.level == "family":
                    warnings.append(f"Datasheet #{ds['id']} covers {best.matched_part}, a variant of this part "
                                    "family; ordering suffix (package, speed, temperature) must be checked.")
                    for f in ds_facts:
                        f.confidence = round(f.confidence * 0.7, 3)
                facts.extend(ds_facts)
                facts = _corroborate(facts, warnings, 0.9 if best.level == "exact" else 0.85)
                status = "datasheet_exact" if best.level == "exact" else max(status, "datasheet_family", key=_rank)

        if not vendor:
            v = _best(facts, "manufacturer")
            vendor = v.value if v else None
        base = c["confidence"] or 0.5
        conf = {"datasheet_exact": max(base, 0.9), "datasheet_family": max(base, 0.75),
                "decoded": max(base, 0.75), "vendor_only": base, "unidentified": min(base, 0.4)}[status]
        spec = summarize(facts)

        with self.db.transaction() as tx:
            tx.execute("DELETE FROM component_specs WHERE owner_kind='component' AND owner_id=?"
                       " AND source_type<>'user'", (component_id,))
            for f in facts:
                tx.execute("INSERT OR IGNORE INTO component_specs(owner_kind, owner_id, attribute, value, unit,"
                           " source_type, source_reference, confidence) VALUES ('component',?,?,?,?,?,?,?)",
                           (component_id, f.attribute, f.value, f.unit, f.source_type, f.source_reference,
                            f.confidence))
            tx.execute("UPDATE hardware_components SET component_type=?, component_name=COALESCE(component_name,?),"
                       " manufacturer=?, match_status=?, confidence=?, specification=?, datasheet_id=?,"
                       " analyzed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), source_reference=?,"
                       " analysis_warnings=? WHERE id=?",
                       (cat, CATEGORIES[cat], vendor, status, round(conf, 3), spec,
                        datasheet["id"] if datasheet else None,
                        "; ".join(sorted({f.source_reference for f in facts})) or c["source_reference"],
                        json.dumps(warnings), component_id))
        self.audit.record("hardware.analyze", "hardware_component", component_id, status=status, facts=len(facts))
        user = [SpecFact(r["attribute"], r["value"], r["unit"], "user", r["source_reference"], r["confidence"])
                for r in self.facts(component_id) if r["source_type"] == "user"]
        return ComponentAnalysis(component_id, cat, part or None, vendor, status, round(conf, 3), facts + user,
                                 datasheet, warnings, spec)

    def analyze_project(self, project_id: int) -> list[ComponentAnalysis]:
        out = [self.analyze(c["id"]) for c in self.list(project_id)]
        self.db.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                        " VALUES (?, 'hardware', ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                        (project_id, f"Hardware analysis: {len(out)} components"))
        return out

    def _reference_facts(self, part: str) -> list[SpecFact]:
        """Facts stored earlier in the reference DB for the same part (carry their original sources)."""
        c = canonical(part)
        out = []
        for kind, table in (("chipset", "chipsets"), ("memory", "memory_chips"), ("panel", "display_panels")):
            col = "panel_model" if kind == "panel" else "part_number"
            for r in self.db.query(f"SELECT id, {col} AS pn FROM {table}"):
                if canonical(r["pn"]) == c:
                    for f in self.facts(r["id"], kind):
                        out.append(SpecFact(f["attribute"], f["value"], f["unit"], f["source_type"],
                                            f"reference DB {kind} #{r['id']} ← {f['source_reference']}",
                                            f["confidence"]))
        return out

    # ---- board summary ------------------------------------------------------------------
    def board_summary(self, project_id: int) -> dict:
        p = self.projects.get(project_id)
        comps = self.list(project_id)
        by_cat: dict[str, list[dict]] = {}
        for c in comps:
            by_cat.setdefault(category_for(c["component_type"]), []).append(c)

        def names(cat):
            return [f"{c['manufacturer'] or '?'} {c['part_number'] or '(no part number)'}"
                    + (f" ×{c['quantity']}" if c["quantity"] > 1 else "") for c in by_cat.get(cat, [])]

        summary = {
            "mainboard": p.mainboard or "not identified",
            "pcb_revision": p.pcb_revision or "not identified",
            "boards": names("board"),
            "panel": p.panel_model or (names("display_panel") or ["not identified"])[0],
        }
        for cat in ("soc", "gpu", "wifi", "bluetooth", "wifi_bt", "audio", "tcon", "power_supply"):
            summary[cat] = names(cat) or ["not identified (no evidence)"]
        summary["ram"] = self._capacity_total(by_cat.get("ram", []), "RAM")
        summary["flash"] = self._capacity_total(by_cat.get("flash", []), "flash")
        return summary

    def _capacity_total(self, comps: list[dict], label: str) -> dict:
        if not comps:
            return {"chips": [], "total": None, "text": f"{label}: not identified (no evidence)"}
        chips, missing, total_bytes, sources, min_conf = [], 0, 0, set(), 1.0
        for c in comps:
            facts = self.facts(c["id"])
            cap = _best_row(facts, "capacity_bytes")
            den = _best_row(facts, "density_bits")
            if cap:
                b = int(cap["value"]) * c["quantity"]
                src = cap
            elif den:
                b = int(den["value"]) // 8 * c["quantity"]
                src = den
            else:
                missing += 1
                chips.append(f"{c['part_number'] or '?'}: capacity unknown")
                continue
            total_bytes += b
            label_src = "decoder + datasheet" if "corroborated" in src["source_reference"] else src["source_type"]
            sources.add(label_src)
            min_conf = min(min_conf, src["confidence"])
            chips.append(f"{c['part_number']} ×{c['quantity']}: {format_bytes(b // c['quantity'])} each "
                         f"({label_src})")
        if missing:
            return {"chips": chips, "total": None,
                    "text": f"{label}: total not determined — {missing} of {len(comps)} chip(s) have no capacity evidence"}
        return {"chips": chips, "total": total_bytes, "confidence": round(min_conf, 2), "sources": sorted(sources),
                "text": f"{label}: {format_bytes(total_bytes)} total (from {', '.join(sorted(sources))}; "
                        f"confidence {min_conf:.0%}{'; confirm with datasheet' if 'decoder' in sources else ''})"}

    # ---- reference database ----------------------------------------------------------------
    def save_to_reference(self, component_id: int) -> tuple[str, int]:
        """Store an analysed component in the reference DB (chipsets / memory_chips / display_panels)
        together with all its facts and their sources."""
        c = self.get(component_id)
        if not c["part_number"]:
            raise ValueError("Component has no part number")
        if c["match_status"] in ("not_analyzed",):
            raise ValueError("Analyse the component first")
        cat = category_for(c["component_type"])
        kind = _CATALOG_KIND.get(cat, "chipset")
        facts = self.facts(component_id)
        ds_url = None
        if c["datasheet_id"]:
            ds_url = self.datasheets.get(c["datasheet_id"])["source_url"]
        src = f"tv_project #{c['project_id']} component #{component_id}"
        with self.db.transaction() as tx:
            if kind == "memory":
                cap_bytes = proven_capacity_bytes(facts)
                mtype = _best_row(facts, "memory_type")
                tx.execute("INSERT OR IGNORE INTO memory_chips(vendor, part_number) VALUES (?,?)",
                           (c["manufacturer"], c["part_number"]))
                rid = tx.execute("SELECT id FROM memory_chips WHERE vendor IS ? AND part_number=?",
                                 (c["manufacturer"], c["part_number"])).fetchone()[0]
                tx.execute("UPDATE memory_chips SET memory_type=COALESCE(?,memory_type),"
                           " capacity_bytes=COALESCE(?,capacity_bytes), datasheet_url=COALESCE(?,datasheet_url),"
                           " source_reference=? WHERE id=?",
                           (mtype["value"] if mtype else None, cap_bytes, ds_url, src, rid))
            elif kind == "panel":
                tx.execute("INSERT OR IGNORE INTO display_panels(vendor, panel_model, source_reference) VALUES (?,?,?)",
                           (c["manufacturer"], c["part_number"], src))
                rid = tx.execute("SELECT id FROM display_panels WHERE vendor IS ? AND panel_model=?",
                                 (c["manufacturer"], c["part_number"])).fetchone()[0]
            else:
                tx.execute("INSERT OR IGNORE INTO chipsets(vendor, part_number, chip_type) VALUES (?,?,?)",
                           (c["manufacturer"], c["part_number"], cat))
                rid = tx.execute("SELECT id FROM chipsets WHERE vendor IS ? AND part_number=?",
                                 (c["manufacturer"], c["part_number"])).fetchone()[0]
                spec = c["specification"]
                tx.execute("UPDATE chipsets SET chip_type=?, specification=COALESCE(?,specification),"
                           " datasheet_url=COALESCE(?,datasheet_url), source_reference=? WHERE id=?",
                           (cat, spec, ds_url, src, rid))
            for f in facts:
                if f["source_reference"].startswith("reference DB"):
                    continue  # already there
                tx.execute("INSERT OR IGNORE INTO component_specs(owner_kind, owner_id, attribute, value, unit,"
                           " source_type, source_reference, confidence) VALUES (?,?,?,?,?,?,?,?)",
                           (kind, rid, f["attribute"], f["value"], f["unit"], f["source_type"],
                            f["source_reference"], f["confidence"]))
            tx.execute("UPDATE hardware_components SET catalog_kind=?, catalog_id=? WHERE id=?", (kind, rid, component_id))
        self.audit.record("reference.save", kind, rid, component_id=component_id)
        return kind, rid

    def reference_entries(self) -> list[dict]:
        rows = []
        for kind, table, pn, typ in (("chipset", "chipsets", "part_number", "chip_type"),
                                     ("memory", "memory_chips", "part_number", "memory_type"),
                                     ("panel", "display_panels", "panel_model", "interface")):
            for r in self.db.query(f"SELECT id, vendor, {pn} AS pn, {typ} AS typ, source_reference FROM {table}"):
                n = self.db.scalar("SELECT COUNT(*) FROM component_specs WHERE owner_kind=? AND owner_id=?",
                                   (kind, r["id"]))
                rows.append({"kind": kind, "id": r["id"], "vendor": r["vendor"], "part_number": r["pn"],
                             "type": r["typ"], "facts": n, "source": r["source_reference"]})
        return rows


# ---- helpers -------------------------------------------------------------------------------
_RANKS = ["unidentified", "vendor_only", "decoded", "datasheet_family", "datasheet_exact"]


def _rank(s: str) -> int:
    return _RANKS.index(s)


def _best(facts: list[SpecFact], attr: str) -> SpecFact | None:
    c = [f for f in facts if f.attribute == attr]
    return max(c, key=lambda f: f.confidence) if c else None


def _best_row(rows: list[dict], attr: str) -> dict | None:
    c = [r for r in rows if r["attribute"] == attr]
    return max(c, key=lambda r: r["confidence"]) if c else None


def proven_capacity_bytes(facts: list[dict]) -> int | None:
    """Capacity that may be stored as a reference value (not just shown as a fact):
    1. a decoder value corroborated by the datasheet,
    2. otherwise an operator-entered value (always has a reference),
    3. otherwise a datasheet value, only if the datasheet states exactly one capacity/density
       (a sheet covering several densities is ambiguous).
    Decoder-only values are never stored as proven capacity."""
    def to_bytes(r):
        return int(r["value"]) // 8 if r["attribute"] == "density_bits" else int(r["value"])
    rel = [r for r in facts if r["attribute"] in ("density_bits", "capacity_bytes")]
    for r in rel:
        if r["source_type"] == "decoder" and "corroborated" in r["source_reference"]:
            return to_bytes(r)
    for r in rel:
        if r["source_type"] == "user":
            return to_bytes(r)
    ds = {to_bytes(r) for r in rel if r["source_type"] == "datasheet"}
    return ds.pop() if len(ds) == 1 else None


def _corroborate(facts: list[SpecFact], warnings: list[str], boost: float = 0.9) -> list[SpecFact]:
    """Decoder facts confirmed by the datasheet get higher confidence; contradictions are reported."""
    def key(f):
        return (f.attribute, memory_family(f.value) if f.attribute == "memory_type" else f.value)
    ds = {key(f) for f in facts if f.source_type == "datasheet"}
    ds_attrs = {f.attribute for f in facts if f.source_type == "datasheet"}
    for f in facts:
        if f.source_type != "decoder" or f.attribute not in ("memory_type", "density_bits", "capacity_bytes"):
            continue
        if key(f) in ds:
            f.confidence = max(f.confidence, boost)
            f.source_reference += " (corroborated by datasheet)"
        elif f.attribute in ds_attrs:
            shown = format_bits(int(f.value)) if f.attribute == "density_bits" else f.value
            warnings.append(f"Decoded {f.attribute} {shown} is not stated in the matched datasheet — check the "
                            "datasheet's ordering information.")
    return facts


def summarize(facts: list[SpecFact]) -> str:
    """Short specification text. Each value marked with its source type."""
    parts = []
    for attr in ("memory_type", "density_bits", "capacity_bytes", "organization", "device_family", "interface",
                 "supply_voltage", "data_rate", "package"):
        f = _best(facts, attr)
        if not f:
            continue
        v = f.value
        if attr == "density_bits":
            v = format_bits(int(v))
        elif attr == "capacity_bytes":
            v = format_bytes(int(v))
        elif f.unit and attr not in ("density_bits",):
            v = f"{v} {f.unit}"
        parts.append(f"{v} [{f.source_type}]")
    return ", ".join(parts)


def facts_to_json(facts: list[SpecFact]) -> str:
    return json.dumps([f.__dict__ for f in facts])
