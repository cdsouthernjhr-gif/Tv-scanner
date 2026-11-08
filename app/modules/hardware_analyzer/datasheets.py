"""Local datasheet library and datasheet matching.

* PDFs are copied into ``<data>/Datasheets/<Vendor>/`` read-only, SHA-256 verified,
  deduplicated; the operator's file is only read.
* Text is extracted per page (pypdf) and stored, so matching works offline.
* Part numbers mentioned in a datasheet are indexed in canonical form.
* Specification facts are extracted with regexes, each tied to a page number,
  and only from a datasheet that actually mentions the component's part
  number (exactly or as the same base family).

Datasheets are never downloaded automatically; ``source_url`` is whatever the
operator states (or empty).
"""
from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.hardware_analyzer.decoders import SpecFact
from app.modules.identification.catalog import canonical
from app.security.audit import AuditLogger
from app.security.file_protection import ensure_within, make_read_only, safe_component
from app.security.hashing import sha256_file

log = logging.getLogger(__name__)

MAX_PAGES_INDEXED = 400
# Candidate part numbers inside datasheet text: letters+digits, 6..24 chars, may contain '-'.
_PART_TOKEN = re.compile(r"\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]{2,})?\b")
_NOT_PART = re.compile(r"^(LP)?DDR\d|^USB\d|^HDMI|^PCIE|^\d")
_TOKEN_STOP = {"DDR3", "DDR4", "DDR3L", "LPDDR4", "SPI", "QSPI", "JEDEC", "RoHS", "FBGA", "WSON", "SOIC",
               "USON", "VFBGA", "TFBGA", "ROHS", "PDF", "REV", "MHZ", "MBPS"}


@dataclass
class DatasheetMatch:
    datasheet_id: int
    title: str | None
    vendor: str | None
    level: str                # 'exact' | 'family'
    matched_part: str
    page: int | None
    score: float


@dataclass
class DuplicateDatasheet(Exception):
    datasheet_id: int

    def __str__(self) -> str:
        return f"Datasheet already in library (id={self.datasheet_id})"


# ---- fact extraction ---------------------------------------------------------------
# Case matters: "Gb"/"Gbit" = gigabits, "GB" = gigabytes.
_DENSITY = re.compile(r"\b(\d{1,4})\s*-?\s*([GM])\s*-?\s*(?:[Bb]it|BIT|b)\b(?!\s*/\s*s)")
_BYTES = re.compile(r"\b(\d{1,4})\s*([GM])B\b(?!\s*/\s*s)")
_MEMTYPE = re.compile(r"\b(LPDDR4X?|LPDDR3|DDR4|DDR3L|DDR3|DDR2|SPI\s+NOR|SPI\s+NAND|SERIAL\s+NOR|"
                      r"NAND\s+FLASH|E\s?MMC|UFS)\b", re.I)
_VOLT_RANGE = re.compile(r"\b(\d\.\d{1,2})\s*V?\s*(?:TO|-|–|~)\s*(\d\.\d{1,2})\s*V\b", re.I)
_VDD = re.compile(r"\bV(?:DD|CC)\s*(?:=|:)?\s*(\d\.\d{1,3})\s*V\b", re.I)
_SPEED = re.compile(r"\b(?:DDR[34]L?-(\d{3,4})|(\d{3,4})\s*(?:MT/S|MBPS))\b", re.I)
_FREQ = re.compile(r"\b(\d{2,4})\s*MHZ\b", re.I)
_PACKAGE = re.compile(r"\b(\d{2,3}-?BALL\s+[A-Z]*BGA|[A-Z]?FBGA-?\d{0,3}|WSON-?\d{1,2}|SOIC-?\d{1,2}|"
                      r"USON-?\d{1,2}|TSOP-?\d{0,2}|BGA-?\d{2,3}|QFN-?\d{2,3}|LQFP-?\d{2,3})\b", re.I)
_TEMP = re.compile(r"(-\d{2})\s*°?\s*C?\s*(?:TO|~)\s*\+?(\d{2,3})\s*°?\s*C", re.I)
_INTERFACE = re.compile(r"\b(V-BY-ONE(?:\s*HS)?|LVDS|EDP|MIPI\s*DSI|HDMI\s*2\.\d|HDMI|I2S|USB\s*[23]\.\d|"
                        r"PCIE|SDIO|802\.11\s*[A-Z/]+|BLUETOOTH\s*\d\.\d)\b", re.I)


def extract_facts(pages: list[tuple[int, str]], datasheet_id: int, max_per_attr: int = 3) -> list[SpecFact]:
    """Pattern-based fact extraction. Confidence 0.6–0.7: the text states it, but
    a datasheet can cover several variants, so the operator should confirm."""
    found: dict[tuple[str, str], SpecFact] = {}
    counts: dict[str, int] = {}

    def add(attr, value, unit, page, conf):
        key = (attr, value)
        if key in found or counts.get(attr, 0) >= max_per_attr:
            return
        counts[attr] = counts.get(attr, 0) + 1
        found[key] = SpecFact(attr, value, unit, "datasheet", f"datasheet #{datasheet_id} p.{page}", conf)

    for page, text in pages:
        for m in _MEMTYPE.finditer(text):
            add("memory_type", re.sub(r"\s+", " ", m.group(1).upper()), None, page, 0.65)
        for m in _DENSITY.finditer(text):
            n, u = int(m.group(1)), m.group(2).upper()
            bits = n * (1024 ** 3 if u == "G" else 1024 ** 2)
            if 1024 ** 2 <= bits <= 1024 ** 4:
                add("density_bits", str(bits), "bit", page, 0.6)
        for m in _BYTES.finditer(text):
            n, u = int(m.group(1)), m.group(2)
            add("capacity_bytes", str(n * (1024 ** 3 if u == "G" else 1024 ** 2)), "byte", page, 0.6)
        for m in _VOLT_RANGE.finditer(text):
            lo, hi = float(m.group(1)), float(m.group(2))
            if 0.5 <= lo < hi <= 15:
                add("supply_voltage", f"{lo:g}-{hi:g}", "V", page, 0.65)
        for m in _VDD.finditer(text):
            v = float(m.group(1))
            if 0.5 <= v <= 15:
                add("supply_voltage", f"{v:g}", "V", page, 0.65)
        for m in _SPEED.finditer(text):
            add("data_rate", m.group(1) or m.group(2), "MT/s", page, 0.6)
        for m in _FREQ.finditer(text):
            add("clock_frequency", m.group(1), "MHz", page, 0.55)
        for m in _PACKAGE.finditer(text):
            add("package", m.group(1).upper(), None, page, 0.65)
        for m in _TEMP.finditer(text):
            add("temperature_range", f"{m.group(1)}..+{m.group(2)}", "°C", page, 0.6)
        for m in _INTERFACE.finditer(text):
            add("interface", re.sub(r"\s+", " ", m.group(1).upper()), None, page, 0.6)
    return list(found.values())


def memory_family(v: str) -> str:
    """Comparable form of a memory type: 'DDR3 SDRAM' == 'DDR3', 'Serial NOR' == 'SPI NOR flash'."""
    t = re.sub(r"[^A-Z0-9]", "", v.upper())
    for word in ("SDRAM", "FLASH", "MEMORY"):
        t = t.replace(word, "")
    return t.replace("SERIALNOR", "SPINOR").replace("SERIALNAND", "SPINAND")


def base_family(part: str) -> str:
    """Part number without ordering suffixes: leading letters + first digit run + following
    letters up to the next digit run that starts a package/speed code.

    W25Q64JVSIQ -> W25Q64, K4B4G1646E-BYK0 -> K4B4G1646, MSD6A648 -> MSD6A648
    (shown before OCR folding).
    Used only for 'family' (not exact) matches.
    """
    plain = re.sub(r"[^A-Z0-9]", "", part.upper())
    m = re.match(r"^([A-Z]+\d+(?:[A-Z]{1,2}\d+){0,2})", plain)
    base = m.group(1) if m else plain
    # returned in canonical (OCR-folded) form; folding is per character so prefixes are kept
    return canonical(base if len(base) >= 5 else plain)


class DatasheetLibrary:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger):
        self.config, self.db, self.audit = config, db, audit

    @property
    def root(self) -> Path:
        return self.config.data_dir / "Datasheets"

    def import_pdf(self, source: str | Path, vendor: str | None = None, title: str | None = None,
                   source_url: str | None = None) -> int:
        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(source)
        with open(source, "rb") as fh:
            if fh.read(5) != b"%PDF-":
                raise ValueError("Not a PDF file")
        digest = sha256_file(source)
        row = self.db.query_one("SELECT id FROM datasheets WHERE sha256=?", (digest,))
        if row:
            raise DuplicateDatasheet(row[0])
        dest_dir = self.root / safe_component(vendor)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / safe_component(source.name, "datasheet.pdf")
        if dest.exists():
            dest = dest_dir / f"{dest.stem}__{digest[:12]}{dest.suffix}"
        ensure_within(self.root, dest)
        shutil.copy2(source, dest)
        if sha256_file(dest) != digest:
            dest.unlink(missing_ok=True)
            raise IOError("Datasheet copy verification failed")
        make_read_only(dest)
        did = self.db.execute(
            "INSERT INTO datasheets(vendor, title, original_filename, stored_path, sha256, file_size, source_url)"
            " VALUES (?,?,?,?,?,?,?)",
            (vendor, title, source.name, str(dest), digest, dest.stat().st_size, source_url))
        try:
            self.index(did)
        except Exception as exc:  # keep the file; indexing can be retried
            log.warning("Datasheet %s text extraction failed: %s", did, exc)
        self.audit.record("datasheet.import", "datasheet", did, sha256=digest, source=str(source))
        return did

    def index(self, datasheet_id: int) -> int:
        from pypdf import PdfReader
        ds = self.get(datasheet_id)
        reader = PdfReader(ds["stored_path"])
        pages = []
        for i, page in enumerate(reader.pages[:MAX_PAGES_INDEXED], start=1):
            try:
                pages.append((i, page.extract_text() or ""))
            except Exception as exc:
                log.warning("page %s of datasheet %s: %s", i, datasheet_id, exc)
                pages.append((i, ""))
        parts: dict[str, tuple[str, int]] = {}
        for pno, text in pages:
            for tok in _PART_TOKEN.findall(text.upper()):
                if tok in _TOKEN_STOP or len(tok) < 5 or _NOT_PART.match(tok):
                    continue
                c = canonical(tok)
                parts.setdefault(c, (tok, pno))
        title = ds["title"]
        if not title and reader.metadata and reader.metadata.title:
            title = str(reader.metadata.title)[:200]
        with self.db.transaction() as c:
            c.execute("DELETE FROM datasheet_pages WHERE datasheet_id=?", (datasheet_id,))
            c.execute("DELETE FROM datasheet_parts WHERE datasheet_id=?", (datasheet_id,))
            c.executemany("INSERT INTO datasheet_pages(datasheet_id, page, text) VALUES (?,?,?)",
                          [(datasheet_id, p, t) for p, t in pages])
            c.executemany("INSERT INTO datasheet_parts(datasheet_id, part_number, canonical, first_page)"
                          " VALUES (?,?,?,?)", [(datasheet_id, raw, can, pg) for can, (raw, pg) in parts.items()])
            c.execute("UPDATE datasheets SET page_count=?, text_extracted=1, title=? WHERE id=?",
                      (len(reader.pages), title, datasheet_id))
        return len(parts)

    def get(self, datasheet_id: int) -> dict:
        row = self.db.query_one("SELECT * FROM datasheets WHERE id=?", (datasheet_id,))
        if row is None:
            raise KeyError(datasheet_id)
        return dict(row)

    def list(self) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT d.*, (SELECT COUNT(*) FROM datasheet_parts p WHERE p.datasheet_id=d.id) AS part_count"
            " FROM datasheets d ORDER BY d.id DESC")]

    def pages(self, datasheet_id: int) -> list[tuple[int, str]]:
        return [(r["page"], r["text"]) for r in self.db.query(
            "SELECT page, text FROM datasheet_pages WHERE datasheet_id=? ORDER BY page", (datasheet_id,))]

    def find(self, part_number: str) -> list[DatasheetMatch]:
        """Exact canonical match first; otherwise same base family (lower score)."""
        c = canonical(part_number)
        if len(c) < 4:
            return []
        out: dict[int, DatasheetMatch] = {}
        for r in self.db.query(
                "SELECT p.*, d.title, d.vendor FROM datasheet_parts p JOIN datasheets d ON d.id=p.datasheet_id"
                " WHERE p.canonical=?", (c,)):
            out[r["datasheet_id"]] = DatasheetMatch(r["datasheet_id"], r["title"], r["vendor"], "exact",
                                                    r["part_number"], r["first_page"], 1.0)
        fam = base_family(part_number)
        if fam != c and len(fam) >= 5:
            for r in self.db.query(
                    "SELECT p.*, d.title, d.vendor FROM datasheet_parts p JOIN datasheets d ON d.id=p.datasheet_id"
                    " WHERE p.canonical LIKE ?", (fam + "%",)):
                if r["datasheet_id"] not in out:
                    out[r["datasheet_id"]] = DatasheetMatch(r["datasheet_id"], r["title"], r["vendor"], "family",
                                                            r["part_number"], r["first_page"], 0.6)
        return sorted(out.values(), key=lambda m: -m.score)
