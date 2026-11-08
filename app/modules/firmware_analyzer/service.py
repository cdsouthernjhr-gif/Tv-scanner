"""Firmware Analyzer orchestration.

Run sequence (each step stored with the run id):

1. Integrity: the library copy must still match its recorded SHA-256 (else abort).
2. Working copy in ``workspace/fw_<id>/`` — verified by hash; re-created if it was altered.
3. Native deep signature scan → ``firmware_components`` (source 'native').
4. Entropy + encryption indicators.
5. Strings (full dump to the run folder; categorised hits stored).
6. Binwalk (optional second opinion) → components with source 'binwalk'.
7. Safe extraction of filesystems/archives/compressed streams/partitions →
   ``firmware_extracted_files`` (hash, config/sensitive classification).
8. Metadata facts with provenance → ``firmware_metadata``.
9. Integrity re-check of the original: ``original_unchanged`` recorded.
"""
from __future__ import annotations

import json
import logging
import shutil
import traceback
from dataclasses import asdict
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.integrations.binwalk import adapter as bw
from app.integrations.ghidra import adapter as gh
from app.modules.firmware_analyzer import compare as cmp
from app.modules.firmware_analyzer import config_discovery, entropy, metadata, scanner, strings_analysis
from app.modules.firmware_analyzer.extractor import ExtractionEntry, Limits, SafeExtractor
from app.modules.firmware_library.library import FirmwareLibrary
from app.security.audit import AuditLogger
from app.security.hashing import sha256_file
from app.services.external_tools import detect_tools

log = logging.getLogger(__name__)
EXTRACTABLE = {"squashfs", "cramfs", "ext2", "ext3", "ext4", "zip", "tar", "cpio", "7z", "gzip", "xz", "bzip2",
               "lzma", "uimage", "android_sparse", "jffs2", "ubi", "ubifs"}


def _python_tool(name: str) -> str | None:
    """CLI installed by pip: on PATH, or next to the interpreter (venv Scripts/bin not activated)."""
    import sys
    found = shutil.which(name)
    if found:
        return found
    base = Path(sys.executable).parent
    for cand in (base / name, base / f"{name}.exe", base / "Scripts" / f"{name}.exe"):
        if cand.is_file():
            return str(cand)
    return None


class IntegrityError(Exception):
    pass


class FirmwareAnalyzer:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger, library: FirmwareLibrary):
        self.config, self.db, self.audit, self.library = config, db, audit, library

    # ---- tools ---------------------------------------------------------------------------
    def tools(self) -> dict[str, str | None]:
        found = {t.key: t.path for t in detect_tools(self.config)}
        found["unsquashfs"] = shutil.which("unsquashfs")
        found["debugfs"] = shutil.which("debugfs")
        found["jefferson"] = _python_tool("jefferson")
        found["ubireader"] = _python_tool("ubireader_extract_files")
        found["binwalk_cmd"] = bw.find_binwalk(self.config.get("tools.binwalk") or None)
        found["ghidra"] = gh.find_headless(self.config.get("tools.ghidra_headless") or None)
        return found

    # ---- working copy ------------------------------------------------------------------------
    def working_copy(self, firmware_id: int) -> Path:
        rec = self.library.get(firmware_id)
        wc = self.library.make_working_copy(firmware_id)
        if sha256_file(wc) != rec.sha256:      # altered by an earlier tool → recreate from the original
            wc.unlink()
            wc = self.library.make_working_copy(firmware_id)
            if sha256_file(wc) != rec.sha256:
                raise IntegrityError("working copy does not match the original's SHA-256")
        return wc

    # ---- main entry ---------------------------------------------------------------------------
    def analyze(self, firmware_id: int, extract: bool = True, use_binwalk: bool | None = None,
                run_strings: bool = True) -> int:
        rec = self.library.get(firmware_id)
        stored = Path(rec.stored_path)
        before = sha256_file(stored) if stored.is_file() else None
        if before != rec.sha256:
            self.library.verify_integrity(firmware_id)
            raise IntegrityError(f"Stored firmware #{firmware_id} no longer matches its recorded SHA-256 — "
                                 "analysis refused.")
        opts = {"extract": extract, "binwalk": use_binwalk, "strings": run_strings}
        run_id = self.db.execute("INSERT INTO firmware_analysis_runs(firmware_id, options_json, original_sha256_before)"
                                 " VALUES (?,?,?)", (firmware_id, json.dumps(opts), before))
        self.audit.record("firmware.analyze.start", "firmware_file", firmware_id, run_id=run_id)
        try:
            wc = self.working_copy(firmware_id)
            run_dir = wc.parent / f"run_{run_id}"
            run_dir.mkdir(parents=True, exist_ok=True)
            self.db.execute("UPDATE firmware_analysis_runs SET working_copy=? WHERE id=?", (str(wc), run_id))
            self._pipeline(firmware_id, run_id, rec, wc, run_dir, extract, use_binwalk, run_strings)
            status, error = "completed", None
        except Exception as exc:
            log.error("Analysis of firmware %s failed:\n%s", firmware_id, traceback.format_exc())
            status, error = "failed", str(exc)
        after = sha256_file(stored)
        unchanged = after == before
        self.db.execute("UPDATE firmware_analysis_runs SET status=?, error=?, original_sha256_after=?,"
                        " original_unchanged=?, finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                        (status, error, after, int(unchanged), run_id))
        if not unchanged:   # should be impossible (read-only file, only copies are processed)
            self.library.verify_integrity(firmware_id)
        if rec.project_id:
            self.db.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                            " VALUES (?, 'firmware', ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                            (rec.project_id, f"Firmware #{firmware_id} analysis run #{run_id}: {status}"))
        self.audit.record("firmware.analyze.finish", "firmware_file", firmware_id, run_id=run_id, status=status,
                          original_unchanged=unchanged, error=error)
        if status == "failed":
            raise RuntimeError(f"Analysis run #{run_id} failed: {error}")
        return run_id

    def _store(self, firmware_id, run_id, analyzer: str, result) -> None:
        self.db.execute("INSERT INTO firmware_analysis(firmware_id, analyzer, result_json, run_id) VALUES (?,?,?,?)",
                        (firmware_id, analyzer, json.dumps(result, default=str), run_id))

    def _pipeline(self, fid, run_id, rec, wc: Path, run_dir: Path, extract, use_binwalk, run_strings):
        # 3. signature scan
        sres = scanner.scan(wc)
        with self.db.transaction() as tx:
            for c in sres.components:
                tx.execute("INSERT INTO firmware_components(run_id, firmware_id, offset, size, type, category,"
                           " description, details_json, source, validated) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (run_id, fid, c.offset, c.size, c.type, c.category, c.description,
                            json.dumps({**c.details, "parent_offset": sres.components[c.parent].offset
                                        if c.parent is not None else None}, default=str), "native", int(c.validated)))
        self._store(fid, run_id, "signature_scan", {"file_size": sres.file_size, "components": len(sres.components),
                                                    "rejected_candidates": sres.rejected, "truncated": sres.truncated,
                                                    "gaps": scanner.gaps(sres)})
        # 4. entropy
        eres = entropy.analyze(wc, sres.components)
        self._store(fid, run_id, "entropy", asdict(eres))
        # 5. strings
        stres = None
        if run_strings:
            stres = strings_analysis.analyze(wc, run_dir / "strings.txt")
            self._store(fid, run_id, "strings", asdict(stres))
        # 6. binwalk
        tools = self.tools()
        want_bw = use_binwalk if use_binwalk is not None else bool(self.config.get("analysis.use_binwalk", True))
        if want_bw and tools.get("binwalk_cmd"):
            try:
                b = bw.scan(wc, tools["binwalk_cmd"])
                with self.db.transaction() as tx:
                    for h in b.hits:
                        tx.execute("INSERT INTO firmware_components(run_id, firmware_id, offset, size, type, category,"
                                   " description, source, validated) VALUES (?,?,?,?,?,?,?,?,0)",
                                   (run_id, fid, h.offset, h.size, "binwalk", "binwalk", h.description, "binwalk"))
                self._store(fid, run_id, "binwalk", {"version": b.version, "command": b.command, "hits": len(b.hits)})
            except Exception as exc:
                self._store(fid, run_id, "binwalk", {"error": str(exc)})
        else:
            self._store(fid, run_id, "binwalk", {"skipped": "disabled" if not want_bw else "binwalk not found"})
        # 7. extraction
        inv_facts: list = []
        if extract:
            entries, inv = self._extract(sres, wc, run_dir / "extracted", tools)
            self._store(fid, run_id, "extraction", [asdict(e) for e in entries])
            with self.db.transaction() as tx:
                for f in inv.files:
                    tx.execute("INSERT INTO firmware_extracted_files(run_id, firmware_id, rel_path, size, sha256, kind,"
                               " note) VALUES (?,?,?,?,?,?,?)", (run_id, fid, f.rel_path, f.size, f.sha256, f.kind,
                                                                 f.note))
            inv_facts = inv.facts
            self._store(fid, run_id, "config_discovery", {"config_files": [f.rel_path for f in inv.configs][:500],
                                                          "sensitive_files": [f.rel_path for f in inv.sensitive][:500],
                                                          "facts": inv.facts})
        # 8. metadata
        facts = metadata.build_facts(rec.original_filename, sres, stres, eres, inv_facts)
        with self.db.transaction() as tx:
            for f in facts:
                tx.execute("INSERT INTO firmware_metadata(run_id, firmware_id, attribute, value, source, confidence)"
                           " VALUES (?,?,?,?,?,?)", (run_id, fid, f.attribute, f.value, f.source, f.confidence))
            first = next((c for c in sres.components if c.offset == 0 and c.parent is None), None)
            if first:
                tx.execute("UPDATE firmware_files SET detected_format=? WHERE id=?", (first.description[:120], fid))
        self._store(fid, run_id, "metadata", [asdict(f) for f in facts])

    def _extract(self, sres: scanner.ScanResult, wc: Path, dest: Path, tools):
        limits = Limits(max_total_bytes=int(self.config.get("analysis.max_extract_bytes", 2 * 1024 ** 3)),
                        max_files=int(self.config.get("analysis.max_extract_files", 100_000)))
        ex = SafeExtractor(dest, tools, limits)
        entries: list[ExtractionEntry] = []
        comps = sres.components
        extracted_idx: set[int] = set()
        for i, c in enumerate(comps):
            if c.type not in EXTRACTABLE or not c.validated:
                continue
            # skip children of something already extracted (e.g. gzip inside a uImage, xz blocks in squashfs)
            p, nested = c.parent, False
            while p is not None:
                if p in extracted_idx or comps[p].type in EXTRACTABLE:
                    nested = True
                    break
                p = comps[p].parent
            if nested:
                continue
            e = ex.extract_component(wc, c)
            entries.append(e)
            if e.status in ("extracted", "carved"):
                extracted_idx.add(i)
        # partitions from MBR/GPT: carve, then extract a filesystem found at the partition start
        for c in comps:
            if c.category != "partition_table":
                continue
            for part in c.details.get("partitions", []):
                if not part.get("inside_image") or part["size"] <= 0:
                    continue
                label = (part.get("name") or f"p{part['index']}").replace("/", "_")
                e = ExtractionEntry("partition", part["offset"], "carve", "carved",
                                    str(dest / f"partition_{part['index']}_{label}.img"))
                try:
                    out = Path(e.dest)
                    e.bytes = ex.carve(wc, part["offset"], part["size"], out)
                    e.files = 1
                    sub = scanner.scan(out)
                    head = next((x for x in sub.components if x.offset == 0 and x.type in EXTRACTABLE), None)
                    if head:
                        inner = ex.extract_component(out, head)
                        e.message = f"contains {head.type}: {inner.status} ({inner.files} files)"
                        e.files += inner.files
                        e.skipped_links += inner.skipped_links
                except Exception as exc:
                    e.status, e.message = "failed", str(exc)
                entries.append(e)
        links = [l for e in entries for l in e.skipped_links]
        inv = config_discovery.inventory(dest, links) if dest.exists() else config_discovery.Inventory()
        return entries, inv

    # ---- queries -------------------------------------------------------------------------------
    def runs(self, firmware_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM firmware_analysis_runs WHERE firmware_id=? ORDER BY id DESC", (firmware_id,))]

    def latest_run(self, firmware_id: int, completed_only: bool = True) -> dict | None:
        sql = "SELECT * FROM firmware_analysis_runs WHERE firmware_id=?"
        if completed_only:
            sql += " AND status='completed'"
        r = self.db.query_one(sql + " ORDER BY id DESC LIMIT 1", (firmware_id,))
        return dict(r) if r else None

    def components(self, run_id: int) -> list[dict]:
        out = []
        for r in self.db.query("SELECT * FROM firmware_components WHERE run_id=? ORDER BY offset, source", (run_id,)):
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json") or "{}")
            out.append(d)
        return out

    def metadata(self, run_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM firmware_metadata WHERE run_id=? ORDER BY attribute, confidence DESC", (run_id,))]

    def files(self, run_id: int) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM firmware_extracted_files WHERE run_id=? ORDER BY rel_path", (run_id,))]

    def result(self, run_id: int, analyzer: str):
        r = self.db.query_one("SELECT result_json FROM firmware_analysis WHERE run_id=? AND analyzer=? "
                              "ORDER BY id DESC LIMIT 1", (run_id, analyzer))
        return json.loads(r[0]) if r else None

    def run_dir(self, run_id: int) -> Path:
        r = self.db.query_one("SELECT working_copy FROM firmware_analysis_runs WHERE id=?", (run_id,))
        if not r or not r[0]:
            raise KeyError(run_id)
        return Path(r[0]).parent / f"run_{run_id}"

    def read_bytes(self, firmware_id: int, offset: int, length: int = 4096) -> bytes:
        """Read-only access to the stored original (for the hex viewer)."""
        rec = self.library.get(firmware_id)
        with open(rec.stored_path, "rb") as fh:
            fh.seek(max(0, offset))
            return fh.read(max(0, min(length, 1 << 20)))

    # ---- comparison -----------------------------------------------------------------------------
    def compare(self, id_a: int, id_b: int) -> dict:
        def bundle(fid):
            rec = self.library.get(fid)
            run = self.latest_run(fid)
            return {"record": asdict(rec), "path": rec.stored_path,
                    "components": self.components(run["id"]) if run else [],
                    "metadata": self.metadata(run["id"]) if run else [],
                    "files": self.files(run["id"]) if run else [],
                    "analysed": run is not None}
        a, b = bundle(id_a), bundle(id_b)
        res = cmp.compare(a, b)
        res["analysed"] = {"a": a["analysed"], "b": b["analysed"]}
        self.audit.record("firmware.compare", "firmware_file", id_a, other=id_b)
        return res

    # ---- extras ------------------------------------------------------------------------------------
    def extracted_path(self, run_id: int, rel_path: str) -> Path:
        base = (self.run_dir(run_id) / "extracted").resolve()
        p = (base / rel_path).resolve()
        if base not in p.parents:
            raise ValueError("path outside extraction folder")
        return p

    def run_ghidra(self, firmware_id: int, run_id: int, rel_path: str, timeout_s: int = 600,
                   processor: str | None = None) -> dict:
        headless = self.tools().get("ghidra")
        if not headless:
            raise RuntimeError("Ghidra analyzeHeadless not found (set tools.ghidra_headless or GHIDRA_INSTALL_DIR)")
        target = self.extracted_path(run_id, rel_path)
        res = gh.analyze(headless, target, self.run_dir(run_id), timeout_s, processor)
        payload = {"file": rel_path, "command": res.command, "returncode": res.returncode, "summary": res.summary,
                   "log_tail": res.log_tail}
        self._store(firmware_id, run_id, "ghidra", payload)
        self.audit.record("firmware.ghidra", "firmware_file", firmware_id, run_id=run_id, file=rel_path,
                          ok=res.summary is not None)
        return payload

    def import_extracted(self, firmware_id: int, run_id: int, rel_path: str):
        """Add an extracted file (e.g. upgrade.bin inside a ZIP package) to the library with provenance."""
        parent = self.library.get(firmware_id)
        path = self.extracted_path(run_id, rel_path)
        return self.library.import_file(
            path, category=parent.category, manufacturer=parent.manufacturer, model_number=parent.model_number,
            mainboard=parent.mainboard, project_id=parent.project_id, source_type="extracted_from_firmware",
            download_url=parent.download_url,
            notes=f"Extracted from firmware #{firmware_id} ({parent.original_filename}) run #{run_id}: {rel_path}")
