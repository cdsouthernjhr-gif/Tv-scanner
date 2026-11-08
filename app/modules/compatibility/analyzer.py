"""Firmware Compatibility Analyzer (spec Module I).

Compares a *candidate* firmware (analysed in Phase 4) with what is known about
the TV: project identification, confirmed hardware (Phase 3), software facts
(Phase 6) and the TV's own current/original firmware (the *baseline*, when
one has been analysed).

Every criterion yields: TV value, firmware value, status
(match | mismatch | soft_mismatch | unknown | not_applicable), evidence, and
whether a mismatch is *hard* (makes the firmware INCOMPATIBLE).

Verdicts
--------
VERIFIED COMPATIBLE  content names this model, architecture agrees, mainboard or SoC
                     confirmed, partition layout identical to the baseline (or the
                     package is an official one for this exact model), signing scheme
                     consistent, integrity established, and no mismatch of any kind.
LIKELY COMPATIBLE    model confirmed by content, no hard mismatch, at most one soft concern.
POSSIBLE MATCH       some hardware evidence agrees, nothing hard disagrees.
INCOMPATIBLE         any hard mismatch (model, architecture, partition layout, signing,
                     RAM/flash too small, integrity failure).
INSUFFICIENT EVIDENCE candidate not analysed, or nothing could be compared.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.modules.firmware_finder.matching import find_identifier
from app.modules.hardware_analyzer.service import category_for
from app.modules.software_analyzer.inventory import classify_driver

VERDICTS = ("VERIFIED COMPATIBLE", "LIKELY COMPATIBLE", "POSSIBLE MATCH", "INCOMPATIBLE", "INSUFFICIENT EVIDENCE")
CRITERIA = ["model", "mainboard", "pcb_revision", "soc", "architecture", "ram", "flash", "panel", "bootloader",
            "display_drivers", "audio_drivers", "wifi_drivers", "partition_layout", "signing",
            "hardware_configuration", "integrity", "source"]


@dataclass
class Criterion:
    criterion: str
    tv_value: str | None
    fw_value: str | None
    status: str
    evidence: str
    hard: bool = False


@dataclass
class CompatibilityResult:
    verdict: str
    score: int
    criteria: list[Criterion] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    baseline_firmware_id: int | None = None
    candidate_firmware_id: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def _mem_from_cmdline(text: str) -> int | None:
    m = re.search(r"\bmem=(\d+)([KMG])", text or "")
    if not m:
        return None
    return int(m.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[m.group(2)]


def _bytes_from_text(t: str) -> int | None:
    m = re.search(r"(\d+(?:\.\d+)?)\s*(GB|MB)", t or "")
    if not m:
        return None
    return int(float(m.group(1)) * (1024 ** 3 if m.group(2) == "GB" else 1024 ** 2))


class FirmwareView:
    """Everything the analyzer needs from one analysed firmware."""

    def __init__(self, ctx, firmware_id: int):
        self.ctx, self.id = ctx, firmware_id
        self.record = ctx.library.get(firmware_id)
        self.run = ctx.firmware.latest_run(firmware_id)
        self.meta = ctx.firmware.metadata(self.run["id"]) if self.run else []
        self.files = [f["rel_path"] for f in ctx.firmware.files(self.run["id"])] if self.run else []
        self._strings_path = None
        if self.run:
            st = ctx.firmware.result(self.run["id"], "strings") or {}
            self._strings_path = st.get("dump_path")

    @property
    def analysed(self) -> bool:
        return self.run is not None

    def values(self, attr: str, min_conf: float = 0.7) -> set[str]:
        return {m["value"] for m in self.meta if m["attribute"] == attr and m["confidence"] >= min_conf}

    def mentions(self, ident: str | None, limit_lines: int = 2_000_000) -> str | None:
        """Where the identifier appears: metadata, file names or firmware strings (first hit)."""
        if not ident:
            return None
        for m in self.meta:
            if find_identifier(m["value"], ident):
                return f"metadata {m['attribute']} ({m['source'][:60]})"
        for f in self.files:
            if find_identifier(f, ident):
                return f"extracted file {f}"
        if self._strings_path and Path(self._strings_path).exists():
            key = re.sub(r"[^A-Z0-9]", "", ident.upper())[:3]
            with open(self._strings_path, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i > limit_lines:
                        break
                    # prefilter on the line without separators (identifiers like TP.MS338.PB801 contain dots)
                    if key in re.sub(r"[^A-Z0-9]", "", line.upper()) and find_identifier(line, ident):
                        return f"firmware string {line[:10].strip()}"
        return None

    def drivers(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for f in self.files:
            if f.endswith(".ko"):
                mod = f.rsplit("/", 1)[-1][:-3]
                out.setdefault(classify_driver(mod), set()).add(mod)
        return out

    def partitions(self) -> dict[str, int]:
        parts = {}
        for v in self.values("partition", 0.5):
            m = re.match(r"(.+?): offset (0x[0-9a-f]+), size ([\d,]+) B", v)
            if m:
                parts[m.group(1)] = int(m.group(3).replace(",", ""))
        for v in self.values("partition_info", 0.5):
            m = re.search(r"mtdparts=[^:]+:(.+)", v)
            if m:
                for p in m.group(1).split(","):
                    pm = re.match(r"(\d+|-)([kmg])?(?:@\w+)?\(([^)]+)\)", p.strip(), re.I)
                    if pm:
                        size = -1 if pm.group(1) == "-" else int(pm.group(1)) * {None: 1, "k": 1024, "m": 1024 ** 2,
                                                                                 "g": 1024 ** 3}[(pm.group(2) or "").lower() or None]
                        parts[pm.group(3)] = size
        return parts

    def panel_files(self) -> list[str]:
        return [f for f in self.files if "panel" in f.lower() and f.lower().endswith((".ini", ".bin", ".xml", ".txt", ".cfg"))]


class CompatibilityAnalyzer:
    def __init__(self, ctx):
        self.ctx = ctx

    def baseline_for(self, project_id: int, exclude: int | None = None) -> int | None:
        """The TV's own firmware: an analysed 'Original' firmware of the project (most recent)."""
        for fw in self.ctx.library.list(project_id=project_id):
            if fw.id != exclude and fw.category == "Original" and self.ctx.firmware.latest_run(fw.id):
                return fw.id
        return None

    def evaluate(self, project_id: int, firmware_id: int, baseline_id: int | None = None,
                 store: bool = True) -> CompatibilityResult:
        ctx = self.ctx
        p = ctx.projects.get(project_id)
        cand = FirmwareView(ctx, firmware_id)
        baseline_id = baseline_id if baseline_id is not None else self.baseline_for(project_id, firmware_id)
        base = FirmwareView(ctx, baseline_id) if baseline_id else None
        comps = ctx.hardware.list(project_id)
        summ = ctx.hardware.board_summary(project_id)
        sw = ctx.software.facts(project_id)
        res: list[Criterion] = []
        add = lambda *a, **k: res.append(Criterion(*a, **k))   # noqa: E731

        if not cand.analysed:
            r = CompatibilityResult("INSUFFICIENT EVIDENCE", 0, [], ["The candidate firmware has not been analysed — "
                                    "run the Firmware Analyzer first."], baseline_id, firmware_id)
            return self._store(project_id, r) if store else r

        # ---- model ---------------------------------------------------------------------------------
        fw_models = cand.values("product_model") | cand.values("product_device")
        if p.model_number and fw_models:
            if any(find_identifier(m, p.model_number) for m in fw_models):
                add("model", p.model_number, ", ".join(sorted(fw_models)), "match", "build properties of the firmware")
            else:
                add("model", p.model_number, ", ".join(sorted(fw_models)), "mismatch",
                    "firmware declares a different product model", hard=True)
        elif p.model_number and cand.mentions(p.model_number):
            add("model", p.model_number, "mentioned", "match", cand.mentions(p.model_number))
        else:
            add("model", p.model_number, None, "unknown" if p.model_number else "not_applicable",
                "firmware content does not name a model" if p.model_number else "TV model unknown")

        # ---- mainboard / pcb revision -------------------------------------------------------------------
        if p.mainboard:
            where = cand.mentions(p.mainboard)
            add("mainboard", p.mainboard, "mentioned" if where else None, "match" if where else "unknown",
                where or "mainboard number not found in firmware content")
            if p.pcb_revision:
                add("pcb_revision", p.pcb_revision, None, "unknown",
                    "firmware packages rarely state PCB revisions; confirm with the manufacturer's documentation")
        else:
            add("mainboard", None, None, "not_applicable", "TV mainboard unknown")

        # ---- SoC --------------------------------------------------------------------------------------------
        soc = next((c["part_number"] for c in comps if category_for(c["component_type"]) == "soc" and c["part_number"]), None)
        if soc:
            where = cand.mentions(soc)
            if where:
                add("soc", soc, "mentioned", "match", where)
            else:
                others = sorted(v.split(" (")[0] for v in cand.values("chip_mention", 0.4) if "SoC" in v)
                add("soc", soc, ", ".join(others) or None, "soft_mismatch" if others else "unknown",
                    f"firmware names other SoC(s): {', '.join(others)}" if others else "SoC not named in firmware")
        else:
            add("soc", None, None, "not_applicable", "TV SoC not identified (Hardware Analyzer)")

        # ---- architecture --------------------------------------------------------------------------------------
        fw_arch = cand.values("cpu_architecture")
        tv_arch = base.values("cpu_architecture") if base else set()
        if fw_arch and tv_arch:
            if fw_arch & tv_arch:
                add("architecture", ", ".join(sorted(tv_arch)), ", ".join(sorted(fw_arch)), "match",
                    "baseline and candidate analysis")
            else:
                add("architecture", ", ".join(sorted(tv_arch)), ", ".join(sorted(fw_arch)), "mismatch",
                    "different CPU architecture", hard=True)
        else:
            add("architecture", ", ".join(sorted(tv_arch)) or None, ", ".join(sorted(fw_arch)) or None, "unknown",
                "needs an analysed baseline firmware of this TV" if fw_arch else "candidate architecture unknown")

        # ---- RAM / flash ------------------------------------------------------------------------------------------
        ram = summ["ram"].get("total")
        need = None
        for v in cand.values("kernel_cmdline", 0.5):
            need = _mem_from_cmdline(v) or need
        if ram and need:
            ok = need <= ram
            add("ram", f"{ram // 1024 ** 2} MB", f"mem={need // 1024 ** 2} MB (kernel cmdline)", "match" if ok else "mismatch",
                "kernel memory setting fits installed RAM" if ok else "firmware expects more RAM than installed",
                hard=not ok)
        else:
            add("ram", f"{ram // 1024 ** 2} MB" if ram else None, None, "unknown",
                "firmware states no memory requirement" if ram else "TV RAM not determined")
        flash = summ["flash"].get("total")
        parts = cand.partitions()
        image_end = None
        for v in cand.values("partition", 0.5):
            m = re.match(r".+?: offset (0x[0-9a-f]+), size ([\d,]+) B", v)
            if m:
                end = int(m.group(1), 16) + int(m.group(2).replace(",", ""))
                image_end = max(image_end or 0, end)
        if flash and image_end:
            ok = image_end <= flash
            add("flash", f"{flash // 1024 ** 2} MB", f"partitions end at {image_end // 1024 ** 2} MB",
                "match" if ok else "mismatch", "full-image layout fits flash" if ok else "image larger than TV flash",
                hard=not ok)
        else:
            add("flash", f"{flash // 1024 ** 2} MB" if flash else None, None, "unknown",
                "candidate is not a full flash image with a partition table" if flash else "TV flash size not determined")

        # ---- panel -------------------------------------------------------------------------------------------------
        if p.panel_model:
            where = cand.mentions(p.panel_model)
            pf = cand.panel_files()
            add("panel", p.panel_model, f"{len(pf)} panel configuration file(s)" if pf else None,
                "match" if where else ("soft_mismatch" if pf else "unknown"),
                where or (f"panel not named among {len(pf)} panel configuration(s) — wrong panel settings can damage "
                          "the display or show no picture" if pf else "no panel configuration found in firmware"))
        else:
            add("panel", None, None, "not_applicable", "panel ID unknown (identify it from the panel label)")

        # ---- bootloader --------------------------------------------------------------------------------------------
        fw_bl = cand.values("bootloader")
        tv_bl = (base.values("bootloader") if base else set()) | {f["name"] for f in sw if f["category"] == "bootloader"}
        if fw_bl:
            same = bool(fw_bl & tv_bl)
            add("bootloader", ", ".join(sorted(tv_bl)) or None, ", ".join(sorted(fw_bl)),
                "match" if same else ("soft_mismatch" if tv_bl else "unknown"),
                "same bootloader" if same else ("package contains a different bootloader — a failed bootloader update "
                                                "can make the TV unrecoverable without service tools" if tv_bl
                                                else "package contains a bootloader; current bootloader unknown"))
        else:
            add("bootloader", ", ".join(sorted(tv_bl)) or None, None, "not_applicable",
                "package does not contain a bootloader (existing bootloader kept)")

        # ---- drivers -------------------------------------------------------------------------------------------------
        fw_drv = cand.drivers()
        tv_drv: dict[str, set[str]] = {}
        for f in sw:
            if f["category"] == "driver":
                tv_drv.setdefault(classify_driver(f["name"]), set()).add(f["name"].removesuffix(".ko"))
        if base:
            for k, v in base.drivers().items():
                tv_drv.setdefault(k, set()).update(v)
        for crit, cls, part_cat in (("display_drivers", "display", None), ("audio_drivers", "audio", "audio"),
                                    ("wifi_drivers", "wifi", "wifi")):
            tvs, fws = tv_drv.get(cls, set()), fw_drv.get(cls, set())
            if tvs and fws:
                common = tvs & fws
                add(crit, ", ".join(sorted(tvs))[:120], ", ".join(sorted(fws))[:120],
                    "match" if common else "soft_mismatch",
                    f"common module(s): {', '.join(sorted(common))}" if common else
                    "no common module — drivers may be built into the kernel; verify the function after upgrade")
            else:
                add(crit, ", ".join(sorted(tvs))[:120] or None, ", ".join(sorted(fws))[:120] or None, "unknown",
                    "loadable modules not available on both sides (drivers may be built into the kernel)")

        # ---- partition layout --------------------------------------------------------------------------------------
        bparts = base.partitions() if base else {}
        if parts and bparts:
            if parts == bparts:
                add("partition_layout", f"{len(bparts)} partitions", f"{len(parts)} partitions", "match",
                    "identical names and sizes")
            else:
                diff = sorted(set(parts) ^ set(bparts)) or [k for k in parts if parts[k] != bparts.get(k)]
                add("partition_layout", ", ".join(sorted(bparts))[:120], ", ".join(sorted(parts))[:120], "mismatch",
                    f"layout differs ({', '.join(diff[:6])}) — repartitioning is only acceptable when the manufacturer "
                    "documents it for this upgrade", hard=True)
        else:
            add("partition_layout", f"{len(bparts)} partitions" if bparts else None,
                f"{len(parts)} partitions" if parts else None, "unknown",
                "layout known on one side only" if (parts or bparts) else "no partition table in either image")

        # ---- signing ---------------------------------------------------------------------------------------------------
        fs, ts = cand.values("signing"), (base.values("signing") if base else set())
        fw_signed = any("NONE" not in v for v in fs)
        tv_signed = any("NONE" not in v for v in ts)
        if ts and tv_signed and not fw_signed:
            add("signing", ", ".join(ts), ", ".join(fs) or "no signature metadata", "mismatch",
                "the TV's firmware is signed but the candidate is not — the device will reject it, and bypassing "
                "signature checks is not permitted", hard=True)
        elif fs and ts:
            add("signing", ", ".join(ts), ", ".join(fs), "match" if fs == ts else "soft_mismatch",
                "same signing scheme (keys are not verified by this application)" if fs == ts else
                "different signing algorithms")
        else:
            add("signing", ", ".join(ts) or None, ", ".join(fs) or None, "unknown",
                "no signature metadata to compare (many vendors verify inside the TV's own updater)")

        # ---- hardware configuration ------------------------------------------------------------------------------------
        parts_found = []
        for c in comps:
            if c["part_number"] and category_for(c["component_type"]) in ("wifi", "wifi_bt", "audio", "tcon", "ram", "flash"):
                if cand.mentions(c["part_number"]):
                    parts_found.append(c["part_number"])
        considered = [c for c in comps if c["part_number"]]
        add("hardware_configuration", f"{len(considered)} confirmed component(s)",
            ", ".join(parts_found) or None, "match" if parts_found else "unknown",
            f"firmware names {len(parts_found)} of the TV's components" if parts_found else
            "no component part numbers named in firmware (normal for most packages)")

        # ---- integrity & source -------------------------------------------------------------------------------------------
        rec = cand.record
        current = ctx.library.verify_integrity(firmware_id)
        if current.verification_status == "hash_mismatch":
            add("integrity", rec.sha256[:16] + "…", "changed", "mismatch", "stored copy no longer matches its SHA-256",
                hard=True)
        else:
            sr = ctx.db.query_one("SELECT match_status, verification_status FROM firmware_search_results WHERE "
                                  "firmware_id=? ORDER BY id DESC LIMIT 1", (firmware_id,))
            published = bool(sr and "matches the value published" in (sr["verification_status"] or ""))
            add("integrity", None, current.verification_status, "match",
                "library copy intact" + ("; download hash matched the value published by the source" if published else ""))
        add("source", None, f"{rec.category} ({rec.download_url or 'local import'})",
            "match" if rec.category == "Official" else "unknown",
            "official package" if rec.category == "Official" else "not marked as an official package")

        r = self._verdict(res, base is not None)
        r.baseline_firmware_id, r.candidate_firmware_id = baseline_id, firmware_id
        return self._store(project_id, r) if store else r

    @staticmethod
    def _verdict(res: list[Criterion], have_baseline: bool) -> CompatibilityResult:
        by = {c.criterion: c for c in res}
        hard = [c for c in res if c.status == "mismatch" and c.hard]
        soft = [c for c in res if c.status == "soft_mismatch"]
        matches = [c for c in res if c.status == "match" and c.criterion not in ("integrity", "source")]
        weights = {"model": 30, "mainboard": 15, "soc": 10, "architecture": 10, "partition_layout": 10, "panel": 8,
                   "signing": 5, "ram": 3, "flash": 3, "bootloader": 2, "display_drivers": 1, "audio_drivers": 1,
                   "wifi_drivers": 1, "hardware_configuration": 1}
        score = sum(weights.get(c.criterion, 0) for c in matches) - 8 * len(soft)
        reasons = []
        if hard:
            verdict = "INCOMPATIBLE"
            reasons = [f"{c.criterion}: {c.evidence}" for c in hard]
            score = 0
        elif not matches:
            verdict = "INSUFFICIENT EVIDENCE"
            reasons = ["No criterion could be confirmed. Identify the TV (model, mainboard, SoC, panel), analyse its "
                       "current firmware as a baseline, and analyse the candidate."]
        else:
            model_ok = by["model"].status == "match"
            board_or_soc = by["mainboard"].status == "match" or by["soc"].status == "match"
            layout_ok = by["partition_layout"].status == "match" or (by["source"].status == "match" and
                                                                    by["partition_layout"].status == "unknown")
            strict = (model_ok and board_or_soc and by["architecture"].status == "match" and layout_ok
                      and by["signing"].status in ("match", "unknown") and not soft and have_baseline
                      and by["integrity"].status == "match")
            if strict:
                verdict = "VERIFIED COMPATIBLE"
                reasons.append("model, architecture, board/SoC and layout confirmed against the TV's own firmware; "
                               "no concerns")
            elif model_ok and len(soft) <= 1:
                verdict = "LIKELY COMPATIBLE"
                missing = [c.criterion for c in res if c.status == "unknown" and c.criterion in
                           ("architecture", "partition_layout", "mainboard", "soc")]
                reasons.append("model confirmed by firmware content" + (f"; not confirmed: {', '.join(missing)}" if missing else ""))
                if not have_baseline:
                    reasons.append("no analysed baseline firmware of this TV to compare architecture/layout")
            else:
                verdict = "POSSIBLE MATCH"
                reasons.append("partial agreement: " + ", ".join(c.criterion for c in matches))
            reasons += [f"concern — {c.criterion}: {c.evidence}" for c in soft]
        return CompatibilityResult(verdict, max(0, min(100, score)), res, reasons)

    def _store(self, project_id: int, r: CompatibilityResult) -> CompatibilityResult:
        cid = self.ctx.db.execute(
            "INSERT INTO firmware_compatibility(project_id, firmware_id, verdict, score, reasons_json,"
            " baseline_firmware_id, criteria_json) VALUES (?,?,?,?,?,?,?)",
            (project_id, r.candidate_firmware_id, r.verdict, r.score, json.dumps(r.reasons), r.baseline_firmware_id,
             json.dumps([asdict(c) for c in r.criteria])))
        r.id = cid  # type: ignore[attr-defined]
        self.ctx.audit.record("compatibility.evaluate", "tv_project", project_id, firmware_id=r.candidate_firmware_id,
                              verdict=r.verdict, compatibility_id=cid)
        return r

    def history(self, project_id: int) -> list[dict]:
        return [dict(x) for x in self.ctx.db.query(
            "SELECT c.*, f.original_filename FROM firmware_compatibility c LEFT JOIN firmware_files f ON f.id=c.firmware_id"
            " WHERE c.project_id=? ORDER BY c.id DESC", (project_id,))]

    def get(self, cid: int) -> dict:
        r = self.ctx.db.query_one("SELECT * FROM firmware_compatibility WHERE id=?", (cid,))
        if r is None:
            raise KeyError(cid)
        d = dict(r)
        d["criteria"] = json.loads(d.pop("criteria_json") or "[]")
        d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        return d
