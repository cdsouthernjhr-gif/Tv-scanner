"""Search criteria and query building.

Criteria are assembled from what the application already *knows*: project
identification fields, confirmed hardware components (Phase 3) and metadata
of analysed firmware (Phase 4). Each criterion remembers where it came from.

Query strategy (most specific first):
1. model number (+ "firmware")            — only if known
2. mainboard / chassis (+ "firmware")     — always if known; primary when model unknown
3. firmware file name / version / build   — when an existing firmware is known
4. SoC + "firmware"/"kernel"              — lowest specificity; only adds evidence
5. SHA-256                                — providers that support hash lookup
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field


@dataclass
class SearchCriteria:
    manufacturer: str | None = None
    model_number: str | None = None
    product_code: str | None = None
    chassis: str | None = None
    mainboard: str | None = None
    pcb_revision: str | None = None
    soc: str | None = None
    panel: str | None = None
    ram: str | None = None
    flash: str | None = None
    firmware_version: str | None = None
    firmware_build: str | None = None
    architecture: str | None = None
    firmware_filename: str | None = None
    sha256: str | None = None
    sources: dict[str, str] = field(default_factory=dict)       # field -> where the value came from

    def as_dict(self) -> dict:
        return asdict(self)

    def identifiers(self) -> dict[str, str]:
        keys = ("model_number", "product_code", "chassis", "mainboard", "pcb_revision", "soc", "panel",
                "firmware_version", "firmware_build", "firmware_filename", "sha256")
        return {k: getattr(self, k) for k in keys if getattr(self, k)}

    @property
    def model_unknown(self) -> bool:
        return not self.model_number

    def is_empty(self) -> bool:
        return not (self.identifiers() or self.manufacturer)


@dataclass
class Query:
    text: str
    kind: str          # model | mainboard | chassis | filename | version | soc | hash | product_code
    weight: float      # specificity, used for ranking hits found by this query


def _q(*parts) -> str:
    return " ".join(p for p in parts if p).strip()


def build_queries(c: SearchCriteria, max_queries: int = 8) -> list[Query]:
    out: list[Query] = []
    brand = c.manufacturer or ""
    if c.model_number:
        out.append(Query(_q(brand, c.model_number, "firmware"), "model", 1.0))
        out.append(Query(_q(c.model_number), "model", 0.9))
    if c.mainboard:
        out.append(Query(_q(c.mainboard, "firmware"), "mainboard", 0.9 if c.model_unknown else 0.8))
        if c.pcb_revision and c.model_unknown:
            out.append(Query(_q(c.mainboard, c.pcb_revision), "mainboard", 0.85))
    if c.chassis:
        out.append(Query(_q(brand, c.chassis, "firmware"), "chassis", 0.75))
    if c.product_code:
        out.append(Query(_q(c.product_code, "firmware"), "product_code", 0.75))
    if c.firmware_filename:
        stem = re.sub(r"\.(bin|img|pkg|zip|rom|epk|upg|tar|gz|tgz)$", "", c.firmware_filename, flags=re.I)
        out.append(Query(stem, "filename", 0.7))
    if c.firmware_version and len(c.firmware_version) >= 6:
        out.append(Query(_q(brand, c.firmware_version), "version", 0.6))
    if c.soc:
        out.append(Query(_q(c.soc, "firmware"), "soc", 0.4 if not c.model_unknown else 0.5))
        out.append(Query(_q(c.soc, "linux kernel source"), "soc", 0.3))
    if c.sha256:
        out.append(Query(c.sha256, "hash", 1.0))
    seen, uniq = set(), []
    for q in out:
        key = q.text.lower()
        if q.text and key not in seen:
            seen.add(key)
            uniq.append(q)
    return uniq[:max_queries]


def from_project(ctx, project_id: int) -> SearchCriteria:
    """Assemble criteria from project data, confirmed hardware and analysed firmware."""
    p = ctx.projects.get(project_id)
    c = SearchCriteria()
    for f_proj, f_crit in (("manufacturer", "manufacturer"), ("model_number", "model_number"),
                           ("product_code", "product_code"), ("chassis", "chassis"), ("mainboard", "mainboard"),
                           ("pcb_revision", "pcb_revision"), ("panel_model", "panel"),
                           ("firmware_version", "firmware_version")):
        v = getattr(p, f_proj)
        if v:
            setattr(c, f_crit, str(v))
            c.sources[f_crit] = f"project #{p.id} ({p.identification_source})"
    # hardware: SoC, RAM/flash summary
    try:
        for comp in ctx.hardware.list(project_id):
            cat = comp["component_type"]
            if cat == "soc" and comp["part_number"] and not c.soc:
                c.soc = comp["part_number"]
                c.sources["soc"] = f"hardware component #{comp['id']} ({comp['match_status']})"
        summ = ctx.hardware.board_summary(project_id)
        if summ["ram"].get("total"):
            c.ram = summ["ram"]["text"]
            c.sources["ram"] = "hardware board summary"
        if summ["flash"].get("total"):
            c.flash = summ["flash"]["text"]
            c.sources["flash"] = "hardware board summary"
    except Exception:
        pass
    # firmware already associated with the project: latest analysed file
    try:
        for fw in ctx.library.list(project_id=project_id):
            run = ctx.firmware.latest_run(fw.id)
            if not c.firmware_filename:
                c.firmware_filename = fw.original_filename
                c.sha256 = fw.sha256
                c.sources["firmware_filename"] = c.sources["sha256"] = f"library firmware #{fw.id}"
            if run:
                for m in ctx.firmware.metadata(run["id"]):
                    if m["attribute"] == "cpu_architecture" and not c.architecture and m["confidence"] >= 0.8:
                        c.architecture = m["value"]
                        c.sources["architecture"] = f"firmware #{fw.id} analysis ({m['source']})"
                    if m["attribute"] in ("build_id", "build_number") and not c.firmware_build and m["confidence"] >= 0.8:
                        c.firmware_build = m["value"]
                        c.sources["firmware_build"] = f"firmware #{fw.id} analysis ({m['source']})"
            break
    except Exception:
        pass
    return c
