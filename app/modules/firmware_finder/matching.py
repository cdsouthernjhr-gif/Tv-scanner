"""Firmware matching engine.

Compares a search hit (and, after download, the analysed file) with the TV's
known identifiers. Each criterion gets ``match`` / ``variant`` / ``mismatch`` /
``unknown`` plus the evidence text. Verdict rules:

VERIFIED MATCH
    Only for a *downloaded* file whose integrity is established (SHA-256 equals
    the value published by the source, or obtained from the manufacturer's own
    domain over HTTPS) AND whose analysis confirms the model (build properties /
    strings) AND no hard mismatch. Search text alone can never verify.
HIGH CONFIDENCE MATCH
    Exact model plus mainboard/chassis/product code agreement (or analysis
    confirms the model) with no mismatch.
POSSIBLE MATCH
    Some identifier agrees but not enough for the above. File-name, version or
    SoC similarity alone never goes higher than this.
INCOMPATIBLE
    A hard mismatch from analysed content (different CPU architecture, a
    different product model in build properties, different SoC platform).
INSUFFICIENT INFORMATION
    Nothing to compare, or nothing matched.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.modules.firmware_finder.criteria import SearchCriteria
from app.modules.firmware_finder.providers.base import SearchHit, domains, official_brand
from app.modules.identification.catalog import canonical

VERDICTS = ("VERIFIED MATCH", "HIGH CONFIDENCE MATCH", "POSSIBLE MATCH", "INCOMPATIBLE", "INSUFFICIENT INFORMATION")
WEIGHTS = {"model_number": 40, "mainboard": 25, "chassis": 10, "product_code": 10, "pcb_revision": 5, "soc": 5,
           "panel": 5, "firmware_version": 5, "firmware_build": 5, "firmware_filename": 3, "sha256": 50}
STRONG = {"model_number", "mainboard", "chassis", "product_code"}


@dataclass
class CriterionResult:
    criterion: str
    expected: str | None
    status: str                 # match | variant | mismatch | unknown | not_applicable
    evidence: str


@dataclass
class MatchResult:
    verdict: str
    score: int
    risk: str                   # Low | Medium | High | Critical
    risk_reasons: list[str]
    criteria: list[CriterionResult] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    signature_status: str = "not verifiable"
    verification_status: str = "search result only (not verified)"

    def as_dict(self) -> dict:
        return asdict(self)


def find_identifier(text: str, ident: str) -> str | None:
    """'exact' when the identifier occurs as whole token(s); 'variant' when a token starts with it and
    only a short suffix follows (region/variant code, e.g. UA55AU7000 → UA55AU7000KXXM); else None.
    OCR-confusable characters are folded on both sides."""
    target = canonical(ident)
    if len(target) < 4:
        return None
    toks = [t for t in re.split(r"[^A-Za-z0-9]+", text or "") if t]
    ctoks = [canonical(t) for t in toks]
    for i in range(len(ctoks)):
        acc = ""
        for j in range(i, min(i + 5, len(ctoks))):
            acc += ctoks[j]
            if acc == target:
                return "exact"
            if len(acc) > len(target) + 6:
                break
    for t in ctoks:
        if t.startswith(target) and 0 < len(t) - len(target) <= 5:
            return "variant"
    return None


def _risk_words(text: str) -> list[str]:
    low = text.lower()
    return [w for w in domains()["risk_keywords"] if re.search(r"\b" + re.escape(w) + r"\b", low)]


def evaluate(hit: SearchHit, c: SearchCriteria, download: dict | None = None,
             analysis: list[dict] | None = None) -> MatchResult:
    """download = {"sha256", "expected_sha256", "https", "official"}; analysis = firmware_metadata rows."""
    text = hit.text()
    results: list[CriterionResult] = []
    score = 0
    for crit in ("model_number", "mainboard", "chassis", "product_code", "pcb_revision", "soc", "panel",
                 "firmware_version", "firmware_build", "firmware_filename"):
        exp = getattr(c, crit)
        if not exp:
            results.append(CriterionResult(crit, None, "not_applicable", "not known for this TV"))
            continue
        if crit == "pcb_revision" and not c.mainboard:
            results.append(CriterionResult(crit, exp, "unknown", "revision without mainboard is not meaningful"))
            continue
        hitm = find_identifier(text, exp)
        if hitm == "exact":
            results.append(CriterionResult(crit, exp, "match", f"'{exp}' appears in result title/description/file name"))
            score += WEIGHTS[crit]
        elif hitm == "variant" and crit in ("model_number", "product_code"):
            results.append(CriterionResult(crit, exp, "variant", f"a variant of '{exp}' (extra suffix) appears — "
                                                                 "regional/variant firmware may differ"))
            score += int(WEIGHTS[crit] * 0.6)
        else:
            results.append(CriterionResult(crit, exp, "unknown", "not mentioned by the source"))
    if c.sha256 and hit.sha256:
        same = hit.sha256.lower() == c.sha256.lower()
        results.append(CriterionResult("sha256", c.sha256[:16] + "…", "match" if same else "unknown",
                                       "published SHA-256 equals the TV's current firmware" if same else
                                       "different file from the current firmware (expected for an update)"))
        if same:
            score += WEIGHTS["sha256"]

    mism: list[str] = []
    analysis_model = False
    if analysis:
        def vals(attr):
            return {a["value"] for a in analysis if a["attribute"] == attr and a["confidence"] >= 0.7}
        arch = vals("cpu_architecture")
        if c.architecture and arch:
            if c.architecture in arch:
                results.append(CriterionResult("architecture", c.architecture, "match", "analysis of the downloaded file"))
                score += 10
            else:
                results.append(CriterionResult("architecture", c.architecture, "mismatch",
                                               f"downloaded file is {', '.join(sorted(arch))}"))
                mism.append(f"CPU architecture differs ({', '.join(sorted(arch))} vs {c.architecture})")
        models = vals("product_model") | vals("product_device")
        if c.model_number and models:
            if any(find_identifier(m, c.model_number) for m in models):
                results.append(CriterionResult("analysis_model", c.model_number, "match",
                                               f"build properties name {', '.join(sorted(models))}"))
                score += 20
                analysis_model = True
            else:
                results.append(CriterionResult("analysis_model", c.model_number, "mismatch",
                                               f"build properties name {', '.join(sorted(models))}"))
                mism.append(f"firmware declares product model {', '.join(sorted(models))}")
        chips = " ".join(vals("chip_mention") | vals("board_platform") | vals("hardware"))
        if c.soc and chips:
            if find_identifier(chips, c.soc):
                results.append(CriterionResult("analysis_soc", c.soc, "match", "SoC named inside the firmware"))
                score += 5

    # ---- source / integrity / risk ----------------------------------------------------------
    risk_reasons: list[str] = []
    official = hit.source_type == "official" or bool(official_brand(hit.url))
    if official:
        score += 10
    else:
        risk_reasons.append(f"not an official manufacturer source ({hit.site})")
    if hit.sha256:
        score += 5
    else:
        risk_reasons.append("source publishes no SHA-256")
    rw = _risk_words(text)
    if rw:
        risk_reasons.append(f"content mentions {', '.join(rw)} — may involve modification/security bypass; "
                            "not treated as a firmware source")
    if hit.distribution_status == "unknown":
        risk_reasons.append("redistribution rights unknown")
    if hit.raw.get("kind") in ("repository", "project", "web", "item"):
        risk_reasons.append("result is a page/repository, not a specific firmware file")

    verification = "search result only (not verified)"
    integrity_ok = False
    if download:
        if download.get("expected_sha256"):
            integrity_ok = download["sha256"].lower() == download["expected_sha256"].lower()
            verification = ("downloaded; SHA-256 matches the value published by the source" if integrity_ok
                            else "downloaded; SHA-256 DOES NOT MATCH the published value")
            if not integrity_ok:
                mism.append("downloaded file hash differs from the published hash")
        else:
            integrity_ok = bool(download.get("official") and download.get("https"))
            verification = ("downloaded over HTTPS from the manufacturer's domain; no published hash"
                            if integrity_ok else "downloaded; no published hash to compare")
    signature = "not verifiable"
    if analysis:
        sig = [a["value"] for a in analysis if a["attribute"] == "signing"]
        if sig:
            signature = f"{sig[0]} present (signature not cryptographically verified by this application)"

    strong = [r for r in results if r.criterion in STRONG and r.status == "match"]
    any_match = [r for r in results if r.status in ("match", "variant")]
    model_exact = any(r.criterion == "model_number" and r.status == "match" for r in results)
    reasons: list[str] = []
    if mism:
        verdict = "INCOMPATIBLE"
        reasons += mism
        score = min(score, 10)
    elif c.is_empty():
        verdict = "INSUFFICIENT INFORMATION"
        reasons.append("no identifiers known for this TV — identify it first")
    elif download and integrity_ok and analysis_model:
        verdict = "VERIFIED MATCH"
        reasons.append("file integrity established and its content names this model")
    elif (model_exact and len(strong) >= 2) or analysis_model:
        verdict = "HIGH CONFIDENCE MATCH"
        reasons.append("model and a second hardware identifier agree" if not analysis_model
                       else "analysed content names this model (integrity not established)")
    elif any_match:
        verdict = "POSSIBLE MATCH"
        reasons.append("matched: " + ", ".join(f"{r.criterion} ({r.status})" for r in any_match))
        if not strong:
            reasons.append("only weak identifiers (file name / version / SoC) agree — never sufficient on their own")
            score = min(score, 30)
    else:
        verdict = "INSUFFICIENT INFORMATION"
        reasons.append("none of the TV's identifiers appear in this result")
    if rw and verdict in ("HIGH CONFIDENCE MATCH", "VERIFIED MATCH"):
        verdict = "POSSIBLE MATCH"
        reasons.append("downgraded: modification/bypass keywords")

    if verdict == "INCOMPATIBLE" or rw or hit.distribution_status == "unknown":
        risk = "Critical"
    elif verdict == "VERIFIED MATCH" and official:
        risk = "Low"
    elif verdict in ("VERIFIED MATCH", "HIGH CONFIDENCE MATCH") and (official or hit.sha256):
        risk = "Medium"
    else:
        risk = "High"
    return MatchResult(verdict, max(0, min(100, score)), risk, risk_reasons, results, reasons, signature, verification)
