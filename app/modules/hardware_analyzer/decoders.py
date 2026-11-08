"""Memory part-number decoders (``resources/data/part_decoders.json``).

A decoder turns a *full* part number into facts that the vendor's published
numbering scheme defines: device type, density, organisation. Each fact is
returned with the decoder id and scheme name as its source and is labelled
``decoder`` (never ``datasheet``), so reports show it must still be confirmed.
Nothing is decoded from partial or unrecognised strings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from app.core.config import application_root
from app.modules.identification.catalog import canonical as _canonical


@dataclass
class SpecFact:
    attribute: str
    value: str
    unit: str | None
    source_type: str          # datasheet | decoder | marking_rule | user
    source_reference: str
    confidence: float


@dataclass
class Decoder:
    id: str
    vendor: str
    regex: re.Pattern
    scheme: str
    confidence: float
    raw: dict


@lru_cache(maxsize=1)
def load_decoders() -> tuple[Decoder, ...]:
    data = json.loads((application_root() / "resources" / "data" / "part_decoders.json")
                      .read_text(encoding="utf-8"))
    return tuple(Decoder(d["id"], d["vendor"], re.compile(d["pattern"]), d["scheme"],
                         float(d["confidence"]), d) for d in data["decoders"])


def format_bits(bits: int) -> str:
    for unit, size in (("Gbit", 1024 ** 3), ("Mbit", 1024 ** 2)):
        if bits >= size and bits % size == 0:
            return f"{bits // size} {unit}"
    return f"{bits} bit"


def format_bytes(n: int) -> str:
    for unit, size in (("GB", 1024 ** 3), ("MB", 1024 ** 2)):
        if n >= size and n % size == 0:
            return f"{n // size} {unit}"
    return f"{n} bytes"


def _dens_to_bits(d: str) -> int:
    m = re.fullmatch(r"(\d+)G", d)
    if not m:
        raise ValueError(d)
    return int(m.group(1)) * 1024 ** 3


def normalize_part(part: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", part.upper())


def decode(part_number: str) -> tuple[Decoder, list[SpecFact]] | None:
    """Return (decoder, facts) or None when no decoder matches the full part number."""
    p = normalize_part(part_number)
    for d in load_decoders():
        m = d.regex.match(p)
        if not m:
            continue
        g = m.groupdict()
        raw = d.raw
        ref = f"decoder {d.id}: {d.scheme}"
        facts: list[SpecFact] = [SpecFact("manufacturer", d.vendor, None, "decoder", ref, d.confidence)]
        mtype = raw.get("fixed_type") or raw.get("family_map", {}).get(g.get("fam", ""))
        if mtype:
            facts.append(SpecFact("memory_type", mtype, None, "decoder", ref, d.confidence))
        bits = None
        if g.get("dens"):
            bits = _dens_to_bits(g["dens"])
        elif g.get("depth") and g.get("width"):
            bits = int(g["depth"]) * 1024 ** 2 * int(g["width"])
        elif g.get("mbit"):
            bits = int(g["mbit"]) * 1024 ** 2
        elif g.get("gbit"):
            bits = int(g["gbit"]) * 1024 ** 3
        if bits:
            facts.append(SpecFact("density_bits", str(bits), "bit", "decoder", ref, d.confidence))
        if g.get("emmc"):
            gb = raw["emmc_map"][g["emmc"]]
            facts.append(SpecFact("capacity_bytes", str(gb * 1024 ** 3), "byte", "decoder", ref,
                                  d.confidence))
        org = raw.get("org_map", {}).get(g.get("org", "")) if g.get("org") else None
        if g.get("width"):
            org = f"x{g['width']}"
        if org:
            facts.append(SpecFact("organization", org, None, "decoder", ref, d.confidence))
        if raw.get("note"):
            facts.append(SpecFact("note", raw["note"], None, "decoder", ref, d.confidence))
        return d, facts
    return None


def canonical(part: str) -> str:
    return _canonical(part)
