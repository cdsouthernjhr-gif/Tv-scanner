"""Extract identification candidates from OCR text.

Every candidate records *how* it was found (method) and the source line, so the
operator can judge it. Methods and their base reliability:

* ``label_key``        — value follows an explicit key such as "MODEL:" (0.95)
* ``generic_key``      — ambiguous key ("VERSION:", "REV:") that may not mean firmware/PCB (0.55)
* ``brand_dictionary`` — a known brand name appears as a whole word (0.85)
* ``platform_keyword`` — an OS/platform name appears in the text (0.65)
* ``size_pattern``     — explicit size like 55" or 55 inch (0.75)

The final confidence is base reliability x OCR line confidence. No value is
derived from model-number naming conventions (e.g. guessing size from digits),
because those conventions differ per brand and are not evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from app.core.config import application_root

METHOD_WEIGHT = {"label_key": 0.95, "generic_key": 0.55, "brand_dictionary": 0.85, "platform_keyword": 0.65,
                 "size_pattern": 0.75}

# key regex -> field. Order matters: more specific keys first.
_CODE = r"([A-Z0-9][A-Z0-9\-_/.()]{2,40})"
LABEL_KEYS: list[tuple[str, str, str]] = [
    # (field, key pattern, value pattern)
    ("serial_number", r"(?:S/N|SN|SER(?:IAL)?\.?\s*(?:NO|NUMBER|N[O°])?\.?)", _CODE),
    ("product_code", r"(?:PRODUCT\s*CODE|PROD\.?\s*CODE|PRODUCT\s*(?:NO|NUMBER)\.?|CODE\s*NO\.?)", _CODE),
    ("model_number", r"(?:MODEL\s*(?:NO|NUMBER|NAME|CODE)?\.?|MOD(?:E|È)LE|MODELO)", _CODE),
    ("chassis", r"(?:CHASSIS|CHASIS)", _CODE),
    ("mainboard", r"(?:MAIN\s*BOARD|MAINBOARD|BOARD\s*(?:NO|ID|NAME)\.?)", _CODE),
    ("panel_model", r"(?:PANEL\s*(?:ID|MODEL|NAME|NO)?\.?)", _CODE),
    ("pcb_revision", r"(?:PCB\s*REV(?:ISION)?\.?)", r"([A-Z0-9][A-Z0-9.]{0,7})"),
    ("firmware_version", r"(?:(?:SOFTWARE|FIRMWARE|S/W|SW|F/W|FW)\s*(?:VERSION|VER\.?)?)",
     r"([A-Z0-9][A-Z0-9\-_.]{1,60})"),
]
# Ambiguous keys: a label's "Version" is often the label/hardware version, not firmware.
GENERIC_KEYS: list[tuple[str, str, str]] = [
    ("pcb_revision", r"(?:REV(?:ISION)?\.?)", r"([A-Z0-9][A-Z0-9.]{0,7})"),
    ("firmware_version", r"(?:VERSION|VER\.)", r"([A-Z0-9][A-Z0-9\-_.]{1,60})"),
]
_SEP = r"\s*[:.#=\-]?\s*"
_SIZE = re.compile(r"\b(\d{2,3}(?:\.\d)?)\s*(?:\"|''|”|INCH(?:ES)?|IN\b|CLASS\b)")
_SIZE_KEY = re.compile(r"(?:SCREEN\s*SIZE|SIZE|DIAGONAL)" + _SEP + r"(\d{2,3}(?:\.\d)?)")

# Code-like fields: a value without any digit is a fragment of a key word
# ("MODEL NA ME" -> "NAME"), not a code.
_NEEDS_DIGIT = {"model_number", "serial_number", "product_code", "chassis", "mainboard",
                "panel_model", "firmware_version", "pcb_revision"}

# Words that terminate a value (another key on the same line).
_STOPWORDS = {"MODEL", "SERIAL", "S/N", "SN", "CHASSIS", "PRODUCT", "CODE", "VERSION", "PANEL",
              "MADE", "MANUFACTURED", "DATE", "POWER", "AC", "REV", "VER", "BOARD"}


@dataclass
class Candidate:
    field: str
    value: str
    confidence: float
    method: str
    source_line: str


@lru_cache(maxsize=1)
def _brand_data() -> dict:
    p = application_root() / "resources" / "data" / "tv_brands.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _word_re(alias: str) -> re.Pattern:
    return re.compile(r"(?<![A-Z0-9])" + re.escape(alias) + r"(?![A-Z0-9])")


def _clean_value(v: str) -> str | None:
    v = v.strip().strip(".,;:-_/()")
    if len(v) < 2 or not re.search(r"[A-Z0-9]", v):
        return None
    return v


def _parse_line(line: str, conf: float) -> list[Candidate]:
    out: list[Candidate] = []
    up = line.upper()
    keyed = [(f, k, v, "label_key") for f, k, v in LABEL_KEYS] + \
            [(f, k, v, "generic_key") for f, k, v in GENERIC_KEYS]
    for field, key, val, method in keyed:
        # generic keys must not fire inside a specific key ("PCB REV", "SOFTWARE VERSION")
        prefix = r"(?<![A-Z0-9])" if method == "label_key" else r"(?<![A-Z0-9/])(?<!PCB )(?<!WARE )(?<!S/W )(?<!SW )(?<!F/W )(?<!FW )"
        for m in re.finditer(prefix + key + _SEP + val, up):
            value = _clean_value(m.group(1))
            if not value or value in _STOPWORDS:
                continue
            if field in _NEEDS_DIGIT and not re.search(r"\d", value):
                continue
            # A key directly followed by another key is not a value ("MODEL SERIAL").
            if any(value.startswith(s + " ") or value == s for s in _STOPWORDS):
                continue
            out.append(Candidate(field, value, round(METHOD_WEIGHT[method] * conf, 3),
                                 method, line))
    m = _SIZE_KEY.search(up) or _SIZE.search(up)
    if m:
        size = float(m.group(1))
        if 10 <= size <= 120:
            out.append(Candidate("screen_size_inches", f"{size:g}",
                                 round(METHOD_WEIGHT["size_pattern"] * conf, 3), "size_pattern", line))
    data = _brand_data()
    for brand, aliases in data["brands"].items():
        if any(_word_re(a).search(up) for a in aliases):
            out.append(Candidate("manufacturer", brand,
                                 round(METHOD_WEIGHT["brand_dictionary"] * conf, 3),
                                 "brand_dictionary", line))
    for platform, kws in data["platform_keywords"].items():
        if any(_word_re(k).search(up) for k in kws):
            out.append(Candidate("platform", platform,
                                 round(METHOD_WEIGHT["platform_keyword"] * conf, 3),
                                 "platform_keyword", line))
    return out


def _resolve_overlaps(cands: list[Candidate]) -> list[Candidate]:
    """'PCB REV' must not also yield a generic 'REV'; S/N must not be read as SN twice, etc."""
    # firmware 'VERSION' generic key may duplicate a more specific match: keep longest value per field+line
    best: dict[tuple, Candidate] = {}
    for c in cands:
        key = (c.field, c.value, c.source_line)
        if key not in best or c.confidence > best[key].confidence:
            best[key] = c
    out = list(best.values())
    # drop a value that is a strict prefix of another value for same field+line
    final = []
    for c in out:
        if any(o is not c and o.field == c.field and o.source_line == c.source_line
               and o.value.startswith(c.value) and len(o.value) > len(c.value) for o in out):
            continue
        final.append(c)
    return final


def drop_prefix_fragments(cands: list[Candidate]) -> list[Candidate]:
    """OCR can split one code over two lines ("UA55" / "AU7000KXXM"). If a keyed value
    is a strict prefix of a longer keyed value for the same field, drop the fragment."""
    keyed = [c for c in cands if c.method in ("label_key", "generic_key")]
    out = []
    for c in cands:
        if c in keyed and len(c.value) >= 2 and any(
                o.field == c.field and o is not c and len(o.value) > len(c.value)
                and o.value.startswith(c.value) for o in keyed):
            continue
        out.append(c)
    return out


def extract_candidates(lines: list[tuple[str, float]]) -> list[Candidate]:
    """``lines`` = [(text, ocr_confidence 0..1)], e.g. from ``OcrResult.lines()``."""
    found: list[Candidate] = []
    for text, conf in lines:
        if text.strip():
            found.extend(_parse_line(text, conf))
    found = _resolve_overlaps(found)
    found = drop_prefix_fragments(found)
    # deduplicate across lines: keep the most confident instance of each field/value
    best: dict[tuple, Candidate] = {}
    for c in found:
        k = (c.field, c.value)
        if k not in best or c.confidence > best[k].confidence:
            best[k] = c
    return sorted(best.values(), key=lambda c: (c.field, -c.confidence))


def extract_from_text(text: str, confidence: float = 1.0) -> list[Candidate]:
    return extract_candidates([(ln, confidence) for ln in text.splitlines()])
