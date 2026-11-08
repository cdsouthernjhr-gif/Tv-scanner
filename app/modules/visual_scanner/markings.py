"""Chip-marking and PCB/board-number recognition on OCR tokens.

Pipeline: OCR tokens → join adjacent tokens on the same line (part numbers are
often split, e.g. "BN41-" "02635A") → normalise → try OCR-confusion variants
(O↔0, I↔1, S↔5, B↔8) → match ordered prefix rules from
``resources/data/marking_rules.json``.

A detection is only a *candidate*: it names a vendor/family by numbering
convention and must be confirmed by the operator. Unrecognised but
part-number-like markings on chip photos are kept (``rule_id = None``) so they
can be looked up manually rather than silently dropped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from app.core.config import application_root
from app.modules.visual_scanner.ocr import OcrResult, OcrToken

CORRECTION_PENALTY = 0.85
_PART_LIKE = re.compile(r"^(?=.*[A-Z])(?=.*\d)[A-Z0-9][A-Z0-9\-./()]{4,30}$")
# Things that look like part numbers but are not (dates, lot codes are kept; these are noise).
# (dates, YYWW date codes, voltages, frequencies). Lot codes with letters are kept.
_IGNORE = re.compile(r"^(\d{4}[-/.]\d{2}[-/.]\d{2}|\d{4}[A-Z]{0,2}|V?\d+(\.\d+)+V?|\d+[KMG]?HZ|\d+V|\d+MA)$")


@dataclass
class Rule:
    id: str
    kind: str
    regex: re.Pattern
    vendor: str | None
    type: str
    strength: float
    note: str | None = None


@dataclass
class Detection:
    kind: str                 # 'chip' | 'pcb'
    raw_text: str
    normalized: str
    rule_id: str | None
    vendor: str | None
    type: str | None
    note: str | None
    confidence: float
    bbox: tuple[int, int, int, int] | None


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    data = json.loads((application_root() / "resources" / "data" / "marking_rules.json")
                      .read_text(encoding="utf-8"))
    rules = []
    for kind in ("pcb", "chip"):
        for r in data[kind]:
            rules.append(Rule(r["id"], kind, re.compile(r["pattern"]), r.get("vendor"), r["type"],
                              float(r["strength"]), r.get("note")))
    return tuple(rules)


def normalize(text: str) -> str:
    t = text.upper().strip()
    t = t.replace("—", "-").replace("–", "-").replace(" ", "")
    return t.strip(".,;:'\"`|[]{}")


_TO_DIGIT = str.maketrans({"O": "0", "Q": "0", "D": "0", "I": "1", "L": "1", "S": "5", "B": "8", "Z": "2"})
_TO_ALPHA = str.maketrans({"0": "O", "1": "I", "5": "S", "8": "B", "2": "Z"})


def variants(s: str) -> list[tuple[str, bool]]:
    """(variant, corrected?) — raw first, then common OCR confusion repairs.

    Repairs assume the usual structure *letter prefix + alphanumeric body*:
    digits inside the leading letter run become letters, and letters that sit
    between digits in the body become digits.
    """
    out = [(s, False)]
    body = re.sub(r"(?<=\d)[OQDILSBZ](?=\d)", lambda x: x.group(0).translate(_TO_DIGIT), s)
    for base in dict.fromkeys([s, body]):
        if base != s:
            out.append((base, True))
        for k in range(1, min(4, len(base) - 1) + 1):
            head = base[:k].translate(_TO_ALPHA)
            v = head + base[k:]
            if v != base:
                out.append((v, True))
    seen, uniq = set(), []
    for v, c in out:
        if v not in seen:
            seen.add(v)
            uniq.append((v, c))
    return uniq


def match(text: str, kinds: tuple[str, ...] = ("pcb", "chip")) -> tuple[Rule, str, bool] | None:
    norm = normalize(text)
    for v, corrected in variants(norm):
        for rule in load_rules():
            if rule.kind in kinds and rule.regex.search(v):
                return rule, v, corrected
    return None


def _union(tokens: list[OcrToken]) -> tuple[int, int, int, int]:
    x0 = min(t.bbox[0] for t in tokens)
    y0 = min(t.bbox[1] for t in tokens)
    x1 = max(t.bbox[0] + t.bbox[2] for t in tokens)
    y1 = max(t.bbox[1] + t.bbox[3] for t in tokens)
    return (x0, y0, x1 - x0, y1 - y0)


def detect(ocr: OcrResult, include_unrecognised: bool = False,
           min_token_conf: float = 0.2) -> list[Detection]:
    by_line: dict[int, list[OcrToken]] = {}
    for t in ocr.tokens:
        if t.conf >= min_token_conf:
            by_line.setdefault(t.line, []).append(t)

    spans: list[list[OcrToken]] = []
    for toks in by_line.values():
        toks.sort(key=lambda t: t.bbox[0])
        for i in range(len(toks)):
            spans.append([toks[i]])
            if i + 1 < len(toks):
                spans.append([toks[i], toks[i + 1]])  # split part numbers

    results: dict[tuple[str, str], Detection] = {}
    consumed: set[int] = set()
    # two-token spans first so "BN41-" + "02635A" wins over the fragments
    for span in sorted(spans, key=len, reverse=True):
        if any(id(t) in consumed for t in span):
            continue
        raw = "".join(t.text for t in span) if len(span) > 1 else span[0].text
        m = match(raw)
        conf = sum(t.conf for t in span) / len(span)
        if m:
            rule, norm, corrected = m
            c = conf * rule.strength * (CORRECTION_PENALTY if corrected else 1.0)
            note = rule.note
            if corrected:
                note = ((note + " ") if note else "") + f"OCR correction applied ({normalize(raw)} → {norm})."
            key = (rule.kind, norm)
            if key not in results or c > results[key].confidence:
                results[key] = Detection(rule.kind, raw, norm, rule.id, rule.vendor, rule.type,
                                         note, round(c, 3), _union(span))
            consumed.update(id(t) for t in span)
        elif include_unrecognised and len(span) == 1:
            norm = normalize(raw)
            if _PART_LIKE.match(norm) and not _IGNORE.match(norm):
                key = ("chip", norm)
                if key not in results:
                    results[key] = Detection("chip", raw, norm, None, None, None,
                                             "Part-number-like marking with no known rule; verify manually.",
                                             round(conf * 0.3, 3), _union(span))
    return sorted(results.values(), key=lambda d: -d.confidence)
