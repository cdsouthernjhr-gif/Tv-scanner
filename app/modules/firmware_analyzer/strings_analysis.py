"""Printable-string extraction and categorisation with offsets.

Only facts that a string *states* are reported (e.g. "Linux version 4.9.118"),
each with the byte offset where it was found. The full string list is written
to a text file in the analysis workspace; the database keeps categorised hits.
"""
from __future__ import annotations

import mmap
import re
from dataclasses import dataclass, field
from pathlib import Path

MIN_LEN = 6
MAX_HITS_PER_CATEGORY = 200
_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LEN)

CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("kernel_version", re.compile(r"Linux version (\d+\.\d+(?:\.\d+)?[^\s]*)")),
    ("uboot_version", re.compile(r"U-Boot (\d{4}\.\d{2}[^\s(]*)")),
    ("busybox_version", re.compile(r"BusyBox v(\d+\.\d+(?:\.\d+)?)")),
    ("toolchain", re.compile(r"GCC: \(([^)]*)\) (\d+\.\d+(?:\.\d+)?)")),
    ("android_property", re.compile(r"\b(ro\.(?:build\.(?:version\.release|version\.incremental|display\.id|"
                                    r"fingerprint|date)|product\.(?:model|brand|manufacturer|device|board)|"
                                    r"board\.platform|hardware))=(\S.*)")),
    ("platform_keyword", re.compile(r"\b(Tizen|webOS|VIDAA|Android TV|Google TV|Roku|Linux)\b")),
    ("firmware_version", re.compile(r"(?i)\b(?:firmware|software|sw|fw)[ _-]?(?:version|ver)\s*[:=]\s*([A-Za-z0-9._-]{2,40})")),
    ("build_date", re.compile(r"\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                              r"+\d{1,2} \d\d:\d\d:\d\d (?:[A-Z]{3,4} )?\d{4})")),
    ("url", re.compile(r"\bhttps?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s\"'<>]*)?")),
    ("ip_address", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("config_path", re.compile(r"(?:/[A-Za-z0-9_.-]+)+\.(?:conf|cfg|ini|xml|json|prop|rc)\b")),
    ("partition_name", re.compile(r"\b(?:mtdparts=[^\s]+|androidboot\.[a-z_]+=[^\s]+|root=/dev/[^\s]+)")),
    ("crypto_keyword", re.compile(r"\b(?:BEGIN (?:RSA |EC )?(?:PRIVATE|PUBLIC) KEY|BEGIN CERTIFICATE|AES-?(?:128|256)|"
                                  r"RSA-?(?:1024|2048|4096)|signature|secure ?boot)\b", re.I)),
]


@dataclass
class StringsResult:
    total: int
    hits: dict[str, list[dict]] = field(default_factory=dict)       # category -> [{offset, text, value}]
    chip_mentions: list[dict] = field(default_factory=list)          # marking-rule matches inside strings
    dump_path: str | None = None


def iter_strings(path: str | Path, min_len: int = MIN_LEN):
    with open(path, "rb") as fh:
        size = fh.seek(0, 2)
        if not size:
            return
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for m in _PRINTABLE.finditer(mm):
                yield m.start(), m.group().decode("ascii", "replace")


def analyze(path: str | Path, dump_to: Path | None = None) -> StringsResult:
    from app.modules.visual_scanner.markings import match as marking_match
    res = StringsResult(0)
    seen: dict[str, set] = {}
    chip_seen: set = set()
    token = re.compile(r"\b[A-Z][A-Z0-9]{4,15}\b")
    out = open(dump_to, "w", encoding="utf-8") if dump_to else None
    try:
        for off, s in iter_strings(path):
            res.total += 1
            if out:
                out.write(f"{off:#010x}  {s}\n")
            for cat, rx in CATEGORIES:
                for m in rx.finditer(s):
                    lst = res.hits.setdefault(cat, [])
                    val = m.group(0) if not m.groups() else " ".join(g for g in m.groups() if g)
                    if val in seen.setdefault(cat, set()) or len(lst) >= MAX_HITS_PER_CATEGORY:
                        continue
                    seen[cat].add(val)
                    lst.append({"offset": off + m.start(), "value": val, "text": s[:200]})
            if len(chip_seen) < 100:
                for t in token.findall(s):
                    if t in chip_seen:
                        continue
                    r = marking_match(t, ("chip",))
                    if r and not r[2]:            # exact (uncorrected) rule match only
                        chip_seen.add(t)
                        res.chip_mentions.append({"offset": off, "part": t, "rule": r[0].id, "vendor": r[0].vendor,
                                                  "type": r[0].type})
    finally:
        if out:
            out.close()
    res.dump_path = str(dump_to) if dump_to else None
    return res
