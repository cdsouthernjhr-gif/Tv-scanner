"""Entropy analysis and encryption *indicators*.

Shannon entropy per block (0..8 bits/byte). High entropy (> 7.9) means the data
is compressed **or** encrypted — the two cannot be told apart by entropy alone.
The analyzer therefore only raises an *indicator* of possible encryption when a
high-entropy region is NOT explained by a validated compressed/filesystem
component found by the signature scanner. A chi-square statistic is reported
as supporting information (encrypted data tends to be closer to uniform than
most compressed formats, but this is not proof either).
"""
from __future__ import annotations

import math
import mmap
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HIGH = 7.9
LOW = 1.0
_EXPLAINS = {"compressed", "filesystem", "archive", "kernel", "image"}


@dataclass
class EntropyResult:
    block_size: int
    blocks: list[float]                      # entropy per block
    overall: float
    chi_square: float
    regions: list[dict] = field(default_factory=list)      # consecutive blocks by class
    indicators: list[str] = field(default_factory=list)
    unexplained_high_bytes: int = 0


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def chi_square(counts: Counter, n: int) -> float:
    exp = n / 256
    return sum((counts.get(b, 0) - exp) ** 2 / exp for b in range(256)) if n else 0.0


def choose_block_size(size: int, target_blocks: int = 1024) -> int:
    # >= 8 KiB: with smaller samples even perfectly random data measures < 7.9 bits/byte
    # (small-sample bias: 1 KiB of random bytes averages ~7.8), so encryption would go unnoticed.
    bs = 8192
    while size / bs > target_blocks and bs < 16 * 1024 * 1024:
        bs *= 2
    return bs


def analyze(path: str | Path, components: list | None = None, block_size: int | None = None) -> EntropyResult:
    path = Path(path)
    size = path.stat().st_size
    bs = block_size or choose_block_size(size)
    blocks: list[float] = []
    total = Counter()
    if size:
        with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for off in range(0, size, bs):
                chunk = mm[off:off + bs]
                c = Counter(chunk)
                total.update(c)
                n = len(chunk)
                blocks.append(-sum(v / n * math.log2(v / n) for v in c.values()))
    overall = -sum(v / size * math.log2(v / size) for v in total.values()) if size else 0.0
    res = EntropyResult(bs, [round(b, 4) for b in blocks], round(overall, 4), round(chi_square(total, size), 1))

    def cls(e):
        return "high" if e > HIGH else "low" if e < LOW else "medium"
    start = 0
    for i in range(1, len(blocks) + 1):
        if i == len(blocks) or cls(blocks[i]) != cls(blocks[start]):
            res.regions.append({"offset": start * bs, "size": min(size, i * bs) - start * bs,
                                "class": cls(blocks[start]),
                                "mean": round(sum(blocks[start:i]) / (i - start), 3)})
            start = i

    explained = [(c.offset, c.end) for c in (components or [])
                 if c.size and c.category in _EXPLAINS and c.validated]
    unexplained = 0
    for r in res.regions:
        if r["class"] != "high":
            continue
        a, b = r["offset"], r["offset"] + r["size"]
        covered = 0
        for s, e in explained:
            covered += max(0, min(b, e) - max(a, s))
        r["explained_by_known_format"] = covered >= 0.9 * r["size"]
        if not r["explained_by_known_format"]:
            unexplained += r["size"] - min(covered, r["size"])
    res.unexplained_high_bytes = unexplained
    if size and unexplained >= max(64 * 1024, 0.05 * size):
        res.indicators.append(
            f"{unexplained:,} B ({unexplained / size:.0%}) of high-entropy data are not explained by any recognised "
            "compressed format or filesystem — possible encryption or an unrecognised/proprietary compression. "
            "This is an indicator, not proof.")
    if size and overall > 7.95 and not explained:
        res.indicators.append("Whole file is high-entropy with no recognised structure — the image is likely "
                              "encrypted or wrapped in a proprietary container.")
    # supporting statistic only — never on its own (compressed data can be near-uniform too)
    if res.indicators and res.chi_square < 300 and overall > 7.99:
        res.indicators.append(f"Byte distribution is very close to uniform (chi-square {res.chi_square}), which is "
                              "typical of encrypted data (supporting indicator only).")
    return res
