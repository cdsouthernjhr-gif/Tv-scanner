"""Firmware comparison: binary similarity, structure, metadata and extracted-file differences."""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

BLOCK = 64 * 1024
LIST_LIMIT = 500


def block_hashes(path: Path, block: int = BLOCK) -> list[bytes]:
    out = []
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(block), b""):
            out.append(hashlib.sha1(b).digest())
    return out


def binary_similarity(a: Path, b: Path, block: int = BLOCK) -> dict:
    ha, hb = block_hashes(a, block), block_hashes(b, block)
    same_pos = sum(1 for x, y in zip(ha, hb) if x == y)
    shared = sum((Counter(ha) & Counter(hb)).values())
    n = max(len(ha), len(hb)) or 1
    return {"block_size": block, "blocks_a": len(ha), "blocks_b": len(hb),
            "identical_at_same_offset": same_pos, "identical_at_same_offset_pct": round(100 * same_pos / n, 1),
            "shared_blocks_any_offset": shared, "shared_blocks_pct": round(100 * shared / n, 1)}


def compare(fw_a: dict, fw_b: dict) -> dict:
    """fw_x = {"record": FirmwareRecord-like dict, "path": Path, "components": [...], "metadata": [...],
    "files": [...]} — components/metadata/files as stored in the database (may be empty if not analysed)."""
    ra, rb = fw_a["record"], fw_b["record"]
    res = {
        "a": {"id": ra["id"], "name": ra["original_filename"], "size": ra["file_size"], "sha256": ra["sha256"]},
        "b": {"id": rb["id"], "name": rb["original_filename"], "size": rb["file_size"], "sha256": rb["sha256"]},
        "identical": ra["sha256"] == rb["sha256"],
        "size_difference": rb["file_size"] - ra["file_size"],
    }
    res["binary"] = binary_similarity(Path(fw_a["path"]), Path(fw_b["path"]))

    ta = Counter(c["type"] for c in fw_a["components"])
    tb = Counter(c["type"] for c in fw_b["components"])
    res["structure"] = {t: {"a": ta.get(t, 0), "b": tb.get(t, 0)} for t in sorted(set(ta) | set(tb))
                        if ta.get(t, 0) != tb.get(t, 0)}
    moved = []
    by_sig_b = {(c["type"], c["size"]): c for c in fw_b["components"] if c["size"]}
    for c in fw_a["components"]:
        o = by_sig_b.get((c["type"], c["size"]))
        if o and o["offset"] != c["offset"]:
            moved.append({"type": c["type"], "size": c["size"], "offset_a": c["offset"], "offset_b": o["offset"]})
    res["moved_components"] = moved[:LIST_LIMIT]

    def meta_map(rows):
        m: dict[str, set] = {}
        for r in rows:
            m.setdefault(r["attribute"], set()).add(r["value"])
        return m
    ma, mb = meta_map(fw_a["metadata"]), meta_map(fw_b["metadata"])
    keys = ("kernel_version", "cpu_architecture", "firmware_version", "android_version", "build_id",
            "build_number", "bootloader", "os_family", "filesystems", "compression", "signing", "product_model")
    res["metadata"] = {k: {"a": sorted(ma.get(k, [])), "b": sorted(mb.get(k, []))} for k in keys
                       if ma.get(k) != mb.get(k) and (ma.get(k) or mb.get(k))}
    res["metadata_same"] = sorted(k for k in keys if ma.get(k) and ma.get(k) == mb.get(k))

    fa = {f["rel_path"]: f["sha256"] for f in fw_a["files"] if f["kind"] != "symlink"}
    fb = {f["rel_path"]: f["sha256"] for f in fw_b["files"] if f["kind"] != "symlink"}
    if fa or fb:
        added = sorted(set(fb) - set(fa))
        removed = sorted(set(fa) - set(fb))
        changed = sorted(p for p in set(fa) & set(fb) if fa[p] != fb[p])
        same = len(set(fa) & set(fb)) - len(changed)
        res["files"] = {"added": added[:LIST_LIMIT], "removed": removed[:LIST_LIMIT], "changed": changed[:LIST_LIMIT],
                        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed),
                                   "unchanged": same}}
    else:
        res["files"] = None   # neither firmware was extracted
    return res
