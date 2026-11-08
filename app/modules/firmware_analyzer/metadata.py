"""Combine scanner, strings, entropy and file-inventory results into metadata facts.

Each fact = (attribute, value, source, confidence). Several facts for the same
attribute may coexist (e.g. two kernel versions in a dual-image firmware); the
UI and reports show all of them with their sources rather than picking one
silently.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from app.modules.firmware_analyzer.entropy import EntropyResult
from app.modules.firmware_analyzer.scanner import ScanResult
from app.modules.firmware_analyzer.strings_analysis import StringsResult


@dataclass
class Fact:
    attribute: str
    value: str
    source: str
    confidence: float


_ARCH_NORMAL = {"ARM": "ARM (32-bit)", "AArch64": "ARM64 (AArch64)", "ARM64": "ARM64 (AArch64)", "MIPS": "MIPS",
                "MIPS64": "MIPS64", "x86": "x86", "x86_64": "x86-64", "PowerPC": "PowerPC"}
_VERSION_IN_NAME = re.compile(r"(?i)(?:^|[_\-. ])(v?\d+(?:[._]\d+){1,3}[a-z0-9]*|[A-Z0-9]{2,}-[A-Z0-9]{3,}(?:-[A-Z0-9]+)*\d)"
                              r"(?=$|[_\-. ])")


def build_facts(filename: str, scan: ScanResult, strings: StringsResult | None, entropy: EntropyResult | None,
                inventory_facts: list[tuple[str, str, str, float]] | None = None) -> list[Fact]:
    facts: list[Fact] = []
    add = lambda a, v, s, c: facts.append(Fact(a, str(v), s, round(c, 3)))  # noqa: E731

    # ---- architecture --------------------------------------------------------------
    elf_arch = Counter()
    for c in scan.components:
        if c.type == "elf":
            elf_arch[(c.details.get("machine"), c.details.get("class"), c.details.get("endianness"))] += 1
        elif c.type == "uimage":
            add("cpu_architecture", _ARCH_NORMAL.get(c.details["arch"], c.details["arch"]),
                f"uImage header @{c.offset:#x} (CRC-verified)", 0.9)
        elif c.type == "arm_zimage":
            add("cpu_architecture", "ARM (32-bit)", f"ARM zImage magic @{c.offset:#x}", 0.8)
        elif c.type == "arm64_image":
            add("cpu_architecture", "ARM64 (AArch64)", f"ARM64 Image header @{c.offset:#x}", 0.85)
    if elf_arch:
        (mach, cls, endian), n = elf_arch.most_common(1)[0]
        total = sum(elf_arch.values())
        add("cpu_architecture", _ARCH_NORMAL.get(mach, mach), f"ELF headers ({n} of {total} binaries)",
            0.6 + 0.3 * n / total if total > 1 else 0.7)
        add("endianness", endian, f"ELF headers ({n} binaries)", 0.85)
        add("word_size", cls, f"ELF headers ({n} binaries)", 0.8)

    # ---- kernel / bootloader / OS -----------------------------------------------------------
    s = strings.hits if strings else {}
    for h in s.get("kernel_version", [])[:5]:
        add("kernel_version", h["value"], f"string @{h['offset']:#x}: {h['text'][:60]}", 0.9)
    for c in scan.components:
        if c.type == "uimage":
            m = re.search(r"(\d+\.\d+\.\d+)", c.details.get("name", ""))
            if m and c.details.get("os") == "Linux":
                add("kernel_version", m.group(1), f"uImage name '{c.details['name']}' @{c.offset:#x}", 0.6)
            if c.details.get("image_type") in ("firmware", "standalone") or c.details.get("os") == "U-Boot":
                add("bootloader", f"U-Boot image '{c.details.get('name')}'", f"uImage header @{c.offset:#x}", 0.8)
        if c.type == "android_boot":
            add("os_family", "Android", f"Android boot image @{c.offset:#x}", 0.85)
            if c.details.get("cmdline"):
                add("kernel_cmdline", c.details["cmdline"][:300], f"Android boot header @{c.offset:#x}", 0.9)
        if c.type == "vbmeta":
            add("signing", f"Android Verified Boot, {c.details['algorithm']}", f"vbmeta @{c.offset:#x}", 0.9)
    for h in s.get("uboot_version", [])[:3]:
        add("bootloader", f"U-Boot {h['value']}", f"string @{h['offset']:#x}", 0.85)
    for h in s.get("busybox_version", [])[:2]:
        add("userland", f"BusyBox {h['value']}", f"string @{h['offset']:#x}", 0.85)
    for h in s.get("toolchain", [])[:3]:
        add("toolchain", h["value"], f"string @{h['offset']:#x}", 0.8)
    for h in s.get("build_date", [])[:3]:
        add("build_date", h["value"], f"string @{h['offset']:#x}", 0.6)
    if s.get("kernel_version"):
        add("os_family", "Linux", "kernel version string", 0.85)
    for h in s.get("platform_keyword", []):
        if h["value"] != "Linux":
            add("platform_mention", h["value"], f"string @{h['offset']:#x} (keyword only, not proof of OS)", 0.4)
    for h in s.get("android_property", [])[:20]:
        key, _, val = h["value"].partition(" ")
        attr = {"ro.build.version.release": "android_version", "ro.build.display.id": "build_id",
                "ro.build.version.incremental": "build_number", "ro.product.model": "product_model",
                "ro.board.platform": "board_platform", "ro.hardware": "hardware",
                "ro.build.fingerprint": "build_fingerprint", "ro.product.brand": "product_brand",
                "ro.product.manufacturer": "product_manufacturer", "ro.product.device": "product_device",
                "ro.product.board": "product_board", "ro.build.date": "build_date"}.get(key)
        if attr and val:
            add(attr, val, f"property string @{h['offset']:#x}", 0.8)
            if attr == "android_version":
                add("os_family", "Android", f"ro.build.version.release @{h['offset']:#x}", 0.85)
    for h in s.get("firmware_version", [])[:5]:
        add("firmware_version", h["value"], f"string @{h['offset']:#x}: {h['text'][:60]}", 0.6)
    for h in s.get("partition_name", [])[:10]:
        add("partition_info", h["value"][:200], f"string @{h['offset']:#x}", 0.7)
    for h in (strings.chip_mentions if strings else [])[:20]:
        add("chip_mention", f"{h['part']} ({h['vendor'] or '?'} {h['type']})", f"string @{h['offset']:#x}", 0.5)

    for attr, val, src, conf in inventory_facts or []:
        add(attr, val, f"extracted file {src}", conf)
        if attr == "android_version":
            add("os_family", "Android", f"extracted file {src}", 0.9)

    # ---- version from the file name (weakest evidence) ------------------------------------
    for m in _VERSION_IN_NAME.finditer(filename.rsplit(".", 1)[0]):
        add("firmware_version", m.group(1), f"file name '{filename}' (naming only, unverified)", 0.35)

    # ---- structure-level facts ----------------------------------------------------------------
    fs = sorted({c.type for c in scan.components if c.category == "filesystem"})
    if fs:
        add("filesystems", ", ".join(fs), "validated signatures", 0.9)
    comp = sorted({c.type for c in scan.components if c.category == "compressed"} |
                  {c.details.get("compression") for c in scan.components if c.type in ("squashfs", "uimage")
                   and c.details.get("compression") not in (None, "none")})
    if comp:
        add("compression", ", ".join(comp), "validated signatures / headers", 0.9)
    for c in scan.components:
        if c.category == "partition_table":
            for p in c.details.get("partitions", []):
                label = p.get("name") or f"#{p['index']} type {p.get('type')}"
                add("partition", f"{label}: offset {p['offset']:#x}, size {p['size']:,} B"
                                 + ("" if p.get("inside_image", True) else " (outside image)"),
                    f"{c.type.upper()} @{c.offset:#x}", 0.9)
        if c.type == "uimage" and c.details.get("data_crc_ok") is False:
            add("integrity_warning", f"uImage '{c.details.get('name')}' data CRC mismatch", f"@{c.offset:#x}", 0.95)
    if entropy:
        for ind in entropy.indicators:
            add("encryption_indicator", ind, f"entropy analysis (block {entropy.block_size} B)", 0.5)
        if not entropy.indicators:
            add("encryption_indicator", "none — high-entropy regions are explained by recognised formats"
                if any(r["class"] == "high" for r in entropy.regions) else "none — no high-entropy regions",
                "entropy analysis", 0.6)
    return merge_facts(facts)


# Attributes where different values in one image are a contradiction worth flagging.
_SINGLE_VALUED = {"cpu_architecture": "CPU architecture", "endianness": "endianness",
                  "android_version": "Android version", "product_model": "product model"}


def merge_facts(facts: list[Fact]) -> list[Fact]:
    """One fact per (attribute, value). Independent sources raise confidence
    (1 - Π(1-p), capped at 0.97); the source text lists the first sources and a count.
    Conflicting values for single-valued attributes produce a 'conflict' fact."""
    groups: dict[tuple[str, str], list[Fact]] = {}
    for f in facts:
        groups.setdefault((f.attribute, f.value), []).append(f)
    out = []
    for (attr, val), fs in groups.items():
        fs.sort(key=lambda f: -f.confidence)
        miss = 1.0
        for f in fs:
            miss *= 1 - f.confidence
        conf = fs[0].confidence if len(fs) == 1 else min(0.97, 1 - miss)
        src = fs[0].source if len(fs) == 1 else f"{len(fs)} sources: " + "; ".join(f.source for f in fs[:3]) + \
            ("; …" if len(fs) > 3 else "")
        out.append(Fact(attr, val, src, round(conf, 3)))
    for attr, label in _SINGLE_VALUED.items():
        vals = sorted({f.value for f in out if f.attribute == attr})
        if len(vals) > 1:
            out.append(Fact("conflict", f"Different {label} values found: {', '.join(vals)} — the image may contain "
                                        "code for several targets, or some components are not for this device. "
                                        "Review sources before drawing conclusions.", "metadata cross-check", 0.9))
    return sorted(out, key=lambda f: (f.attribute, -f.confidence))
