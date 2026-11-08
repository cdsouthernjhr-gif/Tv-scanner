"""Inventory of extracted files: hashes, configuration files, sensitive material and OS facts.

Sensitive files (password databases, private keys, certificates) are *listed*
so a technician knows they exist; their contents are never copied into reports.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_EXT = {".conf", ".cfg", ".ini", ".xml", ".json", ".prop", ".rc", ".yaml", ".yml", ".txt", ".sh"}
CONFIG_NAMES = {"fstab", "inittab", "hosts", "resolv.conf", "os-release", "issue", "version", "build.prop",
                "default.prop", "init.rc", "busybox", "hostname", "profile", "mtab", "rcS", "lsb-release"}
SENSITIVE = re.compile(r"(^|/)(shadow|passwd|gshadow|\.htpasswd|authorized_keys|id_rsa|id_dsa|id_ecdsa|id_ed25519)$|"
                       r"\.(pem|key|p12|pfx|jks|keystore|der|crt|cer)$", re.I)
HASH_LIMIT = 256 * 1024 * 1024
PROP_KEYS = {
    "ro.build.version.release": ("android_version", 0.9), "ro.build.display.id": ("build_id", 0.85),
    "ro.build.version.incremental": ("build_number", 0.85), "ro.build.fingerprint": ("build_fingerprint", 0.9),
    "ro.product.model": ("product_model", 0.8), "ro.product.brand": ("product_brand", 0.8),
    "ro.product.manufacturer": ("product_manufacturer", 0.8), "ro.board.platform": ("board_platform", 0.8),
    "ro.hardware": ("hardware", 0.75), "ro.build.date": ("build_date", 0.8),
}


@dataclass
class FileRecord:
    rel_path: str
    size: int
    sha256: str | None
    kind: str          # file | config | sensitive | symlink
    note: str = ""


@dataclass
class Inventory:
    files: list[FileRecord] = field(default_factory=list)
    facts: list[tuple[str, str, str, float]] = field(default_factory=list)   # attribute, value, source, conf

    @property
    def configs(self):
        return [f for f in self.files if f.kind == "config"]

    @property
    def sensitive(self):
        return [f for f in self.files if f.kind == "sensitive"]


def _sha256(p: Path) -> str | None:
    if p.stat().st_size > HASH_LIMIT:
        return None
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _read_text(p: Path, limit: int = 256 * 1024) -> str:
    with open(p, "rb") as fh:
        return fh.read(limit).decode("utf-8", "replace")


def classify(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1]
    if SENSITIVE.search(rel):
        return "sensitive"
    if name in CONFIG_NAMES or Path(name).suffix.lower() in CONFIG_EXT or rel.startswith("etc/") or "/etc/" in rel:
        return "config"
    return "file"


def inventory(root: Path, skipped_links: list[str] | None = None) -> Inventory:
    inv = Inventory()
    root = Path(root)
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            kind = classify(rel)
            note = "contents not reproduced (sensitive)" if kind == "sensitive" else ""
            inv.files.append(FileRecord(rel, p.stat().st_size, _sha256(p), kind, note))
            _facts_from_file(p, rel, inv)
    for link in skipped_links or []:
        inv.files.append(FileRecord(link.split(" -> ")[0], 0, None, "symlink", link))
    return inv


def _facts_from_file(p: Path, rel: str, inv: Inventory) -> None:
    name = rel.rsplit("/", 1)[-1]
    try:
        if name in ("os-release", "lsb-release") or name.endswith("-release") and p.stat().st_size < 65536:
            for line in _read_text(p).splitlines():
                m = re.match(r'^([A-Z_]+)=["\']?([^"\']*)["\']?$', line.strip())
                if m and m.group(1) in ("NAME", "VERSION", "VERSION_ID", "PRETTY_NAME", "ID", "BUILD_ID",
                                        "DISTRIB_ID", "DISTRIB_RELEASE"):
                    inv.facts.append((f"os_{m.group(1).lower()}", m.group(2), rel, 0.9))
        elif name.endswith(".prop") and p.stat().st_size < 1024 * 1024:
            for line in _read_text(p).splitlines():
                k, _, v = line.partition("=")
                if k.strip() in PROP_KEYS and v.strip():
                    attr, conf = PROP_KEYS[k.strip()]
                    inv.facts.append((attr, v.strip(), rel, conf))
        elif name in ("version", "issue") and rel.startswith("etc/") and p.stat().st_size < 4096:
            txt = _read_text(p).strip().splitlines()
            if txt:
                inv.facts.append(("os_" + name, txt[0][:120], rel, 0.7))
        elif name == "init.rc":
            inv.facts.append(("os_family", "Android", rel + " (init.rc present)", 0.7))
        elif name == "busybox":
            inv.facts.append(("userland", "BusyBox", rel, 0.8))
    except OSError:
        pass
