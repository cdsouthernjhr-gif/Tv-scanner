"""Software inventory from files extracted by the Firmware Analyzer.

Everything here reads the analysis workspace (never the original firmware).
Classification of drivers and config files is name-based and labelled as such.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.config import application_root

MAX_READ = 512 * 1024


@lru_cache(maxsize=1)
def fingerprints() -> dict:
    return json.loads((application_root() / "resources" / "data" / "os_fingerprints.json").read_text(encoding="utf-8"))


@dataclass
class Item:
    category: str
    name: str
    value: str | None
    source_ref: str
    confidence: float


def _read(p: Path) -> str:
    try:
        with open(p, "rb") as fh:
            return fh.read(MAX_READ).decode("utf-8", "replace")
    except OSError:
        return ""


def applications(files: list[str], root: Path) -> list[Item]:
    out, seen = [], set()
    for rel in files:
        low = rel.lower()
        m = re.search(r"(?:^|/)(?:system|vendor|product|system_ext|data)/(priv-app|app)/([^/]+)/[^/]+\.apk$", rel)
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            out.append(Item("application", m.group(2), "Android APK (" + m.group(1) + ")", rel, 0.9))
            continue
        if low.endswith((".wgt", ".tpk")):
            name = rel.rsplit("/", 1)[-1]
            if name not in seen:
                seen.add(name)
                out.append(Item("application", name, "Tizen package", rel, 0.8))
            continue
        if low.endswith("appinfo.json") and "/applications/" in low:
            try:
                info = json.loads(_read(root / rel))
                name = info.get("id") or rel.split("/applications/")[1].split("/")[0]
                if name not in seen:
                    seen.add(name)
                    out.append(Item("application", name, f"webOS app {info.get('title', '')} v{info.get('version', '?')}".strip(),
                                    rel, 0.85))
            except (json.JSONDecodeError, OSError):
                pass
    return out


_SO_VER = re.compile(r"^(lib[\w+\-]+?)\.so(?:\.([\d.]+))?$")


def libraries(files: list[str]) -> list[Item]:
    """One entry per library; a versioned file name (libssl.so.1.1) wins over the bare alias (libssl.so)."""
    found: dict[str, Item] = {}
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        m = _SO_VER.match(name)
        if not m:
            continue
        cur = found.get(m.group(1))
        if cur is None or (m.group(2) and cur.value == "version not in file name"):
            found[m.group(1)] = Item("library", m.group(1), m.group(2) or "version not in file name", rel, 0.7)
    return list(found.values())


def classify_driver(module: str) -> str:
    name = module.lower().removesuffix(".ko")
    tokens = set(re.split(r"[_\-.]+", name))
    for cls, kws in fingerprints()["driver_classes"].items():
        for kw in kws:
            if name.startswith(kw) or kw in tokens or f"_{kw}" in name:
                return cls
    return "other"


def drivers(files: list[str]) -> list[Item]:
    out, seen = [], set()
    for rel in files:
        if rel.endswith(".ko"):
            mod = rel.rsplit("/", 1)[-1]
            if mod not in seen:
                seen.add(mod)
                out.append(Item("driver", mod, f"{classify_driver(mod)} (name-based classification)", rel, 0.6))
    return out


_IFACE = re.compile(r"\b(eth\d|wlan\d|p2p\d|usb\d|lo|br\d|ra\d|wlp\w+|enp\w+)\b")
_KV = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*[=:]\s*\"?([^\"#;\n]{1,80})", re.M)
DISPLAY_KEYS = re.compile(r"width|height|resolution|hz|frame.?rate|lvds|vby1|vbyone|v-by-one|panel.?name|panel.?type|"
                          r"panel.?id|bit.?depth|colou?r.?depth|dither|hdr|hdmi", re.I)
AUDIO_KEYS = re.compile(r"sample.?rate|channels?|amp|volume|eq|speaker|spdif|arc|i2s|codec|dolby|dts", re.I)


def config_facts(files: list[str], root: Path) -> list[Item]:
    out = []
    ifaces: dict[str, str] = {}
    for rel in files:
        low = rel.lower()
        name = low.rsplit("/", 1)[-1]
        if not (low.endswith((".conf", ".cfg", ".ini", ".xml", ".rc", ".sh", ".json", ".txt")) or "/etc/" in "/" + low):
            continue
        text = None
        if any(k in low for k in ("network", "interfaces", "wpa_supplicant", "dhcp", "init", "rc.local", "net")):
            text = _read(root / rel)
            for m in _IFACE.finditer(text):
                if m.group(1) != "lo":
                    ifaces.setdefault(m.group(1), rel)
        is_display = any(k in low for k in ("panel", "display", "pq", "lcd", "tcon"))
        is_audio = any(k in name for k in ("audio", "sound", "asound", "mixer", "amp", "dolby"))
        if is_display or is_audio:
            text = text if text is not None else _read(root / rel)
            keys = DISPLAY_KEYS if is_display else AUDIO_KEYS
            n = 0
            for m in _KV.finditer(text):
                if keys.search(m.group(1)) and n < 25:
                    out.append(Item("display" if is_display else "audio", m.group(1), m.group(2).strip(), rel, 0.6))
                    n += 1
            if n == 0:
                out.append(Item("display" if is_display else "audio", "configuration file", rel, rel, 0.5))
    for iface, rel in sorted(ifaces.items()):
        out.append(Item("network_interface", iface, "named in configuration (not proof the hardware exists)", rel, 0.5))
    return out


def fingerprint(files: list[str], root: Path, keywords: set[str], props: dict[str, str],
                packages: set[str]) -> list[Item]:
    """Apply os_fingerprints.json rules. Returns OS indicator items (category 'os')."""
    found: dict[str, list[tuple[str, float]]] = {}
    for rule in fingerprints()["rules"]:
        os_ = rule["os"]
        ev = None
        for pat in rule.get("files", []):
            hit = next((f for f in files if fnmatch.fnmatch(f, pat)), None)
            if hit:
                ev = f"file {hit}"
                break
        if not ev:
            for kw in rule.get("strings", []):
                if kw in keywords:
                    ev = f"keyword '{kw}'"
                    break
        if not ev:
            for pkg in rule.get("packages", []):
                if pkg in packages:
                    ev = f"package {pkg}"
                    break
        if not ev:
            for pat, needle in rule.get("file_contains", []):
                for f in fnmatch.filter(files, pat)[:200]:
                    if needle in _read(root / f):
                        ev = f"'{needle}' in {f}"
                        break
                if ev:
                    break
        if ev and rule.get("requires") and rule["requires"] not in found:
            ev = None
        if ev:
            found.setdefault(os_, []).append((f"{ev} — {rule['basis']}", rule["confidence"]))
    out = []
    for os_, evs in found.items():
        miss = 1.0
        for _, c in evs:
            miss *= 1 - c
        out.append(Item("os", os_, "; ".join(e for e, _ in evs), "OS fingerprint rules", round(min(0.95, 1 - miss), 3)))
    return out
