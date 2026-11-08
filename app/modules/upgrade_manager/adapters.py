"""Upgrade method adapters (plugin architecture).

Each method is an ``UpgradeMethod``. Only ``OfficialUsbUpgrade`` can *execute*,
and what it executes is limited to what the manufacturer's documented USB
procedure asks the technician to do on a PC: put the validated package on a
correctly formatted USB stick under the documented name/path, then verify the
copy. The TV's own official updater performs the update. Nothing is ever
written to a TV, its flash chip, partitions or bootloader by this application.

All other methods produce instructions and a technician report only.
Additional adapters can be registered with ``register()``.
"""
from __future__ import annotations

import ctypes
import fnmatch
import hashlib
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

METHODS: dict[str, "UpgradeMethod"] = {}


def register(cls):
    METHODS[cls.key] = cls()
    return cls


@dataclass
class Check:
    name: str
    ok: bool | None          # None = needs operator confirmation
    detail: str


@dataclass
class ExecutionResult:
    ok: bool
    log: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


class UpgradeMethod:
    key = "base"
    label = "base"
    executes = False
    default_risk = "high"
    summary = ""

    def instructions(self, profile: dict, firmware) -> list[str]:
        steps = [f"Method: {self.label}. Follow the manufacturer's documentation: {profile['documentation_ref']}."]
        if profile.get("instructions"):
            steps += [s.strip() for s in profile["instructions"].splitlines() if s.strip()]
        if profile.get("power_requirements"):
            steps.append(f"Power: {profile['power_requirements']}")
        steps.append("Do NOT switch off the TV or remove the medium while the TV is updating.")
        return steps

    def preflight(self, profile: dict, firmware, target: str | None, fs_probe=None) -> list[Check]:
        return []

    def execute(self, profile: dict, firmware, target: str, progress=None, cancel=None, fs_probe=None) -> ExecutionResult:
        raise PermissionError(f"{self.label} is not executed by this application — technician instructions only")


# ---- filesystem probing ------------------------------------------------------------------------------
def probe_volume(path: str) -> dict:
    """{'fs': 'FAT32'|'exFAT'|'NTFS'|..., 'free': bytes, 'removable': bool|None, 'root': str}"""
    p = Path(path)
    usage = shutil.disk_usage(p)
    if os.name == "nt":
        root = os.path.splitdrive(str(p.resolve()))[0] + "\\"
        fsbuf = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(root), None, 0, None, None, None, fsbuf, 64)
        fs = fsbuf.value if ok else "unknown"
        if fs == "FAT32" or fs.upper() == "FAT32":
            fs = "FAT32"
        removable = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2   # DRIVE_REMOVABLE
        return {"fs": fs, "free": usage.free, "removable": removable, "root": root}
    best, fs = "", "unknown"
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                dev, mnt, typ = line.split()[:3]
                mnt = mnt.replace("\\040", " ")
                if str(p.resolve()).startswith(mnt) and len(mnt) > len(best):
                    best, fs = mnt, {"vfat": "FAT32", "exfat": "exFAT", "ntfs": "NTFS", "ntfs3": "NTFS",
                                     "fuseblk": "NTFS/exFAT (fuse)"}.get(typ, typ)
    except OSError:
        pass
    return {"fs": fs, "free": usage.free, "removable": None, "root": best or str(p)}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


@register
class OfficialUsbUpgrade(UpgradeMethod):
    key = "official_usb"
    label = "Official USB Upgrade"
    executes = True
    default_risk = "medium"
    summary = "Prepares a USB stick exactly as documented; the TV's own updater installs it."

    def target_file(self, profile: dict, firmware, target: str) -> Path:
        sub = (profile.get("usb_target_path") or "/").strip().strip("/\\")
        name = (profile.get("usb_target_name") or "").strip() or Path(firmware.stored_path).name
        if any(c in name for c in "/\\") or ".." in sub.split("/"):
            raise ValueError("invalid target path/name in profile")
        root = Path(target)
        dest = (root / sub / name) if sub else (root / name)
        if root.resolve() not in dest.resolve().parents:
            raise ValueError("target outside the selected drive")
        return dest

    def preflight(self, profile, firmware, target, fs_probe=None) -> list[Check]:
        checks = []
        size = firmware.file_size
        if not target or not Path(target).is_dir():
            return [Check("USB drive", False, "select the USB drive (mounted folder / drive letter)")]
        info = (fs_probe or probe_volume)(target)
        wanted = [x.strip().upper() for x in (profile.get("usb_filesystems") or "").split(",") if x.strip()]
        fs_ok = (info["fs"].upper() in wanted) if wanted else None
        checks.append(Check("Filesystem", fs_ok, f"{info['fs']} (documented: {', '.join(wanted) or 'not stated — confirm'})"))
        if wanted and "FAT32" in wanted and size >= 4 * 1024 ** 3:
            checks.append(Check("FAT32 file size limit", False, "package ≥ 4 GiB cannot be stored on FAT32"))
        need = int(size * 1.1) + 1024 * 1024
        checks.append(Check("Free space", info["free"] >= need, f"{info['free']:,} B free, {need:,} B needed"))
        checks.append(Check("Removable drive", info["removable"] if info["removable"] is not None else None,
                            "removable" if info["removable"] else ("not a removable drive!" if info["removable"] is False
                                                                   else "cannot be determined on this OS — confirm")))
        pat = profile.get("package_pattern")
        if pat:
            checks.append(Check("Package file name", fnmatch.fnmatch(Path(firmware.original_filename).name.lower(),
                                                                     pat.lower()),
                                f"{firmware.original_filename} vs documented pattern {pat}"))
        try:
            dest = self.target_file(profile, firmware, target)
            checks.append(Check("Target path", True, str(dest)))
            if dest.exists():
                checks.append(Check("Existing file", None, f"{dest.name} already exists on the drive and will be replaced"))
        except ValueError as exc:
            checks.append(Check("Target path", False, str(exc)))
        return checks

    def execute(self, profile, firmware, target, progress=None, cancel=None, fs_probe=None) -> ExecutionResult:
        log = []
        blocking = [c for c in self.preflight(profile, firmware, target, fs_probe) if c.ok is False]
        if blocking:
            raise RuntimeError("Pre-flight failed: " + "; ".join(f"{c.name}: {c.detail}" for c in blocking))
        src = Path(firmware.stored_path)
        if _sha256(src) != firmware.sha256:
            raise RuntimeError("Library copy failed its SHA-256 check — aborting")
        dest = self.target_file(profile, firmware, target)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tvis-partial")
        total, done = src.stat().st_size, 0
        log.append(f"Copying {src.name} ({total:,} B) to {dest}")
        try:
            with open(src, "rb") as fi, open(tmp, "wb") as fo:
                for b in iter(lambda: fi.read(1 << 20), b""):
                    if cancel and cancel():
                        raise InterruptedError("cancelled by operator before the TV update started")
                    fo.write(b)
                    done += len(b)
                    if progress:
                        progress(done, total, "copying")
                fo.flush()
                os.fsync(fo.fileno())
            if dest.exists():
                os.chmod(dest, 0o666)
                dest.unlink()
            tmp.rename(dest)
        except BaseException:
            tmp.unlink(missing_ok=True)           # never leave a partial package on the stick
            raise
        log.append("Verifying copy (SHA-256)…")
        if progress:
            progress(total, total, "verifying")
        digest = _sha256(dest)
        ok = digest == firmware.sha256
        log.append(f"SHA-256 on USB: {digest} — {'MATCH' if ok else 'MISMATCH'}")
        if not ok:
            dest.unlink(missing_ok=True)
        return ExecutionResult(ok, log, {"usb_file": str(dest), "sha256": digest, "bytes": total})


def _instruction_only(key_, label_, risk, summary_):
    @register
    class _M(UpgradeMethod):
        key, label, default_risk, summary = key_, label_, risk, summary_
    _M.__name__ = "".join(w.capitalize() for w in key_.split("_"))
    return _M


_instruction_only("official_network", "Official Network Upgrade", "low",
                  "Started from the TV's own menu (e.g. Settings > Software update); the application only documents it.")
_instruction_only("service_tool", "Manufacturer Service Tool", "high",
                  "Performed with the manufacturer's own service software per its manual; report only.")
_instruction_only("authorized_uart", "Authorised Serial / UART Upgrade", "critical",
                  "High risk; technician instructions and report only — never executed by this application.")
_instruction_only("authorized_usb_device", "Authorised USB Device Upgrade", "critical",
                  "High risk; technician instructions and report only — never executed by this application.")
_instruction_only("vendor_recovery", "Supported Vendor Recovery Interface", "high",
                  "Recovery procedure per vendor documentation; technician instructions and report only.")
