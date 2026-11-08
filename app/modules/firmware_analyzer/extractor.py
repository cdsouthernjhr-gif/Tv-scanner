"""Safe extraction of firmware components into the analysis workspace.

Guarantees
----------
* Reads only the *working copy*; writes only below ``dest_root``.
* Every output path is resolved and checked to stay inside ``dest_root``
  (no ``..``/absolute-path traversal, no writing through symlinks).
* Symlinks, device nodes and FIFOs inside archives/filesystems are **recorded,
  not created**.
* Limits: total output bytes, number of files, per-stream compression ratio
  (decompression-bomb protection) and recursion depth.
* External tools (7-Zip, unsquashfs, debugfs) run with argument lists (no
  shell), a timeout, and their output is post-checked with the same rules.

Formats without a safe extractor available are reported as such — nothing is
guessed.
"""
from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import os
import shutil
import stat
import struct
import subprocess
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from app.modules.firmware_analyzer.scanner import Component

log = logging.getLogger(__name__)


class LimitExceeded(Exception):
    pass


@dataclass
class Limits:
    max_total_bytes: int = 2 * 1024 ** 3
    max_files: int = 100_000
    max_ratio: int = 200              # output/input for a single compressed stream
    max_depth: int = 3
    tool_timeout: int = 600


@dataclass
class ExtractionEntry:
    component_type: str
    offset: int
    method: str
    status: str                       # extracted | carved | unsupported | failed | skipped
    dest: str | None = None
    files: int = 0
    bytes: int = 0
    message: str = ""
    skipped_links: list[str] = field(default_factory=list)


class SafeExtractor:
    def __init__(self, dest_root: Path, tools: dict[str, str | None] | None = None, limits: Limits | None = None):
        self.root = Path(dest_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.tools = tools or {}
        self.limits = limits or Limits()
        self.total_bytes = 0
        self.total_files = 0

    # ---- path & limit guards ---------------------------------------------------------
    def _safe_path(self, base: Path, name: str) -> Path:
        name = name.replace("\\", "/")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ValueError(f"path traversal in archive member {name!r}")
        target = (base / Path(*parts)) if parts else base
        rt = target.resolve()
        if rt != self.root and self.root not in rt.parents:
            raise ValueError(f"path escapes workspace: {name!r}")
        # refuse to write through an existing symlink anywhere on the path
        p = base
        for part in parts[:-1]:
            p = p / part
            if p.is_symlink():
                raise ValueError(f"path goes through a symlink: {name!r}")
        return target

    def _account(self, nbytes: int, nfiles: int = 0) -> None:
        self.total_bytes += nbytes
        self.total_files += nfiles
        if self.total_bytes > self.limits.max_total_bytes:
            raise LimitExceeded(f"extraction exceeds {self.limits.max_total_bytes:,} bytes")
        if self.total_files > self.limits.max_files:
            raise LimitExceeded(f"extraction exceeds {self.limits.max_files:,} files")

    def _write_stream(self, dest: Path, chunks, in_size: int) -> int:
        dest.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with open(dest, "wb") as out:
            for chunk in chunks:
                n += len(chunk)
                self._account(len(chunk))
                if in_size and n > max(in_size * self.limits.max_ratio, 1 << 20):
                    raise LimitExceeded(f"compression ratio above {self.limits.max_ratio}:1 (possible bomb)")
                out.write(chunk)
        self._account(0, 1)
        return n

    # ---- primitives -------------------------------------------------------------------------
    def carve(self, src: Path, offset: int, size: int, dest: Path) -> int:
        def gen():
            with open(src, "rb") as fh:
                fh.seek(offset)
                left = size
                while left > 0:
                    b = fh.read(min(left, 1 << 20))
                    if not b:
                        break
                    left -= len(b)
                    yield b
        return self._write_stream(dest, gen(), 0)

    def _decompress_file(self, src: Path, dest: Path, kind: str) -> int:
        factories = {"gzip": lambda: zlib.decompressobj(16 + zlib.MAX_WBITS), "xz": lambda: lzma.LZMADecompressor(),
                     "lzma": lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE), "bzip2": bz2.BZ2Decompressor}
        d = factories[kind]()
        in_size = src.stat().st_size

        def gen():
            with open(src, "rb") as fh:
                while True:
                    b = fh.read(1 << 20)
                    if not b:
                        break
                    out = d.decompress(b)
                    if out:
                        yield out
                    if getattr(d, "eof", False):
                        break
        return self._write_stream(dest, gen(), in_size)

    def _extract_zip(self, src: Path, dest: Path, entry: ExtractionEntry) -> None:
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    entry.skipped_links.append(info.filename)
                    continue
                target = self._safe_path(dest, info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if info.compress_size and info.file_size > max(info.compress_size * self.limits.max_ratio, 1 << 20):
                    raise LimitExceeded(f"{info.filename}: compression ratio too high")
                with z.open(info) as fh:
                    entry.bytes += self._write_stream(target, iter(lambda: fh.read(1 << 20), b""), 0)
                entry.files += 1

    def _extract_tar(self, src: Path, dest: Path, entry: ExtractionEntry) -> None:
        with tarfile.open(src) as t:
            for m in t:
                if m.issym() or m.islnk():
                    entry.skipped_links.append(f"{m.name} -> {m.linkname}")
                    continue
                if not (m.isfile() or m.isdir()):
                    entry.skipped_links.append(f"{m.name} (special file, not created)")
                    continue
                target = self._safe_path(dest, m.name)
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                fh = t.extractfile(m)
                entry.bytes += self._write_stream(target, iter(lambda: fh.read(1 << 20), b""), 0)
                entry.files += 1

    def _extract_cpio(self, src: Path, dest: Path, entry: ExtractionEntry) -> None:
        with open(src, "rb") as fh:
            data_len = src.stat().st_size
            pos = 0
            while pos + 110 <= data_len:
                fh.seek(pos)
                h = fh.read(110)
                if h[:6] not in (b"070701", b"070702"):
                    break
                mode = int(h[14:22], 16)
                fsz, nsz = int(h[54:62], 16), int(h[94:102], 16)
                name = fh.read(nsz)[:-1].decode("utf-8", "replace")
                pos = (pos + 110 + nsz + 3) & ~3
                if name == "TRAILER!!!":
                    break
                if stat.S_ISREG(mode):
                    target = self._safe_path(dest, name)
                    fh.seek(pos)
                    entry.bytes += self._write_stream(target, [fh.read(fsz)], 0)
                    entry.files += 1
                elif stat.S_ISDIR(mode):
                    self._safe_path(dest, name).mkdir(parents=True, exist_ok=True)
                else:
                    fh.seek(pos)
                    tgt = fh.read(fsz).decode("utf-8", "replace") if stat.S_ISLNK(mode) else "special file"
                    entry.skipped_links.append(f"{name} -> {tgt}")
                pos = (pos + fsz + 3) & ~3

    def _unsparse(self, src: Path, dest: Path) -> int:
        with open(src, "rb") as fh:
            magic, major, minor, fhs, chs, blk, tblks, tchunks, _ = struct.unpack("<IHHHHIIII", fh.read(28))
            fh.seek(fhs)

            def gen():
                for _ in range(tchunks):
                    ctype, _r, csz, total = struct.unpack("<HHII", fh.read(12))
                    fh.read(chs - 12)
                    if ctype == 0xCAC1:          # raw
                        left = csz * blk
                        while left:
                            b = fh.read(min(left, 1 << 20))
                            if not b:
                                return
                            left -= len(b)
                            yield b
                    elif ctype == 0xCAC2:        # fill
                        pat = fh.read(4)
                        for _ in range(csz):
                            yield pat * (blk // 4)
                    elif ctype == 0xCAC3:        # don't care
                        for _ in range(csz):
                            yield b"\0" * blk
                    else:                        # crc32
                        fh.read(4)
            # expansion ratio of sparse images is legitimately high; total-size limit still applies
            return self._write_stream(dest, gen(), 0)

    def _run_tool(self, args: list[str], dest: Path) -> tuple[bool, str]:
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=self.limits.tool_timeout,
                               stdin=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        return p.returncode == 0, (p.stdout + p.stderr)[-2000:]

    def _post_check_tree(self, dest: Path, entry: ExtractionEntry) -> None:
        """After an external tool: drop symlinks/special files, verify containment, account sizes."""
        for dirpath, dirnames, filenames in os.walk(dest, followlinks=False):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    entry.skipped_links.append(f"{p.relative_to(dest)} -> {os.readlink(p)}")
                    p.unlink()
                elif not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                    entry.skipped_links.append(f"{p.relative_to(dest)} (special file removed)")
                    p.unlink()
                elif stat.S_ISREG(st.st_mode):
                    rp = p.resolve()
                    if self.root not in rp.parents:
                        raise ValueError(f"extracted file outside workspace: {p}")
                    entry.files += 1
                    entry.bytes += st.st_size
                    self._account(st.st_size, 1)

    def _external(self, kind: str, src: Path, dest: Path, entry: ExtractionEntry) -> bool:
        seven = self.tools.get("seven_zip")
        unsq = self.tools.get("unsquashfs")
        debugfs = self.tools.get("debugfs")
        jeff = self.tools.get("jefferson")
        ubir = self.tools.get("ubireader")
        if kind == "jffs2" and jeff:
            ok, msg = self._run_tool([jeff, "-d", str(dest), str(src)], dest)   # jefferson creates dest itself
            entry.method = "jefferson"
            dest.mkdir(parents=True, exist_ok=True)
            self._post_check_tree(dest, entry)
            if not ok and entry.files == 0:
                raise RuntimeError(msg.strip().splitlines()[-1] if msg.strip() else "jefferson failed")
            return True
        dest.mkdir(parents=True, exist_ok=True)
        if kind in ("ubi", "ubifs") and ubir:
            ok, msg = self._run_tool([ubir, "-o", str(dest), str(src)], dest)
            entry.method = "ubi_reader"
        elif kind == "squashfs" and unsq:
            ok, msg = self._run_tool([unsq, "-no-xattrs", "-f", "-d", str(dest), str(src)], dest)
            entry.method = "unsquashfs"
        elif kind in ("ext2", "ext3", "ext4") and debugfs and not seven:
            ok, msg = self._run_tool([debugfs, "-R", f"rdump / {dest}", str(src)], dest)
            entry.method = "debugfs"
        elif kind in ("squashfs", "ext2", "ext3", "ext4", "cramfs", "7z", "gpt", "mbr") and seven:
            # -snl: store symlinks as links (then removed by the post-check); -y: never prompt
            ok, msg = self._run_tool([seven, "x", "-y", "-snl", f"-o{dest}", str(src)], dest)
            entry.method = "7-Zip"
        else:
            return False
        self._post_check_tree(dest, entry)
        if not ok and entry.files == 0:
            raise RuntimeError(msg.strip().splitlines()[-1] if msg.strip() else "tool failed")
        entry.message = "" if ok else f"tool reported errors; {entry.files} file(s) recovered"
        return True

    # ---- component dispatch -------------------------------------------------------------------
    def extract_component(self, working_copy: Path, c: Component, depth: int = 0) -> ExtractionEntry:
        entry = ExtractionEntry(c.type, c.offset, "", "unsupported")
        base = self.root / f"{c.offset:#010x}_{c.type}"
        entry.dest = str(base)
        try:
            if c.size is None:
                entry.message = "component size unknown — cannot be carved safely"
                return entry
            carved = base.with_suffix(".bin")
            self.carve(working_copy, c.offset, c.size, carved)
            entry.status, entry.method = "carved", "carve"
            self._extract_file(carved, c.type, base, entry, depth, c)
        except LimitExceeded as exc:
            entry.status, entry.message = "failed", f"limit: {exc}"
        except (ValueError, OSError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, lzma.LZMAError,
                zlib.error, EOFError, struct.error) as exc:
            entry.status, entry.message = "failed", str(exc)
        return entry

    def _extract_file(self, src: Path, kind: str, dest: Path, entry: ExtractionEntry, depth: int,
                      c: Component | None = None) -> None:
        if depth > self.limits.max_depth:
            entry.message = "maximum nesting depth reached"
            return
        if kind == "zip":
            entry.method = "zipfile"
            self._extract_zip(src, dest, entry)
        elif kind == "tar":
            entry.method = "tarfile"
            self._extract_tar(src, dest, entry)
        elif kind == "cpio":
            entry.method = "cpio (native)"
            self._extract_cpio(src, dest, entry)
        elif kind in ("gzip", "xz", "lzma", "bzip2"):
            out = dest / "decompressed.bin"
            entry.bytes += self._decompress_file(src, out, kind)
            entry.files += 1
            entry.method = f"{kind} (native)"
            self._nested(out, dest, entry, depth)
        elif kind == "android_sparse":
            out = dest / "unsparsed.img"
            entry.bytes += self._unsparse(src, out)
            entry.files += 1
            entry.method = "android sparse (native)"
            self._nested(out, dest, entry, depth)
        elif kind == "uimage":
            payload = dest / "payload.bin"
            with open(src, "rb") as fh:
                fh.seek(64)
                entry.bytes += self._write_stream(payload, iter(lambda: fh.read(1 << 20), b""), 0)
            entry.files += 1
            entry.method = "uImage payload"
            comp = (c.details or {}).get("compression") if c else None
            if comp in ("gzip", "lzma", "bzip2"):
                out = dest / "payload.decompressed"
                entry.bytes += self._decompress_file(payload, out, comp)
                entry.files += 1
                self._nested(out, dest, entry, depth)
        elif not self._external(kind, src, dest, entry):
            hint = {"jffs2": "pip install jefferson", "ubi": "pip install ubi_reader",
                    "ubifs": "pip install ubi_reader"}.get(kind, "install 7-Zip (or unsquashfs/debugfs via WSL)")
            entry.message = (f"no safe extractor available for {kind} on this system ({hint}). "
                             "Component was carved only.")
            return
        entry.status = "extracted"

    def _nested(self, out: Path, dest: Path, entry: ExtractionEntry, depth: int) -> None:
        """A decompressed stream may itself be an archive (e.g. initrd.gz → cpio)."""
        with open(out, "rb") as fh:
            head = fh.read(512)
        kind = "cpio" if head[:6] in (b"070701", b"070702") else \
            "tar" if len(head) >= 262 and head[257:262] == b"ustar" else None
        if kind:
            self._extract_file(out, kind, dest / f"{kind}_contents", entry, depth + 1)
