"""Build firmware test images natively (no external tools) plus tool-based builders that skip when absent.

All content is synthetic. Formats follow their public specifications so the
scanner's validation (CRCs, header fields) is exercised for real.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib
from pathlib import Path


def uimage(payload: bytes, name: str = "Linux-4.9.118", arch: int = 2, os_: int = 5, typ: int = 2,
           comp: int = 1, corrupt_header: bool = False) -> bytes:
    dcrc = zlib.crc32(payload) & 0xFFFFFFFF
    hdr = struct.pack(">IIIIIIIBBBB", 0x27051956, 0, 1_700_000_000, len(payload), 0x80008000, 0x80008000, dcrc,
                      os_, arch, typ, comp) + name.encode().ljust(32, b"\0")
    hcrc = zlib.crc32(hdr) & 0xFFFFFFFF
    hdr = hdr[:4] + struct.pack(">I", hcrc ^ (1 if corrupt_header else 0)) + hdr[8:]
    return hdr + payload


def android_boot_v0(kernel: bytes, ramdisk: bytes, page: int = 2048, cmdline: str = "console=ttyS0 androidboot.hardware=tv") -> bytes:
    hdr = b"ANDROID!" + struct.pack("<8I", len(kernel), 0x10008000, len(ramdisk), 0x11000000, 0, 0, 0x10000100, page)
    hdr += struct.pack("<II", 0, 0) + b"tvboot".ljust(16, b"\0") + cmdline.encode().ljust(512, b"\0") + b"\0" * 32
    hdr += b"\0" * 1024
    pad = lambda b: b + b"\0" * ((-len(b)) % page)  # noqa: E731
    return pad(hdr) + pad(kernel) + pad(ramdisk)


def android_sparse(raw: bytes, blk: int = 4096) -> bytes:
    assert len(raw) % blk == 0
    nblk = len(raw) // blk
    chunks = []
    i = 0
    while i < nblk:
        b = raw[i * blk:(i + 1) * blk]
        if b == b"\0" * blk:
            j = i
            while j < nblk and raw[j * blk:(j + 1) * blk] == b"\0" * blk:
                j += 1
            chunks.append(struct.pack("<HHII", 0xCAC3, 0, j - i, 12))
            i = j
        else:
            chunks.append(struct.pack("<HHII", 0xCAC1, 0, 1, 12 + blk) + b)
            i += 1
    return struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, nblk, len(chunks), 0) + b"".join(chunks)


def cpio_newc(files: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    out = io.BytesIO()
    ino = 1

    def entry(name: str, data: bytes, mode: int):
        nonlocal ino
        nm = name.encode() + b"\0"
        h = b"070701" + b"".join(f"{v:08x}".encode() for v in
                                 (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        ino += 1
        out.write(h + nm)
        out.write(b"\0" * ((-out.tell()) % 4))
        out.write(data)
        out.write(b"\0" * ((-out.tell()) % 4))
    for n, d in files.items():
        entry(n, d, 0o100644)
    for n, t in (symlinks or {}).items():
        entry(n, t.encode(), 0o120777)
    entry("TRAILER!!!", b"", 0)
    return out.getvalue()


def elf32_arm() -> bytes:
    h = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    h += struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0x8000, 52, 0, 0x5000000, 52, 32, 1, 40, 0, 0)
    ph = struct.pack("<8I", 1, 0, 0x8000, 0x8000, 200, 200, 5, 0x1000)
    return h + ph + b"\0" * 116


def dtb() -> bytes:
    struct_blk = struct.pack(">I", 1) + b"\0\0\0\0" + struct.pack(">I", 2) + struct.pack(">I", 9)
    rsv = b"\0" * 16
    off_rsv = 40
    off_struct = off_rsv + len(rsv)
    off_strings = off_struct + len(struct_blk)
    total = off_strings
    hdr = struct.pack(">10I", 0xD00DFEED, total, off_struct, off_strings, off_rsv, 17, 16, 0, 0, len(struct_blk))
    return hdr + rsv + struct_blk


def gpt_disk(partitions: list[tuple[str, int, bytes]], sector: int = 512) -> bytes:
    """partitions: (name, first_lba, content). Builds protective MBR + GPT header/entries with valid CRCs."""
    last = max(lba + (len(c) + sector - 1) // sector for _, lba, c in partitions) + 34
    disk = bytearray(last * sector)
    disk[446:462] = bytes([0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF]) + struct.pack("<II", 1, last - 1)
    disk[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    for i, (name, lba, content) in enumerate(partitions):
        nsec = (len(content) + sector - 1) // sector
        e = os.urandom(16) + os.urandom(16) + struct.pack("<QQQ", lba, lba + nsec - 1, 0) + \
            name.encode("utf-16-le").ljust(72, b"\0")
        entries[i * 128:(i + 1) * 128] = e
        disk[lba * sector:lba * sector + len(content)] = content
    ecrc = zlib.crc32(bytes(entries)) & 0xFFFFFFFF
    disk[2 * sector:2 * sector + len(entries)] = entries
    hdr = bytearray(b"EFI PART" + struct.pack("<IIII", 0x10000, 92, 0, 0) +
                    struct.pack("<QQQQ", 1, last - 1, 34, last - 34) + os.urandom(16) +
                    struct.pack("<QIII", 2, 128, 128, ecrc))
    struct.pack_into("<I", hdr, 16, zlib.crc32(bytes(hdr)) & 0xFFFFFFFF)
    disk[sector:sector + 92] = hdr
    return bytes(disk)


def vbmeta(algo: int = 1) -> bytes:
    h = b"AVB0" + struct.pack(">IIQQI", 1, 0, 576, 1088, algo)
    return h.ljust(256, b"\0") + b"\0" * (576 + 1088)


def kernel_blob(version: str = "4.9.118") -> bytes:
    s = (f"Linux version {version} (builder@tv) (gcc version 6.3.1 (Linaro)) #1 SMP PREEMPT "
         f"Mon Mar 2 10:11:12 CST 2020\0").encode()
    return os.urandom(20000) + b"\0" + s + b"U-Boot 2015.04-tv (Jan 01 2020)\0" + os.urandom(20000)


def composite(path: Path, version: str = "4.9.118", extra_file: bytes = b"") -> dict:
    """A realistic multi-part 'TV firmware' made only with Python."""
    parts = {}
    rootfs = {"etc/os-release": b'NAME="Linux"\nVERSION_ID="4.9"\n', "system/build.prop":
              b"ro.build.version.release=9\nro.product.model=TESTTV55\nro.board.platform=m7642\n",
              "etc/shadow": b"root:*:0:0:99999:7:::\n", "etc/app.conf": b"x=1\n" + extra_file}
    blob = bytearray(b"TVFW-HDR v1.0 build " + version.encode())
    blob += b"\xff" * (0x10000 - len(blob))

    def place(name, data, align=0x10000):
        nonlocal blob
        blob += b"\xff" * ((-len(blob)) % align)
        parts[name] = len(blob)
        blob += data
    place("uimage", uimage(gzip.compress(kernel_blob(version), mtime=0), name=f"Linux-{version}"))
    place("dtb", dtb())
    place("initrd_gz", gzip.compress(cpio_newc(rootfs, {"bin/sh": "busybox"}), mtime=0))
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as t:
        for n, d in rootfs.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    place("tar", tbuf.getvalue())
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in rootfs.items():
            z.writestr(n, d)
    place("zip", zbuf.getvalue())
    place("xz", lzma.compress(b"config data " * 2000))
    place("bz2", bz2.compress(b"logo data " * 3000))
    place("elf", elf32_arm())
    place("boot", android_boot_v0(os.urandom(5000), gzip.compress(cpio_newc({"init": b"#!/bin/sh"}), mtime=0)))
    place("sparse", android_sparse(b"A" * 4096 + b"\0" * 8192 + b"B" * 4096))
    place("vbmeta", vbmeta())
    blob += b"\xff" * 4096
    path.write_bytes(bytes(blob))
    return parts


# ---- tool-based builders (skipped when tools are missing) --------------------------------
def have(*tools: str) -> bool:
    return all(shutil.which(t) for t in tools)


def build_rootfs_dir(d: Path) -> Path:
    (d / "etc").mkdir(parents=True, exist_ok=True)
    (d / "etc" / "os-release").write_text('NAME="Linux"\nVERSION_ID="4.9"\n')
    (d / "system").mkdir(exist_ok=True)
    (d / "system" / "build.prop").write_text("ro.build.version.release=9\n")
    return d


def squashfs(out: Path, src: Path) -> Path:
    subprocess.run(["mksquashfs", str(src), str(out), "-comp", "xz", "-quiet", "-noappend"], check=True,
                   capture_output=True)
    return out


def ext4(out: Path, src: Path) -> Path:
    with open(out, "wb") as fh:
        fh.truncate(4 * 1024 * 1024)
    subprocess.run(["mkfs.ext4", "-q", "-L", "rootfs", "-d", str(src), str(out)], check=True, capture_output=True)
    return out


def jffs2(out: Path, src: Path) -> Path:
    subprocess.run(["mkfs.jffs2", "-r", str(src), "-o", str(out), "-e", "0x10000", "-l"], check=True,
                   capture_output=True)
    return out
