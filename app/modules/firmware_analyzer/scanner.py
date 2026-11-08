"""Native deep signature scanner (no external tools required).

Finds embedded formats at any offset of a firmware image and **validates**
each hit before reporting it: header CRCs where the format has them (uImage,
xz, 7z, UBI, JFFS2, GPT, tar checksum, PNG IHDR), otherwise structural
consistency (sizes inside the file, version fields, power-of-two block sizes,
trial decompression for gzip/LZMA). Hits that fail validation are counted but
not reported, so random byte patterns do not show up as "filesystems".

Each component has ``validated`` = True when integrity fields were checked,
False when the format only allows a plausibility check (e.g. zstd, JPEG).
"""
from __future__ import annotations

import bz2
import lzma
import mmap
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

MAX_CANDIDATES_PER_TYPE = 20000
TRIAL_DECOMPRESS_LIMIT = 64 * 1024 * 1024      # max compressed bytes walked to find a stream's end


@dataclass
class Component:
    offset: int
    size: int | None
    type: str
    category: str
    description: str
    details: dict = field(default_factory=dict)
    validated: bool = True
    source: str = "native"
    parent: int | None = None      # index of the enclosing component in the result list

    @property
    def end(self) -> int | None:
        return None if self.size is None else self.offset + self.size


@dataclass
class ScanResult:
    file_size: int
    components: list[Component]
    rejected: dict[str, int]       # candidates per type that failed validation
    truncated: list[str]           # types where MAX_CANDIDATES_PER_TYPE was hit


def _crc_le_raw(data: bytes, seed: int) -> int:
    """Linux crc32_le(seed, data) without pre/post inversion (used by UBI and JFFS2)."""
    return (~zlib.crc32(data, ~seed & 0xFFFFFFFF)) & 0xFFFFFFFF


# ---- validators: (mm, off, size_of_file) -> Component | None -------------------------------
UIMAGE_ARCH = {1: "Alpha", 2: "ARM", 3: "x86", 4: "IA64", 5: "MIPS", 6: "MIPS64", 7: "PowerPC", 8: "S390",
               9: "SuperH", 10: "SPARC", 11: "SPARC64", 12: "M68K", 15: "Blackfin", 16: "AVR32", 17: "ST200",
               20: "NDS32", 21: "OpenRISC", 22: "ARM64", 23: "ARC", 24: "x86_64", 25: "Xtensa", 26: "RISC-V"}
UIMAGE_OS = {1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD", 4: "4.4BSD", 5: "Linux", 6: "SVR4", 14: "QNX", 17: "U-Boot",
             19: "RTEMS", 20: "ARM Trusted Firmware", 22: "OpenRTOS"}
UIMAGE_TYPE = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi-file", 5: "firmware", 6: "script",
               7: "filesystem", 8: "flat device tree", 9: "kwbimage", 10: "imximage", 14: "kernel (no load)"}
UIMAGE_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def v_uimage(mm, off, fsize):
    if off + 64 > fsize:
        return None
    hdr = bytes(mm[off:off + 64])
    (magic, hcrc, ts, size, load, ep, dcrc, os_, arch, typ, comp) = struct.unpack(">IIIIIIIBBBB", hdr[:32])
    if zlib.crc32(hdr[:4] + b"\0\0\0\0" + hdr[8:]) & 0xFFFFFFFF != hcrc:
        return None
    if off + 64 + size > fsize:
        return None
    name = hdr[32:64].split(b"\0")[0].decode("latin-1", "replace")
    data_ok = None
    if size <= 256 * 1024 * 1024:
        data_ok = zlib.crc32(mm[off + 64:off + 64 + size]) & 0xFFFFFFFF == dcrc
    typ_s = UIMAGE_TYPE.get(typ, f"type {typ}")
    cat = {"kernel": "kernel", "kernel (no load)": "kernel", "ramdisk": "filesystem", "filesystem": "filesystem",
           "firmware": "bootloader", "standalone": "bootloader", "flat device tree": "devicetree"}.get(typ_s, "image")
    return Component(off, 64 + size, "uimage", cat,
                     f"U-Boot uImage '{name}': {UIMAGE_OS.get(os_, os_)} {typ_s}, {UIMAGE_ARCH.get(arch, arch)}, "
                     f"compression {UIMAGE_COMP.get(comp, comp)}, data CRC {'OK' if data_ok else 'not checked' if data_ok is None else 'MISMATCH'}",
                     {"name": name, "os": UIMAGE_OS.get(os_, str(os_)), "arch": UIMAGE_ARCH.get(arch, str(arch)),
                      "image_type": typ_s, "compression": UIMAGE_COMP.get(comp, str(comp)), "load_address": hex(load),
                      "entry_point": hex(ep), "data_size": size, "timestamp": ts, "data_crc_ok": data_ok})


def v_android_boot(mm, off, fsize):
    if off + 1660 > fsize:
        return None
    h = bytes(mm[off:off + 1660])
    hv = struct.unpack_from("<I", h, 40)[0]
    if hv > 4:
        return None
    if hv <= 2:
        ks, ka, rs, ra, ss, sa, ta, ps = struct.unpack_from("<8I", h, 8)
        if ps not in (2048, 4096, 8192, 16384):
            return None
        pages = lambda n: (n + ps - 1) // ps
        size = ps * (1 + pages(ks) + pages(rs) + pages(ss))
        name = h[48:64].split(b"\0")[0].decode("latin-1", "replace")
        cmdline = h[64:576].split(b"\0")[0].decode("latin-1", "replace")
        details = {"header_version": hv, "page_size": ps, "kernel_size": ks, "ramdisk_size": rs,
                   "second_size": ss, "kernel_addr": hex(ka), "name": name, "cmdline": cmdline}
    else:
        ks, rs, osv, hsz = struct.unpack_from("<4I", h, 8)
        if hsz not in (1580, 1584) or ks == 0:
            return None
        ps = 4096
        size = ps * (1 + (ks + ps - 1) // ps + (rs + ps - 1) // ps)
        cmdline = h[44:44 + 1536].split(b"\0")[0].decode("latin-1", "replace")
        details = {"header_version": hv, "page_size": ps, "kernel_size": ks, "ramdisk_size": rs, "cmdline": cmdline}
    if off + size > fsize + ps:   # last page may be unpadded
        return None
    return Component(off, min(size, fsize - off), "android_boot", "kernel",
                     f"Android boot image v{hv}: kernel {details['kernel_size']} B, ramdisk {details['ramdisk_size']} B",
                     details)


def v_android_sparse(mm, off, fsize):
    if off + 28 > fsize:
        return None
    magic, major, minor, fhs, chs, blk, tblks, tchunks, _ = struct.unpack_from("<IHHHHIIII", mm, off)
    if major != 1 or fhs != 28 or chs != 12 or blk == 0 or blk % 4 or tchunks == 0:
        return None
    pos = off + fhs
    for _ in range(min(tchunks, 1_000_000)):
        if pos + 12 > fsize:
            return None
        ctype, _r, csz, total = struct.unpack_from("<HHII", mm, pos)
        if ctype not in (0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4) or total < 12:
            return None
        pos += total
    return Component(off, pos - off, "android_sparse", "filesystem",
                     f"Android sparse image: {tblks} blocks of {blk} B ({tblks * blk:,} B expanded), {tchunks} chunks",
                     {"block_size": blk, "total_blocks": tblks, "chunks": tchunks, "expanded_size": tblks * blk})


SQUASH_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def v_squashfs(mm, off, fsize, be=False):
    if off + 96 > fsize:
        return None
    e = ">" if be else "<"
    inodes, mtime, bsize, frags = struct.unpack_from(e + "IIII", mm, off + 4)
    comp, blog, flags, nids, major, minor = struct.unpack_from(e + "HHHHHH", mm, off + 20)
    bytes_used = struct.unpack_from(e + "Q", mm, off + 40)[0]
    if major == 4:
        if bsize != (1 << blog) or not (4096 <= bsize <= 1048576) or comp not in SQUASH_COMP:
            return None
        if not (96 <= bytes_used <= fsize - off):
            return None
        return Component(off, bytes_used, "squashfs", "filesystem",
                         f"SquashFS 4.{minor} ({'BE' if be else 'LE'}), {SQUASH_COMP[comp]}, {inodes} inodes, "
                         f"block {bsize}, {bytes_used:,} B",
                         {"version": f"4.{minor}", "compression": SQUASH_COMP[comp], "inodes": inodes,
                          "block_size": bsize, "bytes_used": bytes_used, "created": mtime})
    if major in (2, 3) and minor <= 1:
        # v2/v3 layout differs; bytes_used is 32-bit at offset 8 for v3 (lzma/gzip variants are common in old TVs)
        b3 = struct.unpack_from(e + "I", mm, off + 8)[0]
        if not (96 <= b3 <= fsize - off):
            return None
        return Component(off, b3, "squashfs", "filesystem", f"SquashFS {major}.{minor} ({'BE' if be else 'LE'}) "
                         "(legacy, header partially validated)", {"version": f"{major}.{minor}"}, validated=False)
    return None


def v_cramfs(mm, off, fsize):
    if off + 64 > fsize or bytes(mm[off + 16:off + 32]) != b"Compressed ROMFS":
        return None
    size = struct.unpack_from("<I", mm, off + 4)[0]
    if not (64 <= size <= fsize - off):
        return None
    name = bytes(mm[off + 48:off + 64]).split(b"\0")[0].decode("latin-1", "replace")
    return Component(off, size, "cramfs", "filesystem", f"CramFS '{name}', {size:,} B", {"name": name})


def v_ubi(mm, off, fsize):
    if off + 64 > fsize:
        return None
    h = bytes(mm[off:off + 64])
    if h[4] != 1 or _crc_le_raw(h[:60], 0xFFFFFFFF) != struct.unpack_from(">I", h, 60)[0]:
        return None
    vid_off, data_off = struct.unpack_from(">II", h, 16)
    nxt = mm.find(b"UBI#", off + max(data_off, 4096))
    peb = nxt - off if nxt > 0 else None
    count = 1
    if peb:
        p = off + peb
        while p + 64 <= fsize and bytes(mm[p:p + 4]) == b"UBI#":
            count += 1
            p += peb
    size = peb * count if peb else None
    return Component(off, size, "ubi", "filesystem",
                     f"UBI image: {count} erase block(s)" + (f" of {peb:,} B" if peb else "") +
                     f", VID header @{vid_off}, data @{data_off}",
                     {"erase_block_size": peb, "erase_blocks": count, "vid_hdr_offset": vid_off,
                      "data_offset": data_off})


def v_ubifs(mm, off, fsize):
    if off + 24 > fsize:
        return None
    crc, sqnum, ln, ntype = struct.unpack_from("<IQIB", mm, off + 4)
    if ntype != 6 or not (24 < ln <= 4096) or off + ln > fsize:   # 6 = superblock node
        return None
    if _crc_le_raw(bytes(mm[off + 8:off + ln]), 0xFFFFFFFF) != crc:
        return None
    return Component(off, None, "ubifs", "filesystem", "UBIFS superblock node", {})


def v_jffs2(mm, off, fsize):
    if off + 12 > fsize:
        return None
    magic, ntype, totlen, crc = struct.unpack_from("<HHII", mm, off)
    if ntype & 0x1FFF not in (1, 2, 3, 4, 6, 8, 9) or totlen < 12 or off + totlen > fsize:
        return None
    if _crc_le_raw(bytes(mm[off:off + 8]), 0) != crc:
        return None
    # walk consecutive nodes (4-byte aligned); 0xFF/0x00 padding between nodes is allowed
    # (end of erase block) but a padding run longer than 256 KiB ends the filesystem.
    pos, nodes, last_end = off, 0, off
    while pos + 12 <= fsize and nodes < 1_000_000:
        word = bytes(mm[pos:pos + 4])
        if word[:2] == b"\x85\x19":
            m, t, tl, c = struct.unpack_from("<HHII", mm, pos)
            if tl < 12 or pos + tl > fsize or _crc_le_raw(bytes(mm[pos:pos + 8]), 0) != c:
                break
            pos += (tl + 3) & ~3
            last_end = pos
            nodes += 1
        elif word in (b"\xff\xff\xff\xff", b"\0\0\0\0") and pos - last_end < 256 * 1024:
            pos += 4
        else:
            break
    pos = last_end
    return Component(off, pos - off, "jffs2", "filesystem", f"JFFS2 filesystem (LE), {nodes} nodes", {"nodes": nodes})


def v_ext(mm, off_magic, fsize):
    off = off_magic - 0x438
    if off < 0 or off % 512 or off + 0x800 > fsize:
        return None
    sb = bytes(mm[off + 0x400:off + 0x800])        # full 1 KiB superblock (64-bit fields live at 0x150)
    inodes, blocks = struct.unpack_from("<II", sb, 0)
    log_bs = struct.unpack_from("<I", sb, 24)[0]
    rev = struct.unpack_from("<I", sb, 76)[0]
    if log_bs > 6 or inodes == 0 or blocks == 0 or rev > 1:
        return None
    bs = 1024 << log_bs
    compat, incompat, ro = struct.unpack_from("<III", sb, 92)
    hi = struct.unpack_from("<I", sb, 0x150)[0] if (incompat & 0x80) else 0
    size = ((hi << 32) | blocks) * bs
    if size > (fsize - off) * 2 + bs:   # allow truncated images, but not absurd sizes
        return None
    kind = "ext4" if incompat & (0x40 | 0x80 | 0x200) else "ext3" if compat & 0x4 else "ext2"
    name = sb[120:136].split(b"\0")[0].decode("latin-1", "replace")
    uuid = sb[104:120].hex()
    truncated = size > fsize - off
    return Component(off, min(size, fsize - off), kind, "filesystem",
                     f"{kind} filesystem '{name}', block {bs}, {size:,} B" + (" (truncated in image)" if truncated else ""),
                     {"volume_name": name, "block_size": bs, "size": size, "uuid": uuid, "truncated": truncated})


def _stream_end(decomp_factory, mm, off, fsize):
    """Walk a compressed stream to find where it ends; returns (compressed_len, out_len) or None."""
    d = decomp_factory()
    pos, out = off, 0
    end = min(fsize, off + TRIAL_DECOMPRESS_LIMIT)
    try:
        while pos < end:
            chunk = bytes(mm[pos:min(pos + (1 << 20), end)])
            res = d.decompress(chunk)
            out += len(res)
            if d.eof:
                used = len(chunk) - len(d.unused_data)
                return pos + used - off, out
            pos += len(chunk)
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
        return None
    return None


def v_gzip(mm, off, fsize):
    if off + 18 > fsize:
        return None
    flags, xfl, os_ = mm[off + 3], mm[off + 8], mm[off + 9]
    if flags & 0xE0 or xfl not in (0, 2, 4) or (os_ > 13 and os_ != 255):
        return None
    name = None
    if flags & 0x08:
        p = off + 10 + (2 + struct.unpack_from("<H", mm, off + 10)[0] if flags & 0x04 else 0)
        e = mm.find(b"\0", p, p + 256)
        if e > 0:
            name = bytes(mm[p:e]).decode("latin-1", "replace")
    r = _stream_end(lambda: zlib.decompressobj(16 + zlib.MAX_WBITS), mm, off, fsize)
    if r is None:
        return None
    clen, olen = r
    return Component(off, clen, "gzip", "compressed",   # clen already includes the 8-byte trailer
                     f"gzip stream{(' ' + repr(name)) if name else ''}: {clen:,} B -> {olen:,} B",
                     {"original_name": name, "uncompressed_size": olen})


def v_xz(mm, off, fsize):
    if off + 12 > fsize:
        return None
    flags = bytes(mm[off + 6:off + 8])
    if flags[0] != 0 or flags[1] & 0xF0 or zlib.crc32(flags) & 0xFFFFFFFF != struct.unpack_from("<I", mm, off + 8)[0]:
        return None
    r = _stream_end(lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ), mm, off, fsize)
    size, olen = (r if r else (None, None))
    return Component(off, size, "xz", "compressed",
                     "xz stream" + (f": {size:,} B -> {olen:,} B" if size else " (end not found within limit)"),
                     {"uncompressed_size": olen})


def v_bzip2(mm, off, fsize):
    if off + 10 > fsize or not (0x31 <= mm[off + 3] <= 0x39) or bytes(mm[off + 4:off + 10]) != b"\x31\x41\x59\x26\x53\x59":
        return None
    r = _stream_end(bz2.BZ2Decompressor, mm, off, fsize)
    size, olen = (r if r else (None, None))
    return Component(off, size, "bzip2", "compressed",
                     "bzip2 stream" + (f": {size:,} B -> {olen:,} B" if size else ""), {"uncompressed_size": olen})


def v_lzma(mm, off, fsize):
    if off + 13 > fsize:
        return None
    props = mm[off]
    dsize = struct.unpack_from("<I", mm, off + 1)[0]
    usize = struct.unpack_from("<Q", mm, off + 5)[0]
    if props >= 225 or dsize < 4096 or dsize > (1 << 30) or (dsize & (dsize - 1) and dsize % (3 << 10)):
        return None
    if usize != 0xFFFFFFFFFFFFFFFF and usize > (1 << 36):
        return None
    try:
        d = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
        out = d.decompress(bytes(mm[off:off + 65536]), max_length=8192)
        if len(out) < 256 and not d.eof:
            return None
    except lzma.LZMAError:
        return None
    r = _stream_end(lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE), mm, off, fsize)
    size = r[0] if r else None
    return Component(off, size, "lzma", "compressed",
                     f"LZMA stream, dictionary {dsize // 1024} KiB" +
                     (f", {usize:,} B uncompressed" if usize != 0xFFFFFFFFFFFFFFFF else ""),
                     {"dictionary_size": dsize, "uncompressed_size": None if usize == 0xFFFFFFFFFFFFFFFF else usize})


def v_zstd(mm, off, fsize):
    if off + 6 > fsize or mm[off + 4] & 0x08:   # reserved bit must be 0
        return None
    return Component(off, None, "zstd", "compressed", "Zstandard frame (header plausible)", {}, validated=False)


def v_zip(mm, off, fsize):
    if off + 30 > fsize:
        return None
    ver, flag, meth = struct.unpack_from("<HHH", mm, off + 4)
    nlen, xlen = struct.unpack_from("<HH", mm, off + 26)
    if ver > 63 or meth not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99) or not (0 < nlen <= 1024):
        return None
    name = bytes(mm[off + 30:off + 30 + nlen]).decode("utf-8", "replace")
    # whole archive: locate an EOCD whose central directory points back to this local header
    e = mm.find(b"PK\x05\x06", off)
    tries = 0
    while e > 0 and tries < 50:
        if e + 22 <= fsize:
            cd_size, cd_off = struct.unpack_from("<II", mm, e + 12)
            clen = struct.unpack_from("<H", mm, e + 20)[0]
            if e - cd_size - cd_off == off:
                n = struct.unpack_from("<H", mm, e + 10)[0]
                return Component(off, e + 22 + clen - off, "zip", "archive",
                                 f"ZIP archive, {n} entries (first: {name})", {"entries": n, "first": name})
        e = mm.find(b"PK\x05\x06", e + 4)
        tries += 1
    return None   # lone local headers inside another ZIP are not separate components


def v_7z(mm, off, fsize):
    if off + 32 > fsize or mm[off + 6] != 0:
        return None
    if zlib.crc32(bytes(mm[off + 12:off + 32])) & 0xFFFFFFFF != struct.unpack_from("<I", mm, off + 8)[0]:
        return None
    noff, nsize = struct.unpack_from("<QQ", mm, off + 12)
    size = 32 + noff + nsize
    if off + size > fsize:
        return None
    return Component(off, size, "7z", "archive", f"7-Zip archive, {size:,} B", {})


def v_tar(mm, off_magic, fsize):
    off = off_magic - 257
    if off < 0 or off + 512 > fsize:
        return None
    pos, entries = off, 0
    while pos + 512 <= fsize and entries < 1_000_000:
        h = bytes(mm[pos:pos + 512])
        if h == b"\0" * 512:
            pos += 512
            if pos + 512 <= fsize and bytes(mm[pos:pos + 512]) == b"\0" * 512:
                pos += 512
            break
        try:
            chk = int(h[148:156].strip(b"\0 ") or b"-1", 8)
            size = int(h[124:136].strip(b"\0 ") or b"0", 8)
        except ValueError:
            break
        if chk != sum(h[:148]) + 32 * 8 + sum(h[156:]):
            break
        entries += 1
        pos += 512 + (size + 511) // 512 * 512
    if entries == 0:
        return None
    return Component(off, min(pos, fsize) - off, "tar", "archive", f"POSIX tar archive, {entries} entries",
                     {"entries": entries})


def v_cpio(mm, off, fsize):
    pos, entries = off, 0
    while pos + 110 <= fsize and entries < 1_000_000:
        h = bytes(mm[pos:pos + 110])
        if h[:6] not in (b"070701", b"070702"):
            return None if entries == 0 else Component(off, pos - off, "cpio", "archive",
                                                       f"cpio (newc) archive, {entries} entries (no trailer)",
                                                       {"entries": entries}, validated=False)
        try:
            fsz = int(h[54:62], 16)
            nsz = int(h[94:102], 16)
        except ValueError:
            return None
        name = bytes(mm[pos + 110:pos + 110 + nsz - 1])
        pos = (pos + 110 + nsz + 3) & ~3
        pos = (pos + fsz + 3) & ~3
        if name == b"TRAILER!!!":
            return Component(off, pos - off, "cpio", "archive", f"cpio (newc) archive, {entries} entries",
                             {"entries": entries})
        entries += 1
    return None


ELF_MACHINE = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 62: "x86_64", 183: "AArch64",
               243: "RISC-V", 94: "Xtensa", 42: "SuperH"}
ELF_TYPE = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}


def parse_elf_header(h: bytes) -> dict | None:
    if len(h) < 52 or h[:4] != b"\x7fELF" or h[4] not in (1, 2) or h[5] not in (1, 2) or h[6] != 1:
        return None
    e = "<" if h[5] == 1 else ">"
    is64 = h[4] == 2
    etype, mach = struct.unpack_from(e + "HH", h, 16)
    if etype not in ELF_TYPE:
        return None
    if is64:
        if len(h) < 64:
            return None
        phoff, shoff = struct.unpack_from(e + "QQ", h, 32)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", h, 52)
        if ehsize != 64:
            return None
    else:
        phoff, shoff = struct.unpack_from(e + "II", h, 28)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", h, 40)
        if ehsize != 52:
            return None
    return {"class": "64-bit" if is64 else "32-bit", "endianness": "little" if h[5] == 1 else "big",
            "machine": ELF_MACHINE.get(mach, f"machine {mach}"), "type": ELF_TYPE[etype],
            "size_hint": max(shoff + shnum * shentsize, phoff + phnum * phentsize)}


def v_elf(mm, off, fsize):
    info = parse_elf_header(bytes(mm[off:off + 64]))
    if not info or info["size_hint"] > fsize - off or info["size_hint"] == 0:
        return None
    return Component(off, info["size_hint"], "elf", "executable",
                     f"ELF {info['class']} {info['endianness']}-endian {info['machine']} {info['type']}",
                     {k: v for k, v in info.items() if k != "size_hint"})


def v_dtb(mm, off, fsize):
    if off + 40 > fsize:
        return None
    total, ostruct, ostrings, orsv, ver, lcv = struct.unpack_from(">IIIIII", mm, off + 4)
    if ver not in (16, 17) or lcv > 17 or not (40 <= total <= fsize - off):
        return None
    if not (ostruct < total and ostrings <= total and orsv < total):   # empty strings block may end the blob
        return None
    blob = bytes(mm[off:off + min(total, 1 << 20)])
    fit = b"images" in blob and b"configurations" in blob
    return Component(off, total, "fit" if fit else "dtb", "devicetree",
                     ("FIT image (U-Boot flattened image tree)" if fit else "Device tree blob (DTB)") +
                     f", {total:,} B, version {ver}", {"version": ver})


def v_zimage(mm, off_magic, fsize):
    off = off_magic - 0x24
    if off < 0:
        return None
    start, end = struct.unpack_from("<II", mm, off_magic + 4)
    size = end - start
    if not (1024 < size <= fsize - off):
        return None
    return Component(off, size, "arm_zimage", "kernel", f"Linux ARM zImage, {size:,} B",
                     {"load_start": hex(start)})


def v_arm64(mm, off_magic, fsize):
    off = off_magic - 0x38
    if off < 0:
        return None
    text_off, img_size, flags = struct.unpack_from("<QQQ", mm, off + 8)
    if not (0 < img_size < (1 << 31)) or text_off % 4096:
        return None
    return Component(off, None, "arm64_image", "kernel",
                     f"Linux ARM64 kernel Image (effective size {img_size:,} B)", {"image_size": img_size,
                                                                                  "text_offset": hex(text_off)})


def v_png(mm, off, fsize):
    if off + 33 > fsize or bytes(mm[off + 12:off + 16]) != b"IHDR":
        return None
    if zlib.crc32(bytes(mm[off + 12:off + 29])) & 0xFFFFFFFF != struct.unpack_from(">I", mm, off + 29)[0]:
        return None
    w, h = struct.unpack_from(">II", mm, off + 16)
    e = mm.find(b"IEND", off, min(fsize, off + 64 * 1024 * 1024))
    size = e + 8 - off if e > 0 else None
    return Component(off, size, "png", "image", f"PNG image {w}x{h} (boot logo / UI asset)", {"width": w, "height": h})


def v_jpeg(mm, off, fsize):
    tag = bytes(mm[off + 6:off + 11])
    if tag not in (b"JFIF\0", b"Exif\0"):
        return None
    return Component(off, None, "jpeg", "image", f"JPEG image ({tag[:4].decode()})", {}, validated=False)


AVB_ALGOS = {0: "NONE (unsigned)", 1: "SHA256_RSA2048", 2: "SHA256_RSA4096", 3: "SHA256_RSA8192",
             4: "SHA512_RSA2048", 5: "SHA512_RSA4096", 6: "SHA512_RSA8192"}


def v_vbmeta(mm, off, fsize):
    """Android Verified Boot 2.0 vbmeta header (big-endian)."""
    if off + 256 > fsize:
        return None
    major, minor, auth, aux, algo = struct.unpack_from(">IIQQI", mm, off + 4)
    if major != 1 or minor > 10 or algo not in AVB_ALGOS or auth > (1 << 20) or aux > (1 << 24):
        return None
    if (auth % 64) or (aux % 64):
        return None
    size = 256 + auth + aux
    if off + size > fsize:
        return None
    return Component(off, size, "vbmeta", "signature",
                     f"Android Verified Boot metadata (vbmeta) v{major}.{minor}, algorithm {AVB_ALGOS[algo]}",
                     {"algorithm": AVB_ALGOS[algo], "signed": algo != 0})


def v_mbr(mm, off, fsize):
    if off != 0 or fsize < 512 or bytes(mm[510:512]) != b"\x55\xaa":
        return None
    parts = []
    for i in range(4):
        e = 446 + 16 * i
        status, ptype = mm[e], mm[e + 4]
        lba, n = struct.unpack_from("<II", mm, e + 8)
        if status not in (0, 0x80):
            return None
        if ptype:
            if lba == 0 or n == 0:
                return None
            parts.append({"index": i + 1, "type": hex(ptype), "start_lba": lba, "sectors": n,
                          "offset": lba * 512, "size": n * 512, "bootable": status == 0x80,
                          "inside_image": (lba + n) * 512 <= fsize})
    if not parts or parts[0]["type"] == "0xee":
        return None   # protective MBR is reported via GPT
    return Component(0, 512, "mbr", "partition_table", f"MBR partition table, {len(parts)} partition(s)",
                     {"partitions": parts})


def v_gpt(mm, off, fsize):
    """off points at 'EFI PART'. Sector size = off (512 or 4096)."""
    sector = off
    if sector not in (512, 4096) or off + 92 > fsize:
        return None
    hdr = bytes(mm[off:off + 92])
    hsize = struct.unpack_from("<I", hdr, 12)[0]
    if hsize != 92 or zlib.crc32(hdr[:16] + b"\0\0\0\0" + hdr[20:92]) & 0xFFFFFFFF != struct.unpack_from("<I", hdr, 16)[0]:
        return None
    entries_lba, nent, esz = struct.unpack_from("<QII", hdr, 72)
    parts = []
    base = entries_lba * sector
    for i in range(min(nent, 256)):
        p = base + i * esz
        if p + 128 > fsize:
            break
        e = bytes(mm[p:p + 128])
        if e[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le", "replace").split("\0")[0]
        parts.append({"index": i + 1, "name": name, "offset": first * sector, "size": (last - first + 1) * sector,
                      "inside_image": (last + 1) * sector <= fsize})
    return Component(0, None, "gpt", "partition_table", f"GPT partition table, {len(parts)} partition(s), "
                     f"{sector}-byte sectors", {"partitions": parts, "sector_size": sector})


# (magic, validator, extra kwargs) — offset passed is where the magic was found
SIGNATURES = [
    (b"\x27\x05\x19\x56", v_uimage, {}),
    (b"ANDROID!", v_android_boot, {}),
    (b"\x3a\xff\x26\xed", v_android_sparse, {}),
    (b"hsqs", v_squashfs, {}),
    (b"sqsh", v_squashfs, {"be": True}),
    (b"\x45\x3d\xcd\x28", v_cramfs, {}),
    (b"UBI#", v_ubi, {}),
    (b"\x31\x18\x10\x06", v_ubifs, {}),
    (b"\x85\x19", v_jffs2, {}),
    (b"\x53\xef", v_ext, {}),
    (b"\x1f\x8b\x08", v_gzip, {}),
    (b"\xfd7zXZ\x00", v_xz, {}),
    (b"BZh", v_bzip2, {}),
    (b"\x5d\x00\x00", v_lzma, {}),
    (b"\x28\xb5\x2f\xfd", v_zstd, {}),
    (b"PK\x03\x04", v_zip, {}),
    (b"7z\xbc\xaf\x27\x1c", v_7z, {}),
    (b"ustar", v_tar, {}),
    (b"070701", v_cpio, {}),
    (b"070702", v_cpio, {}),
    (b"\x7fELF", v_elf, {}),
    (b"\xd0\x0d\xfe\xed", v_dtb, {}),
    (b"\x18\x28\x6f\x01", v_zimage, {}),
    (b"ARM\x64", v_arm64, {}),
    (b"\x89PNG\r\n\x1a\n", v_png, {}),
    (b"\xff\xd8\xff", v_jpeg, {}),
    (b"EFI PART", v_gpt, {}),
    (b"AVB0", v_vbmeta, {}),
]
# Types whose children are not scanned separately when the parent is a validated container that
# we report as a whole (e.g. every JFFS2 node, every UBI erase block).
_SKIP_INSIDE_SAME_TYPE = {"jffs2", "ubi", "tar", "cpio", "android_sparse"}


def scan(path: str | Path, max_candidates: int = MAX_CANDIDATES_PER_TYPE) -> ScanResult:
    path = Path(path)
    fsize = path.stat().st_size
    comps: list[Component] = []
    rejected: dict[str, int] = {}
    truncated: list[str] = []
    if fsize == 0:
        return ScanResult(0, [], {}, [])
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        mbr = v_mbr(mm, 0, fsize)
        if mbr:
            comps.append(mbr)
        for magic, fn, kw in SIGNATURES:
            pos, n = mm.find(magic), 0
            covered_until = -1
            while pos != -1:
                n += 1
                if n > max_candidates:
                    truncated.append(fn.__name__[2:])
                    break
                if pos < covered_until:
                    pos = mm.find(magic, pos + 1)
                    continue
                try:
                    c = fn(mm, pos, fsize, **kw)
                except (struct.error, IndexError, ValueError):
                    c = None
                if c is None:
                    rejected[fn.__name__[2:]] = rejected.get(fn.__name__[2:], 0) + 1
                else:
                    comps.append(c)
                    if c.type in _SKIP_INSIDE_SAME_TYPE and c.size:
                        covered_until = c.offset + c.size
                pos = mm.find(magic, pos + 1)
    comps.sort(key=lambda c: (c.offset, -(c.size or 0)))
    _assign_parents(comps)
    return ScanResult(fsize, comps, rejected, truncated)


def _assign_parents(comps: list[Component]) -> None:
    """Parent = smallest validated component with known size that strictly contains the child."""
    for i, c in enumerate(comps):
        best = None
        for j, p in enumerate(comps):
            if j == i or p.size is None or not p.validated:
                continue
            if p.offset <= c.offset and (c.end or c.offset + 1) <= p.end and (p.offset, p.size) != (c.offset, c.size):
                if best is None or p.size < comps[best].size:
                    best = j
        c.parent = best


def gaps(result: ScanResult, min_size: int = 4096) -> list[tuple[int, int]]:
    """Top-level regions not covered by any component with known size."""
    spans = sorted((c.offset, c.end) for c in result.components if c.parent is None and c.size)
    out, cur = [], 0
    for s, e in spans:
        if s - cur >= min_size:
            out.append((cur, s - cur))
        cur = max(cur, e)
    if result.file_size - cur >= min_size:
        out.append((cur, result.file_size - cur))
    return out
