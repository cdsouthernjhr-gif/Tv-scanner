"""Magic-byte file signature identification.

This is the first, dependency-free layer of the Firmware Analyzer. It only
reports what the bytes prove; unknown data is reported as ``unknown`` rather
than guessed. Very short magics (LZMA 0x5D0000, JFFS2 0x1985) are
deliberately excluded here because they produce false positives; Binwalk
handles them with additional header validation. Deep scanning (embedded offsets) is done by Binwalk in Phase 4.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    offset: int = 0
    category: str = "archive"


SIGNATURES: tuple[Signature, ...] = (
    Signature("ZIP archive", b"PK\x03\x04"),
    Signature("ZIP archive (empty)", b"PK\x05\x06"),
    Signature("GZIP compressed", b"\x1f\x8b"),
    Signature("BZIP2 compressed", b"BZh"),
    Signature("XZ compressed", b"\xfd7zXZ\x00"),
    Signature("Zstandard compressed", b"\x28\xb5\x2f\xfd"),
    Signature("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    Signature("RAR archive", b"Rar!\x1a\x07"),
    Signature("POSIX TAR archive", b"ustar", offset=257),
    Signature("U-Boot uImage", b"\x27\x05\x19\x56", category="bootloader/kernel"),
    Signature("Android boot image", b"ANDROID!", category="bootloader/kernel"),
    Signature("Android sparse image", b"\x3a\xff\x26\xed", category="filesystem"),
    Signature("Flattened device tree / FIT", b"\xd0\x0d\xfe\xed", category="bootloader/kernel"),
    Signature("SquashFS (LE)", b"hsqs", category="filesystem"),
    Signature("SquashFS (BE)", b"sqsh", category="filesystem"),
    Signature("CramFS", b"\x45\x3d\xcd\x28", category="filesystem"),
    Signature("UBI image", b"UBI#", category="filesystem"),
    Signature("UBIFS", b"\x31\x18\x10\x06", category="filesystem"),
    Signature("ELF executable", b"\x7fELF", category="executable"),
    Signature("Amlogic USB burning image", b"\x56\x19\xb5\x27", category="vendor"),
    Signature("Android OTA payload (CrAU)", b"CrAU", category="vendor"),
    Signature("PDF document", b"%PDF", category="document"),
)

EXT4_MAGIC_OFFSET = 0x438
EXT4_MAGIC = b"\x53\xef"


@dataclass
class FormatResult:
    format: str
    category: str
    confidence: str  # "signature" when magic bytes match, "extension" when only by name, "none"
    details: str = ""


def detect_format(path: str | Path) -> FormatResult:
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    for sig in SIGNATURES:
        if head[sig.offset:sig.offset + len(sig.magic)] == sig.magic:
            return FormatResult(sig.name, sig.category, "signature")
    if len(head) >= EXT4_MAGIC_OFFSET + 2 and head[EXT4_MAGIC_OFFSET:EXT4_MAGIC_OFFSET + 2] == EXT4_MAGIC:
        return FormatResult("ext2/3/4 filesystem", "filesystem", "signature")
    ext = path.suffix.lower().lstrip(".")
    if ext in {"bin", "img", "rom", "pkg", "epk", "upg"}:
        return FormatResult(f"Unidentified binary (.{ext})", "unknown", "extension",
                            "No known header at offset 0; deep scan required (Phase 4: Binwalk)")
    return FormatResult("unknown", "unknown", "none")
