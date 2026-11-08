# Test Report — Phase 4 (Firmware Analyzer)

* Date: 2026-11-08 · Build 0.4.0 · database schema v4 (migration `0004_firmware_analyzer.sql`)
* Environment: Linux x86-64 container, Python 3.13, PySide6 6.12 (offscreen), Binwalk 2.3.3, 7-Zip (p7zip 16.02),
  squashfs-tools, e2fsprogs, mtd-utils, jefferson 0.4.8, ubi_reader 0.8.16, pytest 9 + pytest-qt.
* **Not executed on a physical Windows 10/11 machine. Ghidra not installed.**

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **186 passed, 0 failed, 0 skipped**
(156 from Phases 1–3 + 30 new).

## Test images
* Built natively in Python (`tests/firmware_builders.py`, run on any OS): uImage with real CRCs, Android boot
  v0, Android sparse, vbmeta, GPT disk with CRCs, DTB, ELF/ARM, cpio, tar, zip, gzip/xz/bzip2, and a composite
  multi-part "TV firmware" image.
* Built with the reference tools (skipped automatically when absent): SquashFS (mksquashfs), ext4 (mkfs.ext4),
  JFFS2 (mkfs.jffs2). During development, UBI/UBIFS (ubinize/mkfs.ubifs) and 7z were also verified manually.
* No vendor firmware is bundled or downloaded.

## Deliverables (spec Module C)

| # | Function | Result | Evidence |
|---|---|---|---|
| 1 | File signature identification | PASS | `test_scanner_finds_all_native_formats` |
| 2 | Firmware header analysis | PASS | uImage/Android boot/sparse/vbmeta/GPT details asserted |
| 3 | Filesystem detection | PASS | squashfs, ext4, jffs2 (real tools); UBI/UBIFS, cramfs validators |
| 4 | Kernel detection | PASS | uImage kernel, `Linux version` string, Android boot image |
| 5 | CPU architecture | PASS | uImage arch (CRC-verified), ELF machine vote, conflict flagging |
| 6 | Firmware version | PASS | strings, build props, file name (weakest, marked unverified) |
| 7 | Partition information | PASS | `test_gpt_and_partitions`; MBR; partitions carved + extracted |
| 8 | Bootloader information | PASS | U-Boot version strings, uImage firmware type |
| 9 | Compression detection | PASS | gzip/xz/bzip2/LZMA with trial decompression |
| 10 | Encryption indicators | PASS | `test_entropy_indicator_only_for_unexplained_data` |
| 11 | Integrity checking | PASS | uImage header + data CRC, corrupted header rejected, library hash before/after |
| 12 | SHA-256 | PASS | before/after per run |
| 13 | Structure visualisation | PASS | StructureMap widget, PDF drawing |
| 14 | Filesystem extraction (safe) | PASS | traversal, symlink, bomb, size-limit tests; 12 formats extracted |
| 15 | Firmware comparison | PASS | `test_compare_two_versions` |
| 16 | Configuration file discovery | PASS | config/sensitive classification, os-release/build.prop facts |
| 17 | Strings analysis | PASS | `test_strings_categories` |
| 18 | Metadata extraction | PASS | `test_full_analysis_pipeline` |
| — | Original firmware unchanged | PASS | `original_unchanged = 1`; analysis refused when the stored copy was altered |
| — | No false positives on random data | PASS | 4 MB (test) and 32 MB (manual): 0 components |
| — | Binwalk integration (v2) | PASS | `test_binwalk_real_run` |
| — | Binwalk v3 | NOT TESTED | parser only (no v3 binary available) |
| — | Ghidra integration | PARTIAL | command, workspace guard, result storage tested with a stand-in; real Ghidra NOT TESTED |
| — | HxD integration | NOT TESTED | Windows-only; button opens the read-only library copy |
| — | Hex viewer | PASS | UI test (`27 05 19 56` at 0x10000) |
| — | Firmware Analysis Report PDF/JSON | PASS | `test_firmware_reports` |
| — | UI (sync + background) | PASS | `test_firmware_analyzer_page`, `test_firmware_analyzer_async` |
| — | PyInstaller build | PASS (Linux) | schema v4, Ghidra script bundled |
| — | Real TV vendor firmware | NOT TESTED | proprietary containers (e.g. vendor-encrypted packages) will show as unrecognised/high entropy |

## Bugs found and fixed during Phase 4
1. Operator precedence `pos + 1 << 20` in the stream walker read a wrong range.
2. gzip size counted the 8-byte trailer twice, which broke nesting inside uImage.
3. ext4 with the 64-bit feature was rejected: `s_blocks_count_hi` lies beyond the 264 bytes read. The full superblock is now read.
4. DTB with an empty strings block (`off_dt_strings == totalsize`) was rejected.
5. Entropy blocks of 1 KiB never exceed ~7.8 for random data, so encryption was invisible in small files. The minimum block size is now 8 KiB.
6. The chi-square "near-uniform" remark fired for fully explained gzip data. It is now only supporting information.
7. The PyInstaller build pulled in a system matplotlib through the binwalk package. It is now excluded.
8. Flaky test (about 1 in 5 runs): random bytes before a test string were sometimes printable and merged into it.
   The analyser was correct (it uses a regex search); the test fixture and assertion were fixed. Six consecutive
   full runs then passed.

## Known open issues
1. Vendor-specific containers (MStar `.bin` scripts, Samsung/LG/Sony/Hisense packages, Amlogic burning images)
   are not parsed beyond generic signatures. They appear as unrecognised regions; adapters can be added per vendor
   when documented.
2. In the frozen EXE, JFFS2/UBI extraction needs `jefferson`/`ubi_reader` on PATH (they are Python CLIs);
   7-Zip covers squashfs/ext/cramfs on Windows.
3. Analysis of very large images (several GB) is bounded by the extraction limits; the scan itself streams with mmap.
