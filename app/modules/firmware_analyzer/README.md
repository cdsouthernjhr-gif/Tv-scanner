# Firmware Analyzer (Phase 4)

## Pipeline (one *analysis run*)
| Step | Module | Stored in |
|---|---|---|
| 1. Integrity check of the library copy (refuse if SHA-256 changed) | `service.py` | `firmware_analysis_runs.original_sha256_before` |
| 2. Hash-verified working copy in `workspace/fw_<id>/` (re-created if altered) | `service.py` | `working_copy` |
| 3. Native deep signature scan with header validation | `scanner.py` | `firmware_components` (source `native`) |
| 4. Entropy per block + encryption indicators | `entropy.py` | `firmware_analysis` (`entropy`) |
| 5. Strings: categorised hits + full dump file | `strings_analysis.py` | `firmware_analysis` (`strings`), `run_N/strings.txt` |
| 6. Binwalk (optional second opinion) | `integrations/binwalk` | `firmware_components` (source `binwalk`) |
| 7. Safe extraction + file inventory | `extractor.py`, `config_discovery.py` | `firmware_extracted_files`, `run_N/extracted/` |
| 8. Metadata facts with provenance | `metadata.py` | `firmware_metadata` |
| 9. Re-hash of the original → `original_unchanged` | `service.py` | `firmware_analysis_runs` |

The original is never opened for writing; the library copy is read-only, and only the hex viewer reads it directly.

## Native scanner — formats and validation
| Format | Validation |
|---|---|
| U-Boot uImage | header CRC32 **and** data CRC32 (mismatch reported) |
| Android boot image v0–v4 | header version, page size, sizes inside file |
| Android sparse | header constants + walk of every chunk |
| SquashFS 4.x (LE/BE) / 2–3 | block size = 2^block_log, compression id, bytes_used inside file |
| CramFS | "Compressed ROMFS" signature + size |
| UBI / UBIFS | EC-header CRC (UBI CRC32), consecutive erase blocks; UBIFS superblock node CRC |
| JFFS2 | node header CRC on every node walked |
| ext2/3/4 | sector-aligned superblock, block size, counts, feature flags, 64-bit size |
| gzip / xz / bzip2 / LZMA | header fields + **trial decompression to the end of the stream** (xz: flags CRC) |
| zstd, JPEG | header plausibility only (marked "plausible", not "validated") |
| ZIP | end-of-central-directory must point back to the first local header |
| 7-Zip | start-header CRC |
| tar | header checksum of every entry |
| cpio (newc) | hex header fields, walk to TRAILER!!! |
| ELF | class/endianness/version, header size; machine → architecture |
| DTB / FIT | version, offsets inside total size |
| ARM zImage / ARM64 Image | magic at fixed offset + size/text-offset sanity |
| PNG | IHDR CRC |
| MBR / GPT | MBR only at offset 0 with sane entries; GPT header CRC |
| Android vbmeta (AVB) | version, algorithm, block sizes → signing indicator |

32 MB of random data produce **zero** components (all candidate magic hits are rejected).

## Encryption indicators
Entropy > 7.9 bits/byte means compressed *or* encrypted. An indicator is raised only for high-entropy
data **not explained** by a validated compressed format/filesystem. Chi-square is reported as
supporting information only. Minimum block size is 8 KiB (smaller blocks under-estimate entropy).

## Metadata facts
Every value carries its source (`uImage header @0x10000 (CRC-verified)`, `string @0x1a2b`,
`extracted file …/build.prop`, `file name (naming only, unverified)`). Identical values from several
sources are merged (`1 − Π(1 − p)`, max 97 %). Contradictions (e.g. ARM vs MIPS binaries) produce a
`conflict` fact instead of a silent choice.

## Extraction safety (`extractor.py`)
* Output only under `run_N/extracted/`; every path resolved and checked (no `..`, absolute paths are
  re-rooted, nothing written through symlinks).
* Symlinks, device nodes and FIFOs are recorded, never created.
* Limits (configurable in `settings.json → analysis`): total bytes (2 GiB), files (100 000),
  compression ratio per stream (200:1), nesting depth 3, tool timeout.
* Native: zip, tar, cpio, gzip/xz/bzip2/LZMA, Android sparse, uImage payload (+ nested cpio/tar).
* External (optional): unsquashfs, 7-Zip (squashfs/ext/cramfs/7z), debugfs, jefferson (JFFS2),
  ubi_reader (UBI/UBIFS). Missing tool → component is carved and the reason is reported.
* MBR/GPT partitions are carved and a filesystem at the partition start is extracted.

## Other features
* **Comparison**: 64 KiB block similarity (same offset / anywhere), component differences, metadata
  differences, extracted file added/removed/changed by SHA-256.
* **Hex viewer** (4 KiB pages, go-to offset, jump from components/strings); **Open in HxD** when installed.
* **Import extracted file into the library** with provenance (`extracted_from_firmware`, parent id, run, path).
* **Ghidra**: see `app/integrations/ghidra/README.md`.
* **Reports**: Firmware Analysis Report (PDF with structure/entropy drawing) and JSON.
