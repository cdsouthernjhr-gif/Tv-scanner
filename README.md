# TV Intelligence Scanner

Universal TV hardware, firmware, software and firmware-upgrade analysis platform
for Windows 10/11 (64-bit). Offline-first desktop application (Python 3 + PySide6 + SQLite).

> **Status: Phase 6 of 8 complete.** Phase 1: core application, database, projects (including
> unknown TVs), evidence images, immutable firmware library, PDF report. Phase 2: OCR (Tesseract),
> OpenCV image processing, label/menu field extraction, chip/PCB marking recognition, model catalog.
> Phase 3: Hardware Analyzer with component reference database, memory part-number decoders,
> local datasheet library with matching, board summary and Hardware Report (PDF/XLSX/CSV/JSON).
> Phase 4: Firmware Analyzer — validated deep signature scan (25+ formats), entropy/encryption
> indicators, strings, metadata with provenance, safe extraction, comparison, hex viewer, Binwalk and
> Ghidra integration, Firmware Analysis Report. Phase 5: Universal Firmware Finder — GitHub, GitLab,
> open-source BSP, Internet Archive, SourceForge, official/community/documentation sites via web-search
> APIs; evidence-based matching; verified downloads. Phase 6: Software & OS Analyzer (firmware, System
> Information OCR, operator entries, authorised read-only UPnP/ADB) and a documented-only Factory & Service
> Menu database with a safe change workflow. Modules for Phase 7 appear in the sidebar marked *P7*.

## Quick start (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```
OCR additionally needs the Tesseract binary (UB-Mannheim Windows build, auto-detected).
Full instructions, EXE build and optional tools: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md).

## What works now (Phases 1–6)

| Module | Function |
|---|---|
| Dashboard | Live counts (projects, identified/unknown TVs, library, analyzed, found, verified, upgrades) + recent scans |
| New TV Project | Register any TV — fields can be left empty when unknown; status `unknown / partial / identified` with capped manual confidence |
| TV Identification | Edit identification data; attach evidence images (stored read-only with SHA-256); **Run OCR** → candidates (manufacturer, model, serial, product code, chassis, mainboard, PCB rev., panel, firmware version, size, platform) with confidence + source line → accept/reject; status `verified` only when manufacturer + model are evidence-backed; catalog matching (works on mainboard/chassis for unknown TVs) |
| Visual Scanner | Crop by mouse, rotate, presets (label, chip marking, PCB silkscreen, screen menu, binarize), preview, save processed copy (original untouched), OCR with token boxes, image-quality warnings, chip/PCB marking recognition (44 numbering-convention rules) → confirm as hardware component |
| Hardware Analyzer | Components from confirmed markings or manual entry (board, position, quantity); analysis via marking rules, 10 memory part-number decoders, reference DB and local datasheet library (exact/family match, facts with page numbers, corroboration/contradiction warnings); every value shows source + confidence; board summary (RAM/flash totals only with complete evidence); reference DB grows from analysed TVs; Hardware Report PDF/XLSX/CSV/JSON |
| Firmware Analyzer | Hash-verified working copy + proof the original is unchanged; native scan with header validation (uImage CRC, SquashFS, ext2/3/4, JFFS2, UBI/UBIFS, CramFS, Android boot/sparse/vbmeta, GPT/MBR, DTB/FIT, ELF, zImage, gzip/xz/bzip2/LZMA/zstd, zip/7z/tar/cpio, PNG/JPEG); entropy map + encryption indicators; strings; kernel/arch/bootloader/OS/firmware-version facts with sources and conflict flags; safe extraction (traversal/symlink/bomb protection) via native code, 7-Zip, unsquashfs, jefferson, ubi_reader; config/sensitive file discovery; comparison; hex viewer/HxD; Binwalk (incl. WSL) and Ghidra headless; PDF/JSON report |
| Universal Firmware Finder | Offline-first; criteria loaded from project/hardware/analysed firmware (works for unknown models via mainboard/chassis/SoC); 8 providers (official sites, GitHub incl. releases/digests/code search, GitLab, open-source BSP, SourceForge, Internet Archive, community, technical docs) with rate limiting, retries, robots.txt, URL validation, de-duplication; verdicts VERIFIED/HIGH/POSSIBLE/INCOMPATIBLE/INSUFFICIENT with per-criterion evidence and risk; download manager with SHA-256 verification, quarantine and malware scan; search history; PDF/CSV/JSON reports; API keys in Windows Credential Manager |
| Software Analyzer | OS, OS version, kernel, build, firmware version, bootloader, applications, libraries, drivers, network interfaces, display/audio configuration — from analysed firmware, OS fingerprint rules, System Information photos (OCR), operator entries (reference required), and authorised read-only UPnP discovery / ADB (Android TV, whitelisted commands); every value with sources; conflict flags; OS Report PDF/JSON |
| Factory & Service Menu | Service-menu database (11 categories) where every record must cite official documentation; refusal of brute-force/bypass procedures; applicability by manufacturer/model pattern/chassis; JSON/CSV import-export; search of service manuals for service-mode passages with page numbers; factory-setting change workflow (plan → documented backup → typed confirmation → performed) with audit; Service Menu Report PDF |
| Firmware Library | Import BIN/IMG/ROM/PKG/ZIP/TAR/TGZ/GZ…; SHA-256; duplicate prevention; `Manufacturer/Model/{Original,Official,Community,Analyzed,Reports}` layout; read-only originals; integrity re-check; filter by mainboard; magic-byte format detection; provenance |
| Reports | TV Identification Report (PDF) with evidence, OCR results, candidates, markings, hardware, firmware and audit trail; Hardware Report (PDF, XLSX, CSV, JSON) |
| Settings | Paths, schema version, OCR engines + languages, detection of 7-Zip / Binwalk / Ghidra / HxD / Tesseract / WSL2 |

## Roadmap
| Phase | Scope |
|---|---|
| 1 ✅ | Core app, SQLite + migrations, projects, images, firmware storage, PDF report |
| 2 ✅ | OCR (Tesseract; PaddleOCR optional), OpenCV preprocessing, chip/PCB marking recognition, model catalog |
| 3 ✅ | Component database, part-number decoders, datasheet library & matching, hardware reports |
| 4 ✅ | Firmware analyzer: validated scan, entropy, strings, metadata, safe extraction, comparison, Binwalk, Ghidra |
| 5 ✅ | Universal Firmware Finder: providers, matching, verified downloads, history, reports |
| 6 ✅ | Software/OS analyzer, documented service-menu database, safe service-action workflow |
| 7 | Compatibility analyzer, upgrade profiles/adapters, backup, verification, recovery guidance |
| 8 | Full testing, installer, EXE, documentation, sample reports |

Design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Test results: [Phase 1](docs/TEST_REPORT_PHASE1.md), [Phase 2](docs/TEST_REPORT_PHASE2.md), [Phase 3](docs/TEST_REPORT_PHASE3.md), [Phase 4](docs/TEST_REPORT_PHASE4.md), [Phase 5](docs/TEST_REPORT_PHASE5.md), [Phase 6](docs/TEST_REPORT_PHASE6.md).
Module docs: [Visual Scanner / OCR](app/modules/visual_scanner/README.md), [Hardware Analyzer](app/modules/hardware_analyzer/README.md), [Firmware Analyzer](app/modules/firmware_analyzer/README.md), [Binwalk](app/integrations/binwalk/README.md), [Ghidra](app/integrations/ghidra/README.md), [Firmware Finder](app/modules/firmware_finder/README.md), [Software & Service Menu](app/modules/software_analyzer/README.md).

## Safety policy (summary)
* Original firmware is never modified; analysis uses isolated working copies.
* No result is invented: unknown values stay unknown; compatibility needs evidence.
* No automatic flashing, no signature bypass, no bootloader modification, no brute-force of service menus.
* Every significant action is written to an audit log.

## Development
```bash
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest      # Windows: run_tests.bat
python main.py --self-check                     # initialise storage, list tools, exit
```

Project layout follows the specification: `main.py`, `config/`, `app/{core,database,ui,modules,integrations,services,security}`,
`database/`, `resources/`, `storage/`, `plugins/`, `tests/`, `docs/`, `installer/`.
