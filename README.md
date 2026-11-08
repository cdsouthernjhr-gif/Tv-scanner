# TV Intelligence Scanner

Universal TV hardware, firmware, software and firmware-upgrade analysis platform
for Windows 10/11 (64-bit). Offline-first desktop application (Python 3 + PySide6 + SQLite).

> **Status: Phase 2 of 8 complete.** Phase 1 delivered the core application, database,
> project registration (including unknown TVs), evidence images, the immutable firmware library
> and the PDF report. Phase 2 adds OCR (Tesseract), OpenCV image processing, extraction of
> identification data from labels and menus, chip-marking and PCB-number recognition, and a
> local model catalog with matching. Modules for later phases appear in the sidebar marked
> *P3…P7* and say clearly that they are not implemented yet.

## Quick start (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```
OCR additionally needs the Tesseract binary (UB-Mannheim Windows build, auto-detected).
Full instructions, EXE build and optional tools: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md).

## What works now (Phases 1–2)

| Module | Function |
|---|---|
| Dashboard | Live counts (projects, identified/unknown TVs, library, analyzed, found, verified, upgrades) + recent scans |
| New TV Project | Register any TV — fields can be left empty when unknown; status `unknown / partial / identified` with capped manual confidence |
| TV Identification | Edit identification data; attach evidence images (stored read-only with SHA-256); **Run OCR** → candidates (manufacturer, model, serial, product code, chassis, mainboard, PCB rev., panel, firmware version, size, platform) with confidence + source line → accept/reject; status `verified` only when manufacturer + model are evidence-backed; catalog matching (works on mainboard/chassis for unknown TVs) |
| Visual Scanner | Crop by mouse, rotate, presets (label, chip marking, PCB silkscreen, screen menu, binarize), preview, save processed copy (original untouched), OCR with token boxes, image-quality warnings, chip/PCB marking recognition (44 numbering-convention rules) → confirm as hardware component |
| Firmware Library | Import BIN/IMG/ROM/PKG/ZIP/TAR/TGZ/GZ…; SHA-256; duplicate prevention; `Manufacturer/Model/{Original,Official,Community,Analyzed,Reports}` layout; read-only originals; integrity re-check; filter by mainboard; magic-byte format detection; provenance |
| Reports | TV Identification Report (PDF) with evidence images, hashes, OCR results, candidates, markings, confirmed hardware, firmware list and audit trail |
| Settings | Paths, schema version, OCR engines + languages, detection of 7-Zip / Binwalk / Ghidra / HxD / Tesseract / WSL2 |

## Roadmap
| Phase | Scope |
|---|---|
| 1 ✅ | Core app, SQLite + migrations, projects, images, firmware storage, PDF report |
| 2 ✅ | OCR (Tesseract; PaddleOCR optional), OpenCV preprocessing, chip/PCB marking recognition, model catalog |
| 3 | Component database, datasheet matching, hardware reports |
| 4 | Binwalk, Ghidra, filesystem/kernel/arch detection, metadata, comparison |
| 5 | Universal Firmware Finder (official, GitHub, GitLab, docs, archive, community providers) |
| 6 | Software/OS analyzer, documented service-menu database |
| 7 | Compatibility analyzer, upgrade profiles/adapters, backup, verification, recovery guidance |
| 8 | Full testing, installer, EXE, documentation, sample reports |

Design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Test results: [Phase 1](docs/TEST_REPORT_PHASE1.md), [Phase 2](docs/TEST_REPORT_PHASE2.md).
OCR/visual scanner details: [app/modules/visual_scanner/README.md](app/modules/visual_scanner/README.md).

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
