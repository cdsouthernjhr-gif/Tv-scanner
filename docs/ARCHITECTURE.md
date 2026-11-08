# TV Intelligence Scanner — Technical Architecture

Version 0.6 (Phases 1–6 implemented). This document is the reference for all later phases.

## 1. Goals and non-negotiable principles

| Principle | How it is enforced |
|---|---|
| Offline-first | All data in a local SQLite DB + local file store. Network is only used by explicit search/download actions (Phase 5); `network.offline_mode` is `true` by default. |
| Originals are immutable | Sources are only opened `rb`. Library copies are SHA-256-verified after copy and marked read-only. Analysis runs on copies in `storage/workspace/` (`FirmwareLibrary.make_working_copy`). |
| Evidence over guessing | Every identification value records its source and confidence. Manual data is capped at 80 % and never marked `verified`. Weak magic numbers are not used for format claims. |
| No fabricated results | Search results must carry the real source URL and retrieval date; compatibility verdicts must list reasons; unknown = `INSUFFICIENT EVIDENCE`. |
| No unsafe flashing | Upgrade execution only through verified per-model profiles and official methods, with explicit confirmation and audit log. High-risk methods produce technician instructions only. |
| Full audit trail | `audit_log` table (append-only via `AuditLogger`) + rotating application log. |

## 2. Layered structure

```
┌──────────────────────────── UI (PySide6) ────────────────────────────┐
│ app/ui/main_window.py  – sidebar (14 modules) + QStackedWidget        │
│ app/ui/pages/*          – one page per module; thin, calls services   │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ AppContext (app/core/context.py)
┌───────────────────────────────▼──────────────────────────────────────┐
│ Services / Modules                                                    │
│  services/   project_service, evidence_service, dashboard_service,    │
│              external_tools                                           │
│  modules/    identification, visual_scanner, hardware_analyzer,       │
│              firmware_analyzer, firmware_finder, firmware_library,    │
│              software_analyzer, service_menu, compatibility,          │
│              upgrade_manager, reports                                 │
│  integrations/ github, manufacturer, community, binwalk, ghidra       │
├───────────────────────────────────────────────────────────────────────┤
│ security/   hashing, file_protection (read-only, path sanitising,     │
│             traversal guard), audit                                   │
├───────────────────────────────────────────────────────────────────────┤
│ database/   connection (SQLite, FK on, WAL), migrations_runner,       │
│             migrations/NNNN_*.sql                                     │
└───────────────────────────────────────────────────────────────────────┘
```

The UI never issues SQL; pages call services through `AppContext`. Every page
exposes programmatic methods (`register()`, `import_firmware()`, `generate()` …)
that the button handlers call, so the same paths are exercised by the tests.

## 3. Data storage layout

```
%LOCALAPPDATA%\TVIntelligenceScanner\         (override: --data-dir or TVIS_DATA_DIR)
├── settings.json                user overrides of config/default_config.json
├── database\tv_intelligence.sqlite3
├── TV_Firmware_Library\<Manufacturer>\<Model>\{Original,Official,Community,Analyzed,Reports}\
├── storage\projects\<id>\evidence\<sha256>.<ext>   (read-only copies)
├── storage\reports\<project_id>\*.pdf
├── storage\workspace\fw_<id>\    isolated working copies for analysis
└── logs\application.log          rotating, 5 x 5 MB
```

## 4. Database

SQLite with numbered SQL migrations (`app/database/migrations/NNNN_name.sql`).
`migrations_runner.apply_migrations` applies each pending file atomically, records it
in `schema_migrations`, and sets `PRAGMA user_version`. A failed migration is rolled
back completely. To change the schema: add `0002_xxx.sql` — never edit an applied file.

Tables (0001): all 22 tables from the specification plus `tv_projects`
(one physical TV under investigation, known or unknown) and `audit_log`.
Provenance for every firmware file: `firmware_sources` (origin, URL, access time,
reliability) ← `firmware_files` (sha256 UNIQUE, stored_path, imported/downloaded
time, verification_status) → `firmware_analysis` (analyzer, result JSON).

`verification_status` semantics:
* `unverified` – not checked.
* `hash_ok` – stored copy matches the SHA-256 recorded at import (integrity only).
* `hash_mismatch` – stored copy was altered/corrupted.
* `verified` – reserved for authenticity proven by vendor signature / official hash (Phase 5/7). Never set by import alone.

## 5. Module design for later phases

### Phase 2 — Identification & Visual Scanner (implemented)
* `modules/visual_scanner/preprocess.py` — OpenCV pipeline + presets per evidence type; quality report.
* `modules/visual_scanner/ocr.py` — `OcrEngine` interface; `TesseractEngine`, optional `PaddleOcrEngine`.
* `modules/visual_scanner/markings.py` — chip/PCB marking rules (`resources/data/marking_rules.json`) with OCR-confusion repair.
* `modules/identification/parsers.py` — keyed/brand/platform/size extraction (`resources/data/tv_brands.json`).
* `modules/identification/service.py` — multi-variant OCR, `ocr_results`, `identification_candidates`, `marking_detections`; accept/reject; confirm → `hardware_components`.
* `modules/identification/catalog.py` — catalog built only from confirmed TVs; OCR-tolerant matching.
* Migration `0002`: `ocr_results`, `identification_candidates`, `marking_detections`, `scan_evidence.parent_evidence_id/processing_json`, `tv_projects.panel_model`.
* Identification status: `unknown → partial → identified → verified`; `verified` needs manufacturer + model backed by accepted image evidence. Source: `manual / evidence / mixed`.
See `app/modules/visual_scanner/README.md` for confidence formulas.

### Phase 3 — Hardware Analyzer (implemented)
* `modules/hardware_analyzer/decoders.py` — memory part-number decoders (`resources/data/part_decoders.json`).
* `modules/hardware_analyzer/datasheets.py` — datasheet library (read-only PDFs, pypdf text per page, part index, exact/family match, fact extraction with page refs).
* `modules/hardware_analyzer/service.py` — analysis pipeline (sanity check → marking rule → decoder → reference DB → datasheet → corroboration), board summary, reference DB.
* `modules/reports/hardware_report.py` — Hardware/Motherboard/Chipset report (PDF) + CSV/JSON/XLSX.
* `ui/worker.py` — QThreadPool worker; OCR, datasheet import and bulk analysis run off the UI thread.
* Migration `0003`: `datasheets`, `datasheet_pages`, `datasheet_parts`, `component_specs` (one row per fact with source + confidence), extra `hardware_components` columns.
See `app/modules/hardware_analyzer/README.md` for evidence levels and summary rules.

### Phase 4 — Firmware Analyzer (implemented)
* `modules/firmware_analyzer/scanner.py` — validated deep signature scan (mmap), nesting, gaps.
* `entropy.py`, `strings_analysis.py`, `metadata.py` (facts with provenance, merge + conflict), `extractor.py` (safe extraction), `config_discovery.py`, `compare.py`, `hexview.py`, `service.py` (run orchestration, integrity before/after).
* `integrations/binwalk/adapter.py` (v2/v3, WSL), `integrations/ghidra/adapter.py` + `scripts/TVISSummary.java`.
* `modules/reports/firmware_report.py` — PDF (structure/entropy drawing) + JSON.
* Migration `0004`: `firmware_analysis_runs`, `firmware_components`, `firmware_metadata`, `firmware_extracted_files`, `firmware_analysis.run_id`.
See `app/modules/firmware_analyzer/README.md`.

### Phase 5 — Universal Firmware Finder (implemented)
* `modules/firmware_finder/` — `criteria.py`, `http.py`, `providers/` (GitHub, open-source, GitLab, Internet Archive, web-search backends Google CSE/Brave/SearXNG with official/community/documentation/SourceForge providers), `matching.py`, `engine.py`.
* `security/secrets.py` (keyring → Windows Credential Manager), `security/malware_scan.py` (Defender/ClamAV).
* `modules/reports/search_report.py` — Firmware Search Report PDF/CSV/JSON.
* Migration `0005`: `search_sessions`, extended `firmware_search_results`, `firmware_downloads`.
See `app/modules/firmware_finder/README.md` for verdict rules and access policy.

### Phase 6 — Software & Service Menu (implemented)
* `modules/software_analyzer/` — `inventory.py` (apps, libraries, drivers, configs, OS fingerprint rules in `resources/data/os_fingerprints.json`), `connectors.py` (UPnP/SSDP LAN discovery, ADB read-only whitelist), `service.py` (facts with provenance, summary, conflicts).
* `modules/service_menu/service.py` — documented-only service-menu DB, import/export, service-manual passage search, service-action workflow.
* `modules/reports/software_report.py` — Operating System Report, Service Menu Report.
* Migration `0006`: `software_facts`, `device_sessions`, extended `service_menus`, `service_actions`.
See `app/modules/software_analyzer/README.md`.

### Phase 7 — Compatibility & Upgrade Manager
* `CompatibilityAnalyzer.evaluate(project, firmware) -> Verdict(reasons[])`: each criterion (SoC, board, PCB rev, panel, RAM, flash, partition layout, bootloader, signature) → `match/mismatch/unknown` with evidence; any hard mismatch ⇒ `INCOMPATIBLE`; critical unknowns ⇒ `INSUFFICIENT EVIDENCE`.
* Upgrade adapters (`plugins/upgrade/*`) implement `UpgradeMethod` (`supports(profile)`, `preflight()`, `prepare()`, `execute(progress_cb)`, `verify()`). The first adapter is *Official USB Upgrade* which only **prepares** a USB stick (copies the validated vendor package to the documented path, checks FAT32/capacity) — the TV performs the flash itself. Methods without a verified profile are refused; UART/recovery produce technician reports only.
* Every step writes to `firmware_upgrade_sessions.log` and `audit_log`.

### Reports (Phase 1 → 8)
`PdfReportGenerator` (Phase 1: TV Identification). Later: hardware, firmware, OS, service
menu, search, compatibility, upgrade reports, and XLSX (openpyxl), CSV, JSON, HTML exporters
sharing one report data model.

## 6. External tools
Detected at runtime (`services/external_tools.py`) from PATH, known install folders, or
`settings.json → tools`. Missing tools disable the dependent features with a clear message;
nothing is downloaded or installed automatically.

## 7. Testing strategy
* Unit + integration tests per module (`tests/`), headless Qt via `pytest-qt` (`QT_QPA_PLATFORM=offscreen`).
* Every phase ships a test report in `docs/` with PASS / FAIL / NOT TESTED per acceptance item.
