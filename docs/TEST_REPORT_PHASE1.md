# Test Report — Phase 1 (Core Windows Application)

* Date: 2026-11-08
* Build: 0.1.0, database schema v1
* Test environment: Linux x86-64 container, Python 3.13, PySide6 6.12 (Qt offscreen platform), pytest 9 + pytest-qt.
* **Not executed on a physical Windows 10/11 machine** — see "NOT TESTED" items.

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **36 passed, 0 failed**.

## Acceptance test matrix (specification §16)

| # | Acceptance item | Result | Evidence |
|---|---|---|---|
| 1 | Application opens on Windows | **NOT TESTED** | Main window builds and all 14 pages navigate headless (`test_main_window_navigation`). PyInstaller build + `--self-check` of the frozen binary succeeded on Linux. Needs a run on Windows. |
| 2 | TV project can be registered | PASS | `test_register_unknown_tv`, `test_register_identified_tv_capped_confidence`, `test_end_to_end_workflow` |
| 3 | Images can be added | PASS | `test_add_evidence_image`, `test_evidence_rejects_bad_input`, UI workflow test |
| 4 | OCR works | NOT TESTED | Phase 2 scope; not implemented |
| 5 | Firmware can be imported | PASS | `test_import_preserves_original_and_layout`, `test_duplicate_detection` |
| 6 | Hash can be computed | PASS | `test_sha256_known_vector` (NIST "abc" vector) |
| 7 | Firmware Analyzer detects supported formats | PASS (partial) | Magic-byte detection for ZIP, GZIP, TAR, uImage, Android boot, SquashFS, ELF, ext4 (`test_signature_detection`). Deep analysis (Binwalk) is Phase 4. |
| 8 | Universal Firmware Finder performs real search | NOT TESTED | Phase 5 scope |
| 9 | GitHub search returns real results | NOT TESTED | Phase 5 scope |
| 10 | Firmware results have sources | PASS (local import) | Every import creates a `firmware_sources` row with origin + access time. Online sources: Phase 5. |
| 11 | Compatibility Analyzer gives evidence-based verdict | NOT TESTED | Phase 7 scope |
| 12 | Upgrade Manager identifies supported methods | NOT TESTED | Phase 7 scope (schema + allowed methods defined) |
| 13 | Upgrade only via verified profile | NOT TESTED | Phase 7 scope |
| 14 | PDF report can be generated | PASS | `test_pdf_identification_report`, `test_pdf_report_unknown_tv_without_evidence` |
| 15 | Database can be reopened | PASS | `test_migrations_idempotent_and_reopen`; self-check run twice on same data dir |
| 16 | Original firmware unchanged after processing | PASS | byte-for-byte + mtime comparison in `test_import_preserves_original_and_layout`; `test_working_copy_isolated` |

## Additional checks

| Check | Result |
|---|---|
| All 22 specification tables + `tv_projects`, `audit_log` created | PASS |
| Migration runner: incremental, idempotent, atomic rollback on error | PASS |
| Library copies read-only, tampering detected by integrity check | PASS |
| Windows-unsafe names (`<>:"/\|?*`, `CON`, `..`) sanitised; path traversal blocked | PASS |
| Manual identification confidence capped at 80 %, never "verified" | PASS |
| Importing firmware never sets "verified" | PASS |
| Audit log entries for project/evidence/firmware/report actions | PASS |
| Visual inspection of Dashboard / TV Identification pages (offscreen screenshot) | PASS |

## Known open issues
1. Not yet run on real Windows 10/11 hardware (items marked NOT TESTED #1).
2. Pages for Phases 2–7 are explicit "not implemented" pages — they produce no results.
3. PyInstaller output is a folder distribution; an MSI/Inno Setup installer is Phase 8.
4. Secure API-key storage (Windows Credential Manager via `keyring`) is Phase 5; no keys are stored in Phase 1.
