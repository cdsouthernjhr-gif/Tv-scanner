# Test Report — Phase 3 (Hardware Analyzer)

* Date: 2026-11-08 · Build 0.3.0 · database schema v3 (migration `0003_hardware_analyzer.sql`)
* Environment: Linux x86-64 container, Python 3.13, PySide6 6.12 (offscreen), OpenCV 5.0, Tesseract 5.3.4,
  pypdf 6.17, ReportLab, openpyxl, pytest 9 + pytest-qt.
* **Not executed on a physical Windows 10/11 machine.**

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **156 passed, 0 failed, 0 skipped**
(102 from Phases 1–2 + 54 new).

Datasheets used in tests are generated PDFs marked "SYNTHETIC TEST DOCUMENT" (`tests/synthetic_datasheets.py`);
no vendor documents are bundled.

## Phase 3 deliverables

| Item | Result | Evidence |
|---|---|---|
| Component database (reference DB: chipsets, memory, panels + facts with provenance) | PASS | `test_reference_db_roundtrip`, `test_reference_capacity_not_set_from_decoder_only` |
| Memory part-number decoding (10 decoders, 12 vendor cases + eMMC) | PASS | `test_decoders`, `test_emmc_capacity_in_bytes` |
| No decoding of partial / unknown / OCR-misread part numbers | PASS | `test_no_decode_without_full_match`, `test_ocr_misread_part_not_decoded` |
| Datasheet library (read-only copy, SHA-256, dedupe, PDF check, text index) | PASS | `test_datasheet_import_index_find`, `test_datasheet_rejects_non_pdf` |
| Datasheet matching exact vs family | PASS | same + `test_analyze_family_match_warns_and_reduces` |
| Spec fact extraction with page reference; bits vs bytes | PASS | `test_extract_facts_units_and_pages` |
| Decoder ↔ datasheet corroboration and contradiction warning | PASS | `test_analyze_exact_datasheet_corroborates_decoder`, `test_contradiction_reported` |
| Each result has name, manufacturer, part no., spec, evidence image, confidence, source | PASS | analyzer tests + `test_hardware_reports_all_formats` |
| Board totals only with complete evidence | PASS | `test_board_summary_totals_only_with_full_evidence`, `test_proven_capacity_rules` |
| Visual Scanner → confirmed marking → analysed component | PASS | `test_confirmed_marking_feeds_analyzer` |
| Operator-entered facts require a reference and survive re-analysis | PASS | `test_reanalyze_keeps_user_facts` |
| Hardware Report PDF + CSV + JSON + XLSX | PASS | `test_hardware_reports_all_formats` (PDF text verified with pypdf) |
| Hardware Analyzer UI | PASS | `test_hardware_page_workflow` |
| Background worker (OCR no longer blocks the UI) | PASS | `test_background_worker`, `test_visual_scanner_async_ocr` |
| Upgrade of Phase 2 database (v2 → v3) | PASS | manual run on a Phase 2 data directory |
| PyInstaller build bundles decoders + pypdf | PASS (Linux) | frozen `--self-check`: schema v3, 10 decoders |
| Real vendor datasheets | NOT TESTED | no vendor PDFs bundled; layout of real datasheets may yield fewer facts |
| Scanned (image-only) datasheets | NOT SUPPORTED | no text layer; documented |
| Online datasheet lookup | NOT IMPLEMENTED | only "search in browser"; automated sources come with Phase 5 providers |
| Application on Windows 10/11 | NOT TESTED | |

## Bugs found and fixed during Phase 3 testing
1. `canonical()` folds OCR-confusable letters (Q→0, S→5) and broke the base-family regex. Family
   extraction now runs on the plain part number and is folded afterwards.
2. `W25Q64)V` passed the sanity check because `(` `)` were allowed for LG revisions. Now only a
   trailing `(n.n)` is allowed.
3. Memory types `DDR3 SDRAM` vs `DDR3` were reported as contradictory. They are now compared in
   normalised form.
4. Case-insensitive density matching would read "8GB" (bytes) as 8 Gbit. Bits and bytes are now
   parsed separately.
5. The reference DB never stored a capacity proven by datasheet + decoder corroboration. Fixed with
   explicit "proven capacity" rules.

## Known open issues
1. Fact extraction is pattern-based. A datasheet that covers many variants produces several values
   per attribute (up to 3 are kept, each with its page); the operator decides.
2. Micron FBGA codes (5-character package markings) are not decoded; the analyser warns about this.
3. Marking rules and decoders cover common TV parts only; extend the JSON files as needed.
