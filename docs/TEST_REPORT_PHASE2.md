# Test Report — Phase 2 (TV Identification & Visual Scanner)

* Date: 2026-11-08 · Build 0.2.0 · database schema v2 (migration `0002_visual_scanner_ocr.sql`)
* Environment: Linux x86-64 container, Python 3.13, PySide6 6.12 (offscreen), OpenCV 5.0 (headless),
  Tesseract 5.3.4 (`eng`), pytest 9 + pytest-qt.
* **Not executed on a physical Windows 10/11 machine.**

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **102 passed, 0 failed, 0 skipped**
(36 Phase 1 + 66 Phase 2). OCR integration tests skip automatically when Tesseract is missing;
in this run they all executed.

## Test images
No real product photos are bundled. `tests/synthetic_images.py` renders photos with the problems
real ones have: rotation, sensor noise, blur, low-contrast light-on-dark chip text, white
silkscreen on green PCB, dark on-screen menus. Model/part strings are illustrative only.

## Phase 2 deliverables

| Item | Result | Evidence |
|---|---|---|
| OCR works (Tesseract) | **PASS** | `test_ocr_integration.py`: rear label, chip marking, system menu, PCB silkscreen |
| Image processing (crop, rotate, deskew, enhance, presets) | PASS | `test_preprocess.py` (deskew error < 0.6° for ±4°, 8°) |
| Unicode file paths (Windows) | PASS | `test_unicode_path_roundtrip` |
| Image quality warnings (blur, low resolution, dark) | PASS | `test_quality_report_flags_blur_and_resolution` |
| Chip marking recognition | PASS | 14 rule cases incl. O/0, S/5, B/8 corrections; light-on-dark OCR test |
| PCB number recognition | PASS | BN41, TP.*, 17MB rules; real OCR of silkscreen |
| No false rule matches on noise/date codes | PASS | `test_marking_no_false_rule`, `test_detect_joins_split_tokens_and_filters_noise` |
| Label/menu field extraction with confidence + source line | PASS | `test_parsers_markings.py` |
| No size guessed from model digits | PASS | `test_size_only_from_explicit_text` |
| Candidates require operator decision | PASS | `test_run_ocr_stores_results_and_candidates` |
| `verified` only from evidence (not manual, not catalog) | PASS | `test_accept_reject_and_verified_status`, `test_catalog_match_is_not_physical_evidence` |
| Confirmed marking → hardware component with evidence link | PASS | `test_markings_confirm_creates_hardware_component` |
| Processed copies never alter originals | PASS | `test_save_processed_keeps_original` |
| Database matching (catalog, OCR-tolerant, mainboard-only for unknown TV) | PASS | `test_catalog_save_and_match` |
| Visual Scanner UI (crop, preview, save, OCR, confirm) | PASS | `test_ui.py` Phase 2 tests |
| Identification UI (OCR → accept → verified → catalog) | PASS | `test_identification_ocr_accept_to_verified` |
| PDF report includes OCR, candidates, markings, hardware | PASS | `test_report_with_ocr_data` |
| PyInstaller build bundles rules/migrations | PASS (Linux) | frozen `--self-check`: schema v2, 44 rules, 46 brands, Tesseract found |
| PaddleOCR engine | NOT TESTED | adapter implemented; package not installed (≈1 GB) |
| OCR accuracy on real photos | NOT TESTED | requires real TV label/board photos |
| Application on Windows 10/11 | NOT TESTED | |

## Observations from real OCR runs
* Label: brand, full model, size and serial were read; the serial's first character was read as
  `O` instead of `0`. OCR cannot separate these reliably, so both readings stay visible and the
  operator decides. Lower-confidence alternative readings (e.g. `YA5S5AU7000KXXM`) are listed below the
  best reading.
* PCB: `W25Q64JV` was read as `W25Q64)V` in one variant. The Winbond rule still matched, and the
  operator can type the corrected part number when confirming.
* Bug found and fixed while testing: deskew rotated the wrong way and doubled the skew. It is now
  covered by `test_deskew_corrects_rotation`.
* Fixed: OpenCV 5 changed the `HoughLinesP` output shape; the code now handles both.

## Known open issues
1. Accuracy is validated on synthetic images only; the Tesseract defaults may need tuning on real
   photos (glossy labels, curved chip packages).
2. OCR runs on the UI thread (wait cursor, usually 1–3 s per image). A background worker is planned
   for Phase 3, when more image-heavy work arrives.
3. The catalog starts empty by design and grows only from TVs you confirm and save.
4. The marking rules name vendor families only. Datasheet lookup and specifications come in Phase 3.
