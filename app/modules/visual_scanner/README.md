# Visual Scanner & OCR integration (Phase 2)

## Components
| File | Purpose |
|---|---|
| `preprocess.py` | OpenCV operations (crop, rotate, deskew, CLAHE, denoise, sharpen, thresholds, polarity) and presets per evidence type. Unicode-safe image I/O for Windows paths. Image quality report (blur, exposure, resolution). |
| `ocr.py` | `OcrEngine` interface; `TesseractEngine` (pytesseract, word confidences + boxes); optional `PaddleOcrEngine`. |
| `markings.py` | Chip-marking / PCB-number recognition from OCR tokens using `resources/data/marking_rules.json`. |
| `../identification/parsers.py` | Extracts model, serial, product code, chassis, mainboard, PCB rev., panel, firmware version, size, brand, platform from OCR text (`resources/data/tv_brands.json`). |
| `../identification/service.py` | Orchestration: multi-variant OCR, storage, candidate review, marking confirmation. |
| `../identification/catalog.py` | Local model catalog (built only from confirmed TVs) and OCR-tolerant matching. |

## OCR engines
* **Tesseract** (required for OCR). Windows: install the UB-Mannheim build to
  `C:\Program Files\Tesseract-OCR` (auto-detected) or set `tools.tesseract` in `settings.json`.
  Languages: `eng` is enough for labels; add others via the installer.
* **PaddleOCR** (optional): `pip install paddleocr paddlepaddle`. Detected automatically and
  selectable in the Visual Scanner. Not tested in this release.

## How a reading becomes data
1. OCR runs on a *processed copy in memory*; the stored evidence file is never modified.
   "Save processed copy" stores the result as a new evidence row linked by `parent_evidence_id`
   with the exact processing steps in `processing_json`.
2. In auto mode up to 5 preprocessing/layout variants are tried. Every trial is stored in
   `ocr_results`; candidates are collected across trials (a code split by one variant is often
   whole in another) and a value that is a strict prefix of a longer value for the same field is dropped.
3. Candidates and markings are **pending** until the operator accepts/confirms them.
   * accepted candidate → written to the project, counted as evidence-backed;
   * confirmed marking → `hardware_components` row with `verified_by_user=1`.
4. Status `verified` requires manufacturer **and** model to be evidence-backed. Values copied from
   the catalog are not evidence of the physical TV and never produce `verified`.

## Confidence
`candidate confidence = method weight × OCR line confidence`

| Method | Weight | Meaning |
|---|---|---|
| `label_key` | 0.95 | value follows an explicit key ("MODEL:", "S/N", "Software Version") |
| `brand_dictionary` | 0.85 | known brand as a whole word |
| `size_pattern` | 0.75 | explicit `55"`, `55 inch`, `Screen size: 55` |
| `platform_keyword` | 0.65 | "Android TV", "Tizen", "webOS", "VIDAA", ... appears |
| `generic_key` | 0.55 | ambiguous key ("Version:", "REV") |
| `pcb_rule:<id>` | rule strength | PCB number convention (see rules file) |
| `catalog_match` | 0.9 × match score | from the local catalog, not from this TV |

The same value found in several images: `1 − Π(1 − pᵢ)`, capped at 99 %.
Marking confidence = token confidence × rule strength (× 0.85 when an OCR character correction such
as O→0 was needed).

## What is deliberately NOT done
* Screen size is never derived from digits inside a model number (conventions differ per brand).
* Memory capacity / chip specification is never inferred from a marking — Phase 3 does that only
  with a datasheet reference.
* Unrecognised part-number-like strings on chip photos are kept (low confidence, "verify manually")
  rather than guessed or dropped. Date codes (`2219B`), voltages, frequencies are ignored.

## Extending
* Brands / platform keywords: edit `resources/data/tv_brands.json`.
* Marking rules: add to `resources/data/marking_rules.json` (`pattern`, `vendor`, `type`,
  `strength`, optional `note`). Rules are evaluated in order: put specific rules first.
  Add a parametrised case in `tests/test_parsers_markings.py` for every new rule.
* New OCR engine: subclass `OcrEngine`, register it in `IdentificationService.engines()`.
