# Hardware Analyzer (Phase 3)

## Components
| File | Purpose |
|---|---|
| `decoders.py` + `resources/data/part_decoders.json` | Memory part-number decoders (Samsung, SK hynix, Micron, Nanya DRAM; Winbond, GigaDevice, Macronix SPI flash; Samsung eMMC). |
| `datasheets.py` | Local datasheet library: PDF import (read-only, SHA-256, dedupe), per-page text (pypdf), part-number index, exact/family matching, specification fact extraction with page numbers. |
| `service.py` | `HardwareAnalyzer`: component CRUD, analysis, board summary, reference database. |
| `../reports/hardware_report.py` | Hardware Report PDF (board summary, components, facts, warnings, evidence images) + CSV / JSON / XLSX exports. |

## Where components come from
1. **Visual Scanner → Confirm marking** (Phase 2): the component gets the evidence image, the
   normalised category (SoC, RAM, flash, Wi-Fi, …) and the board the photo shows.
2. **Manual entry** on the Hardware Analyzer page (confidence starts at 50 %, 60 % with an image).

## Analysis steps and evidence levels
1. Part-number sanity check: characters that never occur in part numbers (`)`, `|`, …) mean an
   OCR misread → nothing is derived; the operator must correct the part number. LG-style
   `(1.0)` revision suffixes are allowed.
2. Marking rule (Phase 2 rules) → vendor and device family only → `vendor_only`.
3. Decoder → memory type, density, organisation (full-pattern match only) → `decoded`.
4. Reference database → facts saved earlier for the same part, with the original source kept
   (`reference DB memory #3 ← datasheet #1 p.2`).
5. Datasheet library → `datasheet_exact` when the datasheet lists this exact part number,
   `datasheet_family` when it lists the same base part (e.g. W25Q64JV**SSIQ** vs W25Q64JV**ZPIQ**);
   family facts are down-weighted ×0.7 and a warning tells the operator to check the suffix.
6. Cross-check: a decoder value stated in the datasheet is marked *corroborated* (90 % for
   exact, 85 % for family); a value the datasheet does not state produces a warning.

| match_status | Identification confidence |
|---|---|
| datasheet_exact | ≥ 90 % |
| datasheet_family / decoded | ≥ 75 % |
| vendor_only | unchanged (marking/manual confidence) |
| unidentified | ≤ 40 % |

## Board summary rules
* SoC, GPU, Wi-Fi, Bluetooth, audio, T-Con, PSU, panel: listed only if a component exists;
  otherwise "not identified (no evidence)". A GPU is never assumed to be "integrated".
* RAM / flash totals are computed **only when every chip** of the class has a capacity fact;
  otherwise "total not determined — N of M chip(s) have no capacity evidence".
* The total says which sources it rests on and adds "confirm with datasheet" when any value is
  decoder-only.

## Reference database
"Save to reference DB" stores the component in `chipsets`, `memory_chips` or `display_panels`
with all its facts (`component_specs`, owner = reference row). The `capacity_bytes` column is set
only from *proven* values: a decoder value corroborated by a datasheet, an operator value with a
reference, or a datasheet that states exactly one capacity. Decoder-only values remain facts.

## Datasheets
* Never downloaded automatically. Import PDFs you obtained from the manufacturer and record the
  source URL; "Search datasheet in browser" only opens a web search in your own browser.
* Fact extraction is pattern-based: memory type, density (`Gb`/`Gbit` = bits, `GB` = bytes),
  capacity, supply voltage, data rate, clock, package, temperature range, interfaces. Each fact
  records `datasheet #id p.N`.
* Scanned (image-only) PDFs have no text layer → no facts; OCR of datasheets is not implemented.

## Extending
* New decoder: add an entry to `part_decoders.json` (named groups `fam`, `dens`, `depth`/`width`,
  `mbit`, `gbit`, `org`, `emmc`) and a parametrised case in `tests/test_hardware.py`.
  Only add schemes the vendor documents publicly; keep confidence ≤ 0.8.
