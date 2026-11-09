# Changelog

## 1.0.1
* Fixed: ADB over the network did not run `adb connect` first, so collecting from an Android TV by IP address failed.
* adb is also found in the usual Windows Platform-Tools folders; clearer message when it is missing.
* User guide: step-by-step TV connection section (UPnP and ADB).

## 1.0.0 — 2026-11-08 (Phase 8: final integration & release)
* Report Center: all 10 technical reports in PDF, XLSX, CSV, JSON and HTML; Motherboard and Chipset reports.
* Windows CI (GitHub Actions, windows-latest): tests, self-check, native GUI smoke test, EXE build, Inno Setup
  installer, silent install / run / uninstall.
* Inno Setup installer script; `main.py --smoke-test`; user guide (Bahasa Melayu); sample reports; acceptance test report.
* Fixes found by the end-to-end scenario: Finder downloads kept a temporary file name (would break documented
  package names on upgrade USB sticks); "Verified Firmware" status was never set.

## 0.7.0 — Phase 7: Compatibility Analyzer & Firmware Upgrade Manager
## 0.6.0 — Phase 6: Software & OS Analyzer, Factory & Service Menu
## 0.5.0 — Phase 5: Universal Firmware Finder
## 0.4.0 — Phase 4: Firmware Analyzer
## 0.3.0 — Phase 3: Hardware Analyzer
## 0.2.0 — Phase 2: TV Identification & Visual Scanner (OCR)
## 0.1.0 — Phase 1: Core application

Details of each phase, including the bugs found and fixed during testing: `docs/TEST_REPORT_PHASE1.md` … `PHASE7.md`.
