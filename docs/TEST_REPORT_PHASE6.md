# Test Report — Phase 6 (Software & OS Analyzer, Factory & Service Menu)

* Date: 2026-11-08 · Build 0.6.0 · database schema v6 (migration `0006_software_service.sql`)
* Environment: Linux container, Python 3.13, PySide6 offscreen. No real TV or LAN devices available.
* **Not executed on Windows 10/11.**

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **238 passed, 0 failed, 0 skipped**
(223 from Phases 1–5 + 15 new: 12 module tests, 2 UI tests, 1 regression test for a Phase 5 bug).

## Module F — Software & OS Analyzer

| Item | Result | Evidence |
|---|---|---|
| OS identification (firmware metadata + fingerprint rules) | PASS | `test_software_analysis_end_to_end`, `test_fingerprint_rules` |
| Android TV / Tizen / webOS / generic Linux indicators; keyword-only stays weak | PASS | `test_fingerprint_rules` |
| Kernel, build, firmware version, bootloader | PASS | end-to-end test (firmware + System Information photo + operator) |
| Installed applications (Android APK, Tizen, webOS appinfo.json) | PASS | `test_inventory_extracts_apps_libs_drivers_configs` |
| System libraries with version from file name | PASS | same |
| Hardware drivers (kernel modules, name-based class, no substring false positives) | PASS | same |
| Network interfaces / display / audio configuration | PASS | same |
| System information menu (OCR) as a source | PASS | end-to-end test |
| Operator entries require a reference; kept on re-analysis | PASS | end-to-end test |
| Conflicting OS evidence flagged | PASS | end-to-end test |
| UPnP/SSDP discovery, LAN-only, host-mismatch rejection, description parsing | PASS | fake socket + real local HTTP server |
| ADB read-only whitelist, LAN-only targets, unauthorised device detected | PASS | stand-in `adb` (POSIX) |
| Authorisation statement required for device queries | PASS | `test_upnp_discover_and_link` |
| Real TV over UPnP / ADB | NOT TESTED | no device in the test environment |
| Operating System Report PDF/JSON | PASS | `test_os_and_service_reports` |
| UI | PASS | `test_software_page` |

## Module G — Factory & Service Menu

| Item | Result | Evidence |
|---|---|---|
| Record fields per spec (manufacturer, model, chassis, platform, firmware, category, documentation, function, availability, risk) | PASS | validation and CRUD tests |
| Official documentation mandatory | PASS | `test_service_menu_validation`, UI test |
| Brute force / password guessing / bypass descriptions refused | PASS | `test_service_menu_validation` |
| Applicability by manufacturer, model glob, chassis | PASS | `test_service_menu_applicable_and_import_export` |
| Import/export JSON & CSV with per-record rejection | PASS | same |
| Service-manual passage search with page numbers; citation from document library | PASS | `test_service_manual_passages_and_document_link` |
| Factory-setting change: backup enforced, typed confirmation, performed only after confirmation, audit log | PASS | `test_service_action_workflow` |
| Service Menu Report PDF | PASS | `test_os_and_service_reports` |
| UI | PASS | `test_service_menu_page` |
| Content of the database | — | ships empty by design: records must come from manufacturer documentation |

## Bugs found and fixed during Phase 6
1. **Phase 5 bug found by a live test**: GitLab answered 429 with a long `Retry-After`, and the HTTP client waited
   without any cap, so a search could hang for minutes. Waits are now capped (`network.max_retry_wait_seconds`,
   default 30 s); longer requests are reported as "rate limited; retry after N s". A regression test was added.
2. When both `libssl.so` and `libssl.so.1.1` existed, the library version was lost. The versioned name now wins.
3. The tab label "TV project & service actions" lost its "&" (Qt shortcut marker). It is now escaped.

## Known open issues
1. OS fingerprint rules for VIDAA and Roku are keyword-only (no documented file-system markers in the rules); they
   stay weak indicators.
2. The ADB tests use a POSIX stand-in script and are skipped on Windows; real ADB requires Android platform-tools.
3. UPnP discovery depends on the TV answering SSDP and on the Windows firewall allowing UDP 1900 responses.
