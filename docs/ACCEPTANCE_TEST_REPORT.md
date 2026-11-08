# Final Acceptance Test Report — TV Intelligence Scanner 1.0.0

* Date: 2026-11-08 · Version 1.0.0 · database schema v7
* Test environments
  1. **Windows** — GitHub Actions `windows-latest` (Windows Server, 64-bit), Python 3.12, PySide6 6.12, Tesseract
     5.5.3 (Chocolatey), 7-Zip. Workflow: `.github/workflows/windows-build.yml`, run
     [#3](https://github.com/cdsouthernjhr-gif/Tv-scanner/actions/runs/42529111075) on commit `dbd1e90`: **success**.
  2. **Linux** development container — Python 3.13 (code base also compiled with Python 3.11: 0 syntax errors),
     Tesseract 5.3.4, Binwalk 2.3.3, squashfs-tools, e2fsprogs, mtd-utils, jefferson, ubi_reader, 7-Zip; live access to
     api.github.com and gitlab.com.
* Automated tests: **315** (unit, integration, UI, end-to-end).
  * Linux: **315 passed**, 0 failed, 0 skipped.
  * Windows: **308 passed, 0 failed, 7 skipped**. Skipped: tests that need Linux filesystem tools or Binwalk (2),
    tests that use POSIX stand-in scripts for ClamAV/ADB (3), and live-network tests deliberately disabled in CI (2).
* Test data is synthetic (generated firmware images using real formats and CRCs, generated photos, datasheets and
  service manuals, and recorded API responses), except for the live GitHub/GitLab searches. **No real TV, vendor
  firmware, USB stick or TV update was available.**

## Specification §16 — acceptance items

| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Application opens on Windows | **PASS** | Windows CI: `main.py --smoke-test` with the **native `windows` Qt platform** opened the main window and visited all 14 pages; the same for the PyInstaller EXE and for the EXE installed by the Inno Setup installer (exit code 0 each). Not yet run interactively on a Windows 10/11 desktop by a person. |
| 2 | TV project can be registered | **PASS** | `test_register_*`, UI workflow tests (Linux + Windows) |
| 3 | Images can be added | **PASS** | `test_add_evidence_image`, UI tests |
| 4 | OCR works | **PASS** | real Tesseract on synthetic label / chip / menu / PCB photos: Linux (5.3.4) and **Windows (5.5.3)** |
| 5 | Firmware can be imported | **PASS** | `test_import_preserves_original_and_layout`, duplicate detection |
| 6 | Hash can be computed | **PASS** | SHA-256 known-vector test; hashes on every stored file and report |
| 7 | Firmware Analyzer detects supported formats | **PASS** | 25+ validated formats; real squashfs/ext4/jffs2/UBI images (Linux tools); 0 false positives on random data |
| 8 | Universal Firmware Finder runs a real search | **PASS** | `test_real_github_search`, `test_real_gitlab_search` against the live APIs (Linux environment) |
| 9 | GitHub search returns real results | **PASS** | same; live UI search screenshot (Phase 5) |
| 10 | Firmware results have sources | **PASS** | provider, page URL, download URL, query, search time stored for every result; in all report formats |
| 11 | Compatibility Analyzer gives evidence-based results | **PASS** | 17 criteria with evidence; VERIFIED / LIKELY / POSSIBLE / INCOMPATIBLE / INSUFFICIENT scenarios tested |
| 12 | Firmware Upgrade Manager identifies supported methods | **PASS** | method registry (6 methods); per-profile applicability; only Official USB executes |
| 13 | Upgrade only through a verified profile | **PASS** | unverified profile → instructions only; INCOMPATIBLE → session blocked |
| 14 | PDF report can be generated | **PASS** | all **10 reports × 5 formats** (PDF, XLSX, CSV, JSON, HTML) — 50 combinations tested on Linux and Windows |
| 15 | Database can be reopened | **PASS** | reopen tests; real upgrades of existing databases v1→v2→…→v7, each phase |
| 16 | Original firmware unchanged after analysis | **PASS** | SHA-256 before/after recorded per run (`original_unchanged = 1`); analysis refused if the stored copy changed |

## Release deliverables

| Deliverable | Status |
|---|---|
| Windows EXE (PyInstaller) | built and smoke-tested in Windows CI |
| Installer (Inno Setup 6, per-user, keeps user data on uninstall) | built, silently installed, run and uninstalled in Windows CI |
| Documentation | README, architecture, Windows installation guide, user guide (Bahasa Melayu), module READMEs, changelog |
| Sample reports | `docs/samples` (synthetic scenario) |
| Test reports | phases 1–7 + this final report |

## NOT TESTED (requires hardware or software not available)
* Interactive use on a Windows 10/11 desktop by a person (CI covers start-up, navigation, EXE and installer).
* Real TVs: UPnP discovery, ADB queries, an actual USB firmware update performed by a TV.
* Real vendor firmware packages and real vendor datasheets / service manuals.
* Ghidra (only a stand-in for `analyzeHeadless`), Binwalk 3, HxD, Microsoft Defender scan of a real download.
* The Windows filesystem probe for USB sticks (FAT32 / removable detection through the Win32 API) with a physical stick.
* Web-search backends (Google Programmable Search, Brave, SearXNG) and Internet Archive live (tested with recorded API
  responses; blocked or unconfigured in the test environment).

## Bugs found during Phase 8 testing (all fixed)
1. Finder downloads kept a temporary file name in the library. This broke documented package-name validation and would
   have put a wrongly named package on the upgrade USB stick. Found by the end-to-end scenario.
2. The "Verified Firmware" status and dashboard counter were never set.
3. On Windows, Tesseract installed in its standard folder but not on PATH was not found by the OCR engine. Found by the
   first Windows CI run.
4. A test compared a POSIX path string, so it failed on Windows. This was a test-only issue.

Across the project, testing found 30+ defects that were fixed before release, including two security-relevant ones:
SSRF-style private-IP URLs were accepted, and long `Retry-After` values were obeyed without a cap. Details are in the
phase test reports.

## Conclusion
All 16 acceptance items of §16 pass. The remaining NOT TESTED items depend on physical TVs, vendor files or optional
third-party tools. The application reports where evidence is missing instead of guessing, and it never writes to a TV.
