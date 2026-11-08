# Test Report — Phase 5 (Universal Firmware Finder)

* Date: 2026-11-08 · Build 0.5.0 · database schema v5 (migration `0005_firmware_finder.sql`)
* Environment: Linux container, Python 3.13, requests 2.34, keyring (no OS backend in the container), PySide6 offscreen.
* Network in the test environment: **api.github.com, gitlab.com and sourceforge.net reachable**. archive.org, vendor
  sites and web-search engines were **blocked by the sandbox's egress policy**. Repository-specific GitHub endpoints
  (`/repos/*/releases`) were also restricted by the sandbox proxy (this is not a GitHub limitation).
* **Not executed on Windows 10/11.**

Command: `QT_QPA_PLATFORM=offscreen python -m pytest` → **223 passed, 0 failed, 0 skipped**
(186 from Phases 1–4 + 37 new, of which 2 are real-network tests).

## Acceptance items (spec §16)

| Item | Result | Evidence |
|---|---|---|
| Universal Firmware Finder runs a real search | **PASS** | `test_real_github_search`, `test_real_gitlab_search` (live APIs); live UI search shown in screenshot |
| GitHub search returns real results | **PASS** | live GitHub repository search |
| Every firmware result has a source | PASS | provider, page URL, query, search time stored for every row; reports include them |
| Unknown model searched by mainboard/chipset | PASS | `test_queries_known_and_unknown_model`; live UI search with mainboard + SoC only |

## Phase 5 deliverables

| Item | Result | Evidence |
|---|---|---|
| Offline-first gate | PASS | `test_offline_blocks_everything` |
| Provider abstraction (8 providers) | PASS | status/availability per provider; disabled ones state why |
| GitHub: repos, releases, asset digest → SHA-256, token, code search only with token, rate-limit stop | PASS | recorded responses |
| GitLab: projects, release links, error noted without failing the search | PASS | `test_engine_search_rank_dedupe_history` |
| Internet Archive: files, MD5/SHA-1, licence → distribution status | PASS (recorded) / NOT TESTED live | archive.org blocked in sandbox |
| Web search backends (Google CSE, Brave, SearXNG), several in parallel, site restriction, look-alike domains dropped | PASS (recorded) / NOT TESTED live | no API keys in the test environment |
| SourceForge via documented RSS feed | PASS (parser + live feed checked manually) | `test_sourceforge_rss_parser` |
| Query builder, parallel search, rate limiting, retries with Retry-After | PASS | http and engine tests |
| robots.txt for pages/downloads | PASS | `test_robots_respected_for_pages` |
| URL validation (schemes, credentials, private/loopback/link-local/metadata IPs, redirects) | PASS | `test_validate_url_rejects`, `test_redirect_to_private_address_rejected` |
| De-duplication across queries/providers | PASS | engine test |
| Matching engine: five verdicts with per-criterion evidence | PASS | matching tests |
| "Never verified from search results" | PASS | `test_search_result_never_verified_even_official_with_hash` |
| Download manager: hash verify, quarantine on mismatch, size/HTML refusals, rights confirmation | PASS | download tests |
| Malware scan integration (threat → quarantine) | PASS (ClamAV stand-in) | Defender on Windows NOT TESTED |
| Download → analysis → VERIFIED MATCH | PASS | `test_download_verify_import_and_verified_after_analysis` |
| API keys in credential store; never in settings/DB/audit | PASS | secrets tests, settings UI test; tests isolated from the real credential store |
| Search history + Firmware Search Report PDF/CSV/JSON | PASS | `test_search_reports` |
| Finder UI (load criteria, queries preview, providers, search, details, download, reports) | PASS | `test_finder_page_workflow` |

## Bugs found and fixed during Phase 5
1. **Security**: `validate_url` accepted private, loopback and cloud-metadata IP literals, because the rejection
   (`UrlRejected`, a `ValueError`) was raised inside the `try` that caught `ValueError`. Fixed and covered by 3 test cases.
2. The User-Agent was taken from session headers. It is now sent with every request, including robots.txt.
3. A release asset did not carry its repository's description, so the board identifier in that description was
   ignored. It is now included and labelled as repository context.
4. Tests could have written test tokens into a developer's real Windows Credential Manager. The test fixture now
   forces an isolated store.

## Known open issues
1. Official manufacturer sites need a web-search API key (or a SearXNG instance). Without one, the official provider is
   disabled and says so. Direct vendor download APIs are not implemented because none are publicly documented.
2. GitHub unauthenticated search is limited to about 10 requests/minute; a token raises the limit and enables code search.
3. Archive.org and web-search backends were not exercised live in this environment.
