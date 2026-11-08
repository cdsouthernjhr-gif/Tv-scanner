# Universal Firmware Finder (Phase 5)

## Architecture
```
criteria.py   SearchCriteria (+ origin of every value) ← project, confirmed hardware, analysed firmware
              build_queries(): model → mainboard/chassis/product code → file name/version → SoC → hash
http.py       HttpClient: offline gate, per-host token-bucket rate limit, retries (429/5xx, Retry-After),
              robots.txt for pages/downloads, URL validation (http/https, no credentials, no private IPs,
              redirects re-checked), URL normalisation for de-duplication
providers/    BaseSearchProvider → SearchHit
  github.py     GitHubProvider (REST search/repositories, releases + asset digest, code search with token,
                rate-limit monitoring), OpenSourceFirmwareProvider (kernel/U-Boot/BSP trees for the SoC/board)
  gitlab.py     GitLabProvider (projects + release asset links; gitlab.com or own instance)
  archive.py    ArchiveSearchProvider (advancedsearch + metadata; licence → distribution status)
  websearch.py  Web backends: Google Programmable Search, Brave Search, SearXNG (several may be active)
                OfficialManufacturerProvider (site: brand-owned domains), CommunitySearchProvider,
                TechnicalDocumentationProvider (datasheets / service manuals, PDF),
                SourceForgeProvider (site:sourceforge.net + documented project RSS file feed)
matching.py   per-criterion evidence → VERIFIED / HIGH CONFIDENCE / POSSIBLE / INCOMPATIBLE / INSUFFICIENT,
              score 0–100, risk Low/Medium/High/Critical with reasons
engine.py     FirmwareFinder: parallel search, dedupe, ranking, history, download manager, re-evaluation
```
Domains used for classification live in `resources/data/source_domains.json` (official brand domains,
community forums, firmware file extensions, risk keywords).

## Rules that keep results honest
* **Offline-first**: nothing goes on the network until the operator enables online search
  (Finder checkbox or Settings). Every request is logged in the session.
* **No invented URLs**: `download_url` is only a URL returned by the source's API/feed/search result
  (Archive files use the Archive's documented `/download/<identifier>/<file>` form from API data).
* **No verification from search text**: a search result can be at most HIGH CONFIDENCE.
  VERIFIED MATCH needs: download → SHA-256 equal to the source-published hash (or HTTPS from the
  manufacturer's domain) → Firmware Analyzer finds this model in the file → no mismatch.
* **Weak evidence is capped**: SoC / file name / version similarity alone → POSSIBLE MATCH, score ≤ 30.
* **Hard mismatches** from analysed content (CPU architecture, product model in build.prop, published
  hash) → INCOMPATIBLE.
* **Risk keywords** (keys, decrypt, crack, bypass, jailbreak, root exploit, patched, modded, unlock) →
  Critical and never above POSSIBLE: such repositories are not firmware sources.
* **Distribution rights**: Archive items without an open licence are `unknown`; downloading them
  requires an explicit confirmation by the operator.
* **Respectful access**: official APIs where they exist; robots.txt for pages and non-API downloads;
  per-host rate limits; no login, cookie replay, CAPTCHA solving or paywall bypass; web pages of
  forums are not scraped (only search-API titles/snippets/links are used).

## Download manager
1. Only results with a `download_url`; pages/repositories → "View Source".
2. Size limit (`finder.max_download_bytes`, default 8 GiB), Content-Length check, HTML responses
   (login/consent pages) refused.
3. SHA-256 computed while streaming; compared with the published value → mismatch = quarantine,
   not imported.
4. Malware scan (Microsoft Defender `MpCmdRun.exe` on Windows, ClamAV elsewhere); threat = quarantine.
   No scanner → recorded as "not scanned" (never shown as clean).
5. Imported read-only into the Firmware Library (category Official only for manufacturer domains,
   otherwise Community) with provenance: provider, page URL, download URL, time, published hash.
6. "Analyze Firmware" runs the Phase 4 analyzer and re-evaluates the match.

## API keys
GitHub token (optional), GitLab token (optional), Google Programmable Search key (+ engine id `cx`
in Settings), Brave Search key. Stored with `keyring` → Windows Credential Manager. Without a secure
store, keys are kept for the session only. Keys never appear in settings.json, the database, logs or
the audit trail.

## Search history and reports
Each search is a `search_sessions` row (criteria with origins, queries, providers, notes/errors,
timestamps); results keep provider, page URL, query and search time. Firmware Search Report: PDF,
CSV, JSON.
