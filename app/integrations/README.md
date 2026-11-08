# Integrations

Adapters for external tools and online sources. Each integration lives in its own
package and must:

1. Be optional — absence of the tool/service disables only the dependent feature.
2. Never modify original firmware (operate on `FirmwareLibrary.make_working_copy()` output).
3. Run external processes with explicit argument lists (no shell), a timeout, and output captured to the analysis record.
4. For online sources: use official APIs where available, respect robots.txt/ToS and rate limits, never bypass login/CAPTCHA/paywalls, and store the real source URL + retrieval time.

| Package | Phase | Status |
|---|---|---|
| `binwalk/` | 4 | Implemented — v2 tested, v3 parser untested; see `binwalk/README.md` |
| `ghidra/` | 4 | Implemented — tested with stand-in only; see `ghidra/README.md` |
| GitHub / GitLab / Archive / web search | 5 | Implemented as Firmware Finder providers in `app/modules/firmware_finder/providers/` |
| `manufacturer/` | — | Reserved for documented vendor download APIs (none publicly documented yet); official sites are covered by site-restricted web search |
| `community/` | 5 | Covered by `CommunitySearchProvider` (search-API results only, no scraping) |

A detailed README is added to each package when it is implemented.
