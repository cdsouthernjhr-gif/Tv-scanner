"""Internet Archive provider (advancedsearch + metadata APIs).

Only items whose licence/rights metadata permits redistribution are marked
'licensed'; everything else is 'unknown' and the download manager will refuse
it unless the operator explicitly confirms they have the right to obtain it.
The Archive publishes MD5/SHA-1 (not SHA-256); those are kept as other hashes.
"""
from __future__ import annotations

from urllib.parse import quote

from app.modules.firmware_finder.criteria import Query, SearchCriteria
from app.modules.firmware_finder.providers.base import BaseSearchProvider, SearchHit, looks_like_firmware_file

API = "https://archive.org"


def distribution_status(meta: dict) -> str:
    lic = (meta.get("licenseurl") or "").lower()
    if "creativecommons.org" in lic or "publicdomain" in lic or "gnu.org/licenses" in lic or "opensource.org" in lic:
        return "licensed"
    return "unknown"


class ArchiveSearchProvider(BaseSearchProvider):
    name = "Internet Archive"
    source_type = "archive"
    description = "archive.org items (redistribution status checked from licence metadata)"

    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        if q.kind == "hash":
            return []
        data, _ = self.http.get_json(f"{API}/advancedsearch.php", params={
            "q": q.text.replace(" firmware", "") + " AND (firmware OR software)",
            "fl[]": ["identifier", "title", "description", "date", "licenseurl"], "rows": 10, "output": "json"})
        hits = []
        for doc in (data.get("response") or {}).get("docs", []):
            ident = doc["identifier"]
            dist = distribution_status(doc)
            desc = doc.get("description")
            desc = " ".join(desc) if isinstance(desc, list) else (desc or "")
            hits.append(SearchHit(self.name, self.source_type, doc.get("title") or ident, f"{API}/details/{ident}",
                                  q.text, q.kind, q.weight, desc[:500], published_at=doc.get("date"),
                                  distribution_status=dist, raw={"kind": "item", "identifier": ident,
                                                                 "licenseurl": doc.get("licenseurl")}))
        for h in list(hits)[:3]:
            ident = h.raw["identifier"]
            try:
                meta, _ = self.http.get_json(f"{API}/metadata/{quote(ident)}")
            except Exception as exc:
                self.status.setdefault("metadata_errors", []).append(f"{ident}: {str(exc)[:100]}")
                continue
            for f in meta.get("files", []):
                if not looks_like_firmware_file(f.get("name", "")):
                    continue
                hits.append(SearchHit(self.name, self.source_type, f["name"], h.url, q.text, q.kind, q.weight,
                                      h.title, file_name=f["name"],
                                      file_size=int(f["size"]) if str(f.get("size", "")).isdigit() else None,
                                      download_url=f"{API}/download/{quote(ident)}/{quote(f['name'])}",
                                      published_at=h.published_at,
                                      other_hashes={k: f[k] for k in ("md5", "sha1") if f.get(k)},
                                      distribution_status=distribution_status(meta.get("metadata", {})),
                                      raw={"kind": "item_file", "identifier": ident}))
        return hits
