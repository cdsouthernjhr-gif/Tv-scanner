"""GitLab provider (official REST API v4, gitlab.com or a configured instance)."""
from __future__ import annotations

from urllib.parse import quote

from app.modules.firmware_finder.criteria import Query, SearchCriteria
from app.modules.firmware_finder.providers.base import BaseSearchProvider, SearchHit, looks_like_firmware_file


class GitLabProvider(BaseSearchProvider):
    name = "GitLab"
    source_type = "gitlab"
    description = "GitLab projects and release asset links"

    @property
    def api(self) -> str:
        base = (self.config.get("finder.gitlab_url") if self.config else None) or "https://gitlab.com"
        return base.rstrip("/") + "/api/v4"

    def _headers(self):
        tok = self.secrets.get("gitlab_token") if self.secrets else None
        return {"PRIVATE-TOKEN": tok} if tok else {}

    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        if q.kind == "hash":
            return []
        data, r = self.http.get_json(f"{self.api}/projects", headers=self._headers(),
                                     params={"search": q.text.replace(" firmware", ""), "per_page": 10,
                                             "order_by": "last_activity_at", "simple": "true"})
        self.status["ratelimit_remaining"] = r.headers.get("RateLimit-Remaining")
        hits = []
        for p in data:
            hits.append(SearchHit(self.name, self.source_type, p["path_with_namespace"], p["web_url"], q.text, q.kind,
                                  q.weight, p.get("description") or "", published_at=p.get("last_activity_at"),
                                  raw={"kind": "project", "id": p["id"], "stars": p.get("star_count")}))
        for p in data[:3]:
            try:
                rels, _ = self.http.get_json(f"{self.api}/projects/{quote(str(p['id']))}/releases",
                                             headers=self._headers(), params={"per_page": 5})
            except Exception as exc:
                self.status.setdefault("release_errors", []).append(f"{p['path_with_namespace']}: {str(exc)[:100]}")
                continue
            for rel in rels:
                for link in (rel.get("assets") or {}).get("links", []):
                    if not looks_like_firmware_file(link.get("name", "")):
                        continue
                    hits.append(SearchHit(
                        self.name, self.source_type, link["name"],
                        (rel.get("_links") or {}).get("self") or p["web_url"], q.text, q.kind, q.weight,
                        (rel.get("name") or rel.get("tag_name") or "") + " — " + (rel.get("description") or "")[:400],
                        file_name=link["name"], download_url=link.get("direct_asset_url") or link.get("url"),
                        version=rel.get("tag_name"), published_at=rel.get("released_at"),
                        raw={"kind": "release_asset", "project": p["path_with_namespace"]}))
        return hits
