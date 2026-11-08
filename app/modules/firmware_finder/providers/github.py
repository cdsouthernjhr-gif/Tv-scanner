"""GitHub provider (official REST API).

* Repository search: ``GET /search/repositories`` (name, description, README).
* Releases of the best repositories: ``GET /repos/{owner}/{repo}/releases`` → assets
  with real ``browser_download_url``; the asset ``digest`` (``sha256:…``) is used
  as the published hash when GitHub provides it.
* Code search (``GET /search/code``) only with a token — GitHub requires
  authentication for it. Repository search is NOT a search of all code.
* Rate-limit headers are recorded in ``status`` and searching stops at 0.
"""
from __future__ import annotations

from app.modules.firmware_finder.criteria import Query, SearchCriteria
from app.modules.firmware_finder.providers.base import (BaseSearchProvider, SearchHit, looks_like_firmware_file)

API = "https://api.github.com"
OPEN_SOURCE_WORDS = ("kernel", "linux", "u-boot", "uboot", "bsp", "source", "sdk", "driver")


class GitHubProvider(BaseSearchProvider):
    name = "GitHub"
    source_type = "github"
    description = "GitHub repositories, releases (assets + digests) and, with a token, code search"
    releases_per_query = 3

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        tok = self.secrets.get("github_token") if self.secrets else None
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    def _track(self, r) -> None:
        for k in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Resource"):
            if k in r.headers:
                self.status[k.split("-", 2)[-1].lower()] = r.headers[k]
        if r.headers.get("X-RateLimit-Remaining") == "0":
            self.status["exhausted"] = True

    def _get(self, path: str, params: dict | None = None):
        if self.status.get("exhausted"):
            raise RuntimeError(f"GitHub rate limit exhausted (resets at epoch {self.status.get('reset')})")
        data, r = self.http.get_json(API + path, headers=self._headers(), params=params)
        self._track(r)
        return data

    def repo_hit(self, repo: dict, q: Query) -> SearchHit:
        desc = repo.get("description") or ""
        st = "open_source" if any(w in (desc + repo["full_name"]).lower() for w in OPEN_SOURCE_WORDS) else self.source_type
        return SearchHit(self.name, st, repo["full_name"], repo["html_url"], q.text, q.kind, q.weight, desc,
                         published_at=repo.get("pushed_at") or repo.get("updated_at"),
                         raw={"kind": "repository", "stars": repo.get("stargazers_count"),
                              "license": (repo.get("license") or {}).get("spdx_id"), "archived": repo.get("archived")})

    def release_hits(self, full_name: str, q: Query, repo_desc: str = "") -> list[SearchHit]:
        hits = []
        for rel in self._get(f"/repos/{full_name}/releases", {"per_page": 5}) or []:
            for a in rel.get("assets", []):
                if not looks_like_firmware_file(a["name"]):
                    continue
                digest = a.get("digest") or ""
                sha = digest.split(":", 1)[1] if digest.startswith("sha256:") else None
                hits.append(SearchHit(
                    self.name, self.source_type, a["name"], rel["html_url"], q.text, q.kind, q.weight,
                    (rel.get("name") or rel.get("tag_name") or "") + " — " + (rel.get("body") or "")[:400] +
                    (f" | repository description: {repo_desc}" if repo_desc else ""),
                    file_name=a["name"], file_size=a.get("size"), download_url=a.get("browser_download_url"),
                    version=rel.get("tag_name"), published_at=rel.get("published_at") or a.get("updated_at"),
                    sha256=sha, sha256_source="GitHub release asset digest (API)" if sha else None,
                    raw={"kind": "release_asset", "repository": full_name, "prerelease": rel.get("prerelease"),
                         "draft": rel.get("draft"), "download_count": a.get("download_count")}))
        return hits

    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        if q.kind == "hash":
            return self.code_search(q) if self.secrets and self.secrets.has("github_token") else []
        data = self._get("/search/repositories", {"q": f"{q.text} in:name,description,readme", "per_page": 10})
        repos = data.get("items", [])
        hits = [self.repo_hit(r, q) for r in repos]
        for r in repos[: self.releases_per_query]:
            try:
                hits += self.release_hits(r["full_name"], q, r.get("description") or "")
            except Exception as exc:          # releases are best-effort enrichment
                self.status.setdefault("release_errors", []).append(f"{r['full_name']}: {str(exc)[:120]}")
        return hits

    def code_search(self, q: Query) -> list[SearchHit]:
        data = self._get("/search/code", {"q": q.text, "per_page": 10})
        return [SearchHit(self.name, self.source_type, f"{i['repository']['full_name']}: {i['path']}", i["html_url"],
                          q.text, q.kind, q.weight, "code search match", file_name=i["name"],
                          raw={"kind": "code", "repository": i["repository"]["full_name"]})
                for i in data.get("items", [])]


class OpenSourceFirmwareProvider(GitHubProvider):
    """Open-source BSP/kernel/U-Boot trees for the identified SoC or board (GitHub)."""
    name = "Open-source firmware (GitHub)"
    source_type = "open_source"
    description = "Kernel / U-Boot / BSP source trees for the SoC or mainboard"
    query_kinds = {"soc", "mainboard"}
    releases_per_query = 0

    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        term = criteria.soc if q.kind == "soc" and criteria.soc else q.text.replace(" firmware", "")
        data = self._get("/search/repositories", {"q": f"{term} kernel OR u-boot OR bsp in:name,description,readme",
                                                  "per_page": 10})
        out = []
        for r in data.get("items", []):
            h = self.repo_hit(r, q)
            h.provider, h.source_type = self.name, "open_source"
            out.append(h)
        return out
