"""Web search backends (documented APIs, keys stored via SecretStore) and providers built on them.

Backends: Google Programmable Search JSON API, Brave Search API, SearXNG (self-hosted, JSON).
Several backends can be configured; the providers use every configured backend so results do not
depend on a single search engine. Only titles, URLs and snippets returned by the API are used —
pages are not scraped.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from app.modules.firmware_finder.criteria import Query, SearchCriteria
from app.modules.firmware_finder.providers.base import (BaseSearchProvider, ProviderUnavailable, SearchHit, domains,
                                                        host_matches, host_of, looks_like_firmware_file,
                                                        official_brand)


class WebBackend:
    name = "web"

    def __init__(self, http, secrets, config):
        self.http, self.secrets, self.config = http, secrets, config

    def configured(self) -> bool:
        raise NotImplementedError

    def search(self, text: str, num: int = 10) -> list[dict]:
        """-> [{title, url, snippet}]"""
        raise NotImplementedError


class GoogleCSE(WebBackend):
    name = "Google Programmable Search"

    def configured(self):
        return bool(self.secrets.get("google_cse_key") and self.config.get("finder.google_cse_cx"))

    def search(self, text, num=10):
        data, _ = self.http.get_json("https://www.googleapis.com/customsearch/v1", params={
            "key": self.secrets.get("google_cse_key"), "cx": self.config.get("finder.google_cse_cx"), "q": text,
            "num": min(num, 10)})
        return [{"title": i.get("title", ""), "url": i["link"], "snippet": i.get("snippet", "")}
                for i in data.get("items", [])]


class BraveSearch(WebBackend):
    name = "Brave Search"

    def configured(self):
        return bool(self.secrets.get("brave_search_key"))

    def search(self, text, num=10):
        data, _ = self.http.get_json("https://api.search.brave.com/res/v1/web/search",
                                     headers={"X-Subscription-Token": self.secrets.get("brave_search_key"),
                                              "Accept": "application/json"}, params={"q": text, "count": num})
        return [{"title": r.get("title", ""), "url": r["url"], "snippet": r.get("description", "")}
                for r in (data.get("web") or {}).get("results", [])]


class SearXNG(WebBackend):
    name = "SearXNG"

    def configured(self):
        return bool(self.config.get("finder.searxng_url"))

    def search(self, text, num=10):
        base = self.config.get("finder.searxng_url").rstrip("/")
        data, _ = self.http.get_json(base + "/search", params={"q": text, "format": "json"})
        return [{"title": r.get("title", ""), "url": r["url"], "snippet": r.get("content", "")}
                for r in data.get("results", [])[:num]]


BACKENDS = (GoogleCSE, BraveSearch, SearXNG)


class WebSearchProvider(BaseSearchProvider):
    """Base for providers that run site-restricted queries through the configured web backends."""
    sites: list[str] = []

    def backends(self) -> list[WebBackend]:
        return [b for b in (cls(self.http, self.secrets, self.config) for cls in BACKENDS) if b.configured()]

    def availability(self):
        b = self.backends()
        if not b:
            return False, "needs a web search API (Google Programmable Search, Brave Search or SearXNG) in Settings"
        return True, "via " + ", ".join(x.name for x in b)

    def site_filter(self, criteria: SearchCriteria) -> str:
        return " OR ".join(f"site:{s}" for s in self.sites)

    def make_query(self, q: Query, criteria: SearchCriteria) -> str:
        f = self.site_filter(criteria)
        return f"{q.text} ({f})" if f else q.text

    def keep(self, url: str, criteria: SearchCriteria) -> bool:
        return not self.sites or any(host_matches(host_of(url), s) for s in self.sites)

    def to_hit(self, r: dict, q: Query, backend: str) -> SearchHit:
        name = urlsplit(r["url"]).path.rsplit("/", 1)[-1]
        is_file = looks_like_firmware_file(name)
        return SearchHit(self.name, self.source_type, r["title"] or r["url"], r["url"], q.text, q.kind, q.weight,
                         r.get("snippet", ""), file_name=name if is_file else None,
                         download_url=r["url"] if is_file else None, manufacturer=official_brand(r["url"]),
                         raw={"kind": "web", "backend": backend})

    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        if q.kind == "hash":
            return []
        backends = self.backends()
        if not backends:
            raise ProviderUnavailable(self.availability()[1])
        hits, errors = [], []
        for b in backends:
            try:
                for r in b.search(self.make_query(q, criteria)):
                    if self.keep(r["url"], criteria):
                        hits.append(self.to_hit(r, q, b.name))
            except Exception as exc:
                errors.append(f"{b.name}: {str(exc)[:150]}")
        if errors:
            self.status["backend_errors"] = errors
        if errors and not hits and len(errors) == len(backends):
            raise RuntimeError("; ".join(errors))
        return hits


class OfficialManufacturerProvider(WebSearchProvider):
    name = "Official manufacturer sites"
    source_type = "official"
    description = "Manufacturer support/download pages (site-restricted web search on brand-owned domains)"

    def _brand_domains(self, criteria):
        off = domains()["official"]
        if criteria.manufacturer:
            for brand, doms in off.items():
                if brand.lower() == criteria.manufacturer.lower():
                    return doms
        return [d for doms in off.values() for d in doms]

    def site_filter(self, criteria):
        return " OR ".join(f"site:{d}" for d in self._brand_domains(criteria))

    def keep(self, url, criteria):
        return any(host_matches(host_of(url), d) for d in self._brand_domains(criteria))


class CommunitySearchProvider(WebSearchProvider):
    name = "Repair communities"
    source_type = "community"
    description = "Public threads on TV repair / electronics forums (search-engine results only; pages are not scraped)"

    @property
    def sites(self):
        return domains()["community"]


class TechnicalDocumentationProvider(WebSearchProvider):
    name = "Technical documentation"
    source_type = "documentation"
    description = "Datasheets and service manuals for the mainboard / SoC (PDF)"
    query_kinds = {"mainboard", "soc", "chassis", "model"}

    def make_query(self, q, criteria):
        base = q.text.replace(" firmware", "").replace(" linux kernel source", "")
        return f"{base} (datasheet OR \"service manual\") filetype:pdf"

    def keep(self, url, criteria):
        return True


class SourceForgeProvider(WebSearchProvider):
    """Projects found via web search (site:sourceforge.net); files listed from the project's documented RSS feed."""
    name = "SourceForge"
    source_type = "sourceforge"
    description = "SourceForge projects (web search) + file lists from project RSS feeds"
    sites = ["sourceforge.net"]

    def search(self, q, criteria):
        hits = super().search(q, criteria)
        projects = []
        for h in hits:
            parts = urlsplit(h.url).path.strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "projects" and parts[1] not in projects:
                projects.append(parts[1])
        for proj in projects[:3]:
            try:
                hits += self.rss_files(proj, q)
            except Exception as exc:
                self.status.setdefault("rss_errors", []).append(f"{proj}: {str(exc)[:100]}")
        return hits

    def rss_files(self, project: str, q: Query) -> list[SearchHit]:
        r = self.http.request("GET", f"https://sourceforge.net/projects/{project}/rss", params={"path": "/"},
                              respect_robots=True)
        if r.status_code != 200:
            return []
        return parse_sourceforge_rss(r.text, project, q, self.name)


def parse_sourceforge_rss(xml_text: str, project: str, q: Query, provider: str = "SourceForge") -> list[SearchHit]:
    ns = {"media": "http://video.search.yahoo.com/mrss/"}
    out = []
    root = ET.fromstring(xml_text)
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        name = title.rsplit("/", 1)[-1]
        if not looks_like_firmware_file(name):
            continue
        content = it.find("media:content", ns)
        size = int(content.get("filesize")) if content is not None and content.get("filesize", "").isdigit() else None
        hashes = {h.get("algo"): (h.text or "").strip() for h in it.findall(".//media:hash", ns)}
        link = (content.get("url") if content is not None else None) or it.findtext("link")
        out.append(SearchHit(provider, "sourceforge", name, f"https://sourceforge.net/projects/{project}/files{title}",
                             q.text, q.kind, q.weight, title, file_name=name, file_size=size, download_url=link,
                             published_at=it.findtext("pubDate"), other_hashes=hashes,
                             raw={"kind": "sf_file", "project": project}))
    return out
