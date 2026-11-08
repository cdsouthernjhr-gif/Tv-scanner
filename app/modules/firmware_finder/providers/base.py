"""Provider abstraction for the Universal Firmware Search Engine."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlsplit

from app.core.config import application_root
from app.modules.firmware_finder.criteria import Query, SearchCriteria
from app.modules.firmware_finder.http import HttpClient


@lru_cache(maxsize=1)
def domains() -> dict:
    return json.loads((application_root() / "resources" / "data" / "source_domains.json").read_text(encoding="utf-8"))


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def official_brand(url: str) -> str | None:
    h = host_of(url)
    for brand, doms in domains()["official"].items():
        if any(host_matches(h, d) for d in doms):
            return brand
    return None


def looks_like_firmware_file(name: str) -> bool:
    n = name.lower()
    return any(n.endswith(ext) for ext in domains()["firmware_extensions"])


def file_format(name: str | None) -> str | None:
    if not name:
        return None
    m = re.search(r"\.(tar\.gz|tar\.xz|[a-z0-9]{1,5})$", name.lower())
    return m.group(1).upper() if m else None


@dataclass
class SearchHit:
    provider: str
    source_type: str              # official | github | gitlab | sourceforge | archive | community | documentation | open_source
    title: str
    url: str                      # page where the result is described (View Source)
    query: str = ""
    query_kind: str = ""
    query_weight: float = 0.5
    description: str = ""
    file_name: str | None = None
    file_size: int | None = None
    download_url: str | None = None   # only when the source itself provides it
    version: str | None = None
    published_at: str | None = None
    sha256: str | None = None
    sha256_source: str | None = None
    other_hashes: dict = field(default_factory=dict)
    manufacturer: str | None = None
    distribution_status: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def site(self) -> str:
        return host_of(self.url)

    def text(self) -> str:
        return " ".join(x for x in (self.title, self.description, self.file_name or "", self.version or "",
                                    self.url) if x)


class ProviderUnavailable(Exception):
    pass


class BaseSearchProvider(ABC):
    name = "base"
    source_type = "other"
    description = ""
    query_kinds: set[str] | None = None        # None = all kinds

    def __init__(self, http: HttpClient, secrets=None, config=None):
        self.http, self.secrets, self.config = http, secrets, config
        self.status: dict = {}

    def availability(self) -> tuple[bool, str]:
        return True, "ready"

    def accepts(self, q: Query) -> bool:
        return self.query_kinds is None or q.kind in self.query_kinds

    @abstractmethod
    def search(self, q: Query, criteria: SearchCriteria) -> list[SearchHit]:
        ...
