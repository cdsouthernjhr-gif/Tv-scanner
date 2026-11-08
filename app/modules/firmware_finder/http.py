"""Polite HTTP client for the Firmware Finder.

* Offline-first: every request fails with ``OfflineError`` while
  ``network.offline_mode`` is on (the operator switches it off explicitly).
* Per-host token-bucket rate limiting (requests/minute, configurable).
* Retries with exponential back-off on connection errors, 429 and 5xx,
  honouring ``Retry-After``.
* robots.txt is honoured for web *pages and downloads* (``respect_robots=True``);
  documented JSON APIs (GitHub, GitLab, Internet Archive) are governed by their
  API terms and rate limits instead.
* No login, cookie replay, CAPTCHA solving or access-control bypass of any kind.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
import urllib.robotparser
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

log = logging.getLogger(__name__)
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "fbclid", "gclid"}


class OfflineError(Exception):
    pass


class RobotsDisallowed(Exception):
    pass


class UrlRejected(ValueError):
    pass


def validate_url(url: str, resolve: bool = False) -> str:
    """Accept only http(s) URLs with a host, no embedded credentials, and (optionally) no private addresses."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise UrlRejected(f"unsupported scheme in {url!r}")
    if not parts.hostname:
        raise UrlRejected(f"no host in {url!r}")
    if parts.username or parts.password:
        raise UrlRejected("URLs with embedded credentials are not accepted")
    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:            # not an IP literal (UrlRejected is a ValueError: keep the checks outside)
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                           or ip.is_multicast or ip.is_unspecified):
        raise UrlRejected(f"private/loopback address not allowed: {host}")
    if ip is None and resolve:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            infos = []
        for info in infos:
            rip = ipaddress.ip_address(info[4][0])
            if rip.is_private or rip.is_loopback or rip.is_link_local:
                raise UrlRejected(f"{host} resolves to a private address")
    return url.strip()


def normalize_url(url: str) -> str:
    """Key for de-duplication: lower-case scheme/host, no fragment, no tracking params, no trailing slash."""
    p = urlsplit(url.strip())
    q = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k.lower() not in TRACKING_PARAMS))
    path = p.path.rstrip("/") or "/"
    host = (p.hostname or "").lower()
    if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
        host += f":{p.port}"
    return urlunsplit(("https" if p.scheme in ("http", "https") else p.scheme, host, path, q, ""))


@dataclass
class _Bucket:
    rate_per_min: float
    tokens: float = 0
    updated: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        self.tokens = max(1.0, self.rate_per_min / 6)    # small burst

    def wait_time(self) -> float:
        now = time.monotonic()
        self.tokens = min(max(1.0, self.rate_per_min / 6), self.tokens + (now - self.updated) * self.rate_per_min / 60)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return 0.0
        return (1 - self.tokens) * 60 / self.rate_per_min


class RateLimiter:
    def __init__(self, default_per_min: float = 30, per_host: dict[str, float] | None = None):
        self.default = default_per_min
        self.per_host = per_host or {}
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self.total_wait = 0.0

    def acquire(self, host: str, sleep=time.sleep) -> float:
        waited = 0.0
        while True:
            with self._lock:
                b = self._buckets.setdefault(host, _Bucket(self.per_host.get(host, self.default)))
                w = b.wait_time()
            if w <= 0:
                self.total_wait += waited
                return waited
            sleep(w)
            waited += w


class HttpClient:
    def __init__(self, config, session: requests.Session | None = None, sleep=time.sleep):
        self.config = config
        self.session = session or requests.Session()
        self.user_agent = config.get("network.user_agent", "TVIntelligenceScanner/0.5")
        self.timeout = float(config.get("network.request_timeout_seconds", 20))
        self.retries = int(config.get("network.retries", 3))
        self.sleep = sleep
        self.limiter = RateLimiter(float(config.get("network.max_requests_per_minute", 30)),
                                   {"api.github.com": 25, "gitlab.com": 60, "archive.org": 30})
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._robots_lock = threading.Lock()
        self.log: list[dict] = []          # request log for search history / debugging

    @property
    def online(self) -> bool:
        return not bool(self.config.get("network.offline_mode", True))

    def _robots_allowed(self, url: str) -> bool:
        p = urlsplit(url)
        base = f"{p.scheme}://{p.netloc}"
        with self._robots_lock:
            if base not in self._robots:
                rp = urllib.robotparser.RobotFileParser()
                try:
                    r = self.session.request("GET", base + "/robots.txt", timeout=self.timeout,
                                             headers={"User-Agent": self.user_agent})
                    if r.status_code in (401, 403):
                        rp.disallow_all = True
                    elif r.status_code >= 400:
                        rp.allow_all = True
                    else:
                        rp.parse(r.text.splitlines())
                except requests.RequestException:
                    rp = None            # robots unreachable: be conservative for pages
                self._robots[base] = rp
            rp = self._robots[base]
        if rp is None:
            return False
        return rp.can_fetch(self.user_agent, url)

    def request(self, method: str, url: str, *, respect_robots: bool = False, headers: dict | None = None,
                params: dict | None = None, stream: bool = False, allow_redirects: bool = True) -> requests.Response:
        if not self.online:
            raise OfflineError("Offline mode is on — enable online search in the Firmware Finder or Settings.")
        validate_url(url)
        if respect_robots and not self._robots_allowed(url):
            raise RobotsDisallowed(f"robots.txt of {urlsplit(url).netloc} disallows {url}")
        host = urlsplit(url).hostname or ""
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            self.limiter.acquire(host, self.sleep)
            t0 = time.monotonic()
            try:
                r = self.session.request(method, url, headers={"User-Agent": self.user_agent, **(headers or {})},
                                         params=params, timeout=self.timeout,
                                         stream=stream, allow_redirects=allow_redirects)
            except requests.RequestException as exc:
                last_exc = exc
                self.log.append({"url": url, "error": str(exc), "attempt": attempt})
                if attempt < self.retries:
                    self.sleep(min(30, 2 ** attempt))
                    continue
                raise
            self.log.append({"url": r.url, "status": r.status_code, "ms": int((time.monotonic() - t0) * 1000),
                             "attempt": attempt})
            if r.history:                         # redirects must not lead to private addresses
                validate_url(r.url)
            if r.status_code == 429 or 500 <= r.status_code < 600:
                if attempt < self.retries:
                    ra = r.headers.get("Retry-After")
                    delay = float(ra) if ra and ra.isdigit() else min(60, 2 ** (attempt + 1))
                    self.sleep(delay)
                    continue
            return r
        raise last_exc or RuntimeError("request failed")

    def get_json(self, url: str, **kw):
        r = self.request("GET", url, **kw)
        if r.status_code >= 400:
            raise requests.HTTPError(f"{r.status_code} {r.reason} for {url}: {r.text[:200]}", response=r)
        return r.json(), r
