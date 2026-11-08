"""In-memory stand-in for requests.Session with recorded API responses."""
from __future__ import annotations

import json
from urllib.parse import urlsplit


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, url="", json_data=None, history=None):
        self.status_code = status
        if json_data is not None:
            body = json.dumps(json_data).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        self.content = body if isinstance(body, bytes) else body.encode()
        self.headers = headers or {}
        self.url = url
        self.history = history or []
        self.reason = {200: "OK", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests"}.get(status, "")

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content)

    def iter_content(self, n):
        for i in range(0, len(self.content), n):
            yield self.content[i:i + n]


class FakeSession:
    """routes: {(method, 'host/path-prefix'): response or callable(url, params, headers) -> response}"""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.headers = {}
        self.calls: list[dict] = []

    def add(self, method, prefix, resp):
        self.routes[(method, prefix)] = resp

    def _find(self, method, url):
        p = urlsplit(url)
        key = (p.hostname or "") + p.path
        best = None
        for (m, prefix), r in self.routes.items():
            if m == method and key.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, r)
        return best[1] if best else None

    def request(self, method, url, headers=None, params=None, timeout=None, stream=False, allow_redirects=True):
        self.calls.append({"method": method, "url": url, "params": params, "headers": headers or {}})
        r = self._find(method, url)
        if r is None:
            return FakeResponse(404, b"not found", url=url)
        if callable(r):
            r = r(url, params, headers or {})
        if isinstance(r, list):          # sequence of responses (for retry tests)
            r = r.pop(0) if len(r) > 1 else r[0]
        if not r.url:
            r.url = url
        return r

    def get(self, url, timeout=None):
        return self.request("GET", url)


# ---- recorded API payloads (shapes follow the public API documentation) ---------------------
def github_repo(full, desc, pushed="2026-01-02T03:04:05Z"):
    return {"full_name": full, "html_url": f"https://github.com/{full}", "description": desc,
            "pushed_at": pushed, "stargazers_count": 5, "license": {"spdx_id": "MIT"}, "archived": False}


def github_release(full, tag, assets, body="Release notes"):
    return {"html_url": f"https://github.com/{full}/releases/tag/{tag}", "tag_name": tag, "name": tag, "body": body,
            "published_at": "2026-02-03T04:05:06Z", "prerelease": False, "draft": False,
            "assets": [{"name": n, "size": s, "browser_download_url": f"https://github.com/{full}/releases/download/{tag}/{n}",
                        "updated_at": "2026-02-03T04:05:06Z", "digest": d, "download_count": 1} for n, s, d in assets]}


SF_RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:media="http://video.search.yahoo.com/mrss/" version="2.0"><channel><title>proj</title>
<item><title>/fw/TP.MS338.PB801_V1.2.bin</title><link>https://sourceforge.net/projects/tvfw/files/fw/TP.MS338.PB801_V1.2.bin/download</link>
<pubDate>Sat, 30 Nov 2024 11:20:05 UT</pubDate>
<media:content url="https://sourceforge.net/projects/tvfw/files/fw/TP.MS338.PB801_V1.2.bin/download" filesize="4096"><media:hash algo="md5">0123456789abcdef0123456789abcdef</media:hash></media:content></item>
<item><title>/docs/readme.txt</title><link>https://sourceforge.net/projects/tvfw/files/docs/readme.txt/download</link></item>
</channel></rss>"""
