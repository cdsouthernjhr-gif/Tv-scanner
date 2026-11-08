import hashlib
import json
import os
import socket
import stat
import sys
from pathlib import Path

import pytest

import firmware_builders as fb
from app.modules.firmware_finder import matching
from app.modules.firmware_finder.criteria import SearchCriteria, build_queries, from_project
from app.modules.firmware_finder.engine import DownloadRefused
from app.modules.firmware_finder.http import (HttpClient, OfflineError, RateLimiter, RobotsDisallowed, UrlRejected,
                                              normalize_url, validate_url)
from app.modules.firmware_finder.providers.archive import ArchiveSearchProvider, distribution_status
from app.modules.firmware_finder.providers.base import SearchHit
from app.modules.firmware_finder.providers.github import GitHubProvider
from app.modules.firmware_finder.providers.websearch import OfficialManufacturerProvider, parse_sourceforge_rss
from app.modules.firmware_finder.criteria import Query
from app.security.secrets import SecretStore
from app.services.project_service import TVProject
from fake_http import SF_RSS, FakeResponse, FakeSession, github_release, github_repo


@pytest.fixture
def online(ctx):
    ctx.config.set("network.offline_mode", False)
    sess = FakeSession()
    ctx.finder.http.session = sess
    ctx.finder.http.sleep = lambda s: None
    ctx.finder.http.limiter = RateLimiter(10_000)
    return ctx, sess


# ---- http ------------------------------------------------------------------------------------------
def test_offline_blocks_everything(ctx):
    assert ctx.config.get("network.offline_mode") is True       # offline-first default
    with pytest.raises(OfflineError):
        ctx.finder.http.request("GET", "https://api.github.com/")
    with pytest.raises(OfflineError):
        ctx.finder.search(SearchCriteria(model_number="ABC123"))


@pytest.mark.parametrize("url", ["ftp://x.com/a", "https://user:pw@x.com/", "http://127.0.0.1/a", "http://10.0.0.5/fw",
                                 "https:///nohost", "file:///etc/passwd", "http://169.254.169.254/latest"])
def test_validate_url_rejects(url):
    with pytest.raises(UrlRejected):
        validate_url(url)


def test_normalize_url():
    a = normalize_url("HTTPS://GitHub.com/a/b/?utm_source=x&b=2&a=1#frag")
    assert a == normalize_url("https://github.com/a/b?a=1&b=2") == "https://github.com/a/b?a=1&b=2"


def test_rate_limiter_waits():
    slept = []
    rl = RateLimiter(60)                       # 1/s, burst 10
    for _ in range(12):
        rl.acquire("h", sleep=lambda s: slept.append(s))
    assert slept and sum(slept) > 0.5


def test_retry_honours_retry_after(online):
    ctx, sess = online
    waits = []
    ctx.finder.http.sleep = waits.append
    sess.add("GET", "api.example.org/x", [FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, json_data={"ok": 1})])
    data, _ = ctx.finder.http.get_json("https://api.example.org/x")
    assert data == {"ok": 1} and 7.0 in waits


def test_robots_respected_for_pages(online):
    ctx, sess = online
    sess.add("GET", "forum.example.org/robots.txt", FakeResponse(200, b"User-agent: *\nDisallow: /private/\n"))
    sess.add("GET", "forum.example.org/", FakeResponse(200, b"page"))
    assert ctx.finder.http.request("GET", "https://forum.example.org/public/a", respect_robots=True).status_code == 200
    with pytest.raises(RobotsDisallowed):
        ctx.finder.http.request("GET", "https://forum.example.org/private/fw.bin", respect_robots=True)


def test_redirect_to_private_address_rejected(online):
    ctx, sess = online
    sess.add("GET", "cdn.example.org/fw", FakeResponse(200, b"x", url="http://192.168.1.1/fw", history=[object()]))
    with pytest.raises(UrlRejected):
        ctx.finder.http.request("GET", "https://cdn.example.org/fw")


# ---- criteria / queries --------------------------------------------------------------------------
def test_queries_known_and_unknown_model():
    q = build_queries(SearchCriteria(manufacturer="Samsung", model_number="UA55AU7000", mainboard="BN41-02635A",
                                     soc="MSD6A648"))
    assert q[0].kind == "model" and q[0].text == "Samsung UA55AU7000 firmware"
    assert [x.kind for x in q].index("mainboard") < [x.kind for x in q].index("soc")
    u = build_queries(SearchCriteria(mainboard="TP.MS338.PB801", pcb_revision="1.1", soc="MSD6A648"))
    assert u[0].kind == "mainboard" and u[0].weight == 0.9 and "TP.MS338.PB801 1.1" in [x.text for x in u]
    assert build_queries(SearchCriteria()) == []


def test_criteria_from_project(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55", mainboard="TP.MS338.PB801"))
    ctx.hardware.analyze(ctx.hardware.add_component(p.id, "soc", "MSD6A648"))
    f = tmp_path / "fw.bin"
    fb.composite(f)
    rec = ctx.library.import_file(f, project_id=p.id)
    ctx.firmware.analyze(rec.id, use_binwalk=False)
    c = from_project(ctx, p.id)
    assert (c.manufacturer, c.model_number, c.mainboard, c.soc) == ("Acme", "TESTTV55", "TP.MS338.PB801", "MSD6A648")
    assert c.architecture == "ARM (32-bit)" and c.sha256 == rec.sha256
    assert c.sources["soc"].startswith("hardware component") and "analysis" in c.sources["architecture"]


# ---- providers ------------------------------------------------------------------------------------
def test_github_provider_releases_digest_and_ratelimit(online):
    ctx, sess = online
    sha = "a" * 64
    sess.add("GET", "api.github.com/search/repositories", FakeResponse(200, json_data={"items": [
        github_repo("acme/tv-fw", "Firmware for TP.MS338.PB801 boards")]}, headers={"X-RateLimit-Remaining": "9",
                                                                                      "X-RateLimit-Limit": "10"}))
    sess.add("GET", "api.github.com/repos/acme/tv-fw/releases", FakeResponse(200, json_data=[github_release(
        "acme/tv-fw", "v1.2", [("TP.MS338.PB801_v1.2.bin", 4096, f"sha256:{sha}"), ("notes.txt", 10, "")])]))
    p = GitHubProvider(ctx.finder.http, ctx.secrets, ctx.config)
    hits = p.search(Query("TP.MS338.PB801 firmware", "mainboard", 0.9), SearchCriteria(mainboard="TP.MS338.PB801"))
    assets = [h for h in hits if h.raw.get("kind") == "release_asset"]
    assert len(assets) == 1 and assets[0].sha256 == sha and assets[0].sha256_source.startswith("GitHub release")
    assert assets[0].download_url.endswith("/v1.2/TP.MS338.PB801_v1.2.bin") and assets[0].version == "v1.2"
    assert p.status["remaining"] == "9"
    assert "Authorization" not in sess.calls[0]["headers"]
    sess.add("GET", "api.github.com/search/repositories", FakeResponse(200, json_data={"items": []},
                                                                         headers={"X-RateLimit-Remaining": "0"}))
    p.search(Query("x", "model", 1), SearchCriteria(model_number="x"))
    with pytest.raises(RuntimeError, match="rate limit"):
        p.search(Query("y", "model", 1), SearchCriteria(model_number="y"))


def test_github_token_and_code_search_only_with_token(online):
    ctx, sess = online
    p = GitHubProvider(ctx.finder.http, ctx.secrets, ctx.config)
    assert p.search(Query("a" * 64, "hash", 1), SearchCriteria(sha256="a" * 64)) == []      # no token: skipped
    ctx.secrets.set("github_token", "ghp_testtoken123")
    sess.add("GET", "api.github.com/search/code", FakeResponse(200, json_data={"items": [
        {"name": "fw.sha256", "path": "x/fw.sha256", "html_url": "https://github.com/a/b/blob/main/x/fw.sha256",
         "repository": {"full_name": "a/b"}}]}))
    hits = p.search(Query("a" * 64, "hash", 1), SearchCriteria(sha256="a" * 64))
    assert hits[0].raw["kind"] == "code"
    assert sess.calls[-1]["headers"]["Authorization"] == "Bearer ghp_testtoken123"


def test_archive_distribution_status_and_files(online):
    ctx, sess = online
    assert distribution_status({"licenseurl": "https://creativecommons.org/licenses/by/4.0/"}) == "licensed"
    assert distribution_status({}) == "unknown"
    sess.add("GET", "archive.org/advancedsearch.php", FakeResponse(200, json_data={"response": {"docs": [
        {"identifier": "tvfw-item", "title": "TV firmware dump", "date": "2020-01-01"}]}}))
    sess.add("GET", "archive.org/metadata/tvfw-item", FakeResponse(200, json_data={"metadata": {}, "files": [
        {"name": "MSD6A648_upgrade.bin", "size": "1024", "md5": "abc"}, {"name": "cover.jpg"}]}))
    hits = ArchiveSearchProvider(ctx.finder.http, ctx.secrets, ctx.config).search(
        Query("MSD6A648 firmware", "soc", 0.4), SearchCriteria(soc="MSD6A648"))
    f = [h for h in hits if h.file_name][0]
    assert f.distribution_status == "unknown" and f.other_hashes == {"md5": "abc"} and f.sha256 is None
    assert f.download_url == "https://archive.org/download/tvfw-item/MSD6A648_upgrade.bin"


def test_web_search_backends_and_official_domains(online):
    ctx, sess = online
    p = OfficialManufacturerProvider(ctx.finder.http, ctx.secrets, ctx.config)
    assert p.availability()[0] is False
    ctx.secrets.set("brave_search_key", "BSA-test")
    ctx.config.set("finder.searxng_url", "https://searx.example.org")
    assert p.availability() == (True, "via Brave Search, SearXNG")
    sess.add("GET", "api.search.brave.com/res/v1/web/search", FakeResponse(200, json_data={"web": {"results": [
        {"title": "UA55AU7000 software", "url": "https://www.samsung.com/my/support/model/UA55AU7000/", "description": "Firmware"},
        {"title": "fake", "url": "https://samsung.com.evil.example/fw.bin", "description": "x"}]}}))
    sess.add("GET", "searx.example.org/search", FakeResponse(200, json_data={"results": [
        {"title": "Upgrade file", "url": "https://downloadcenter.samsung.com/content/FM/UA55AU7000.zip", "content": "zip"}]}))
    hits = p.search(Query("Samsung UA55AU7000 firmware", "model", 1.0),
                    SearchCriteria(manufacturer="Samsung", model_number="UA55AU7000"))
    assert {h.url for h in hits} == {"https://www.samsung.com/my/support/model/UA55AU7000/",
                                     "https://downloadcenter.samsung.com/content/FM/UA55AU7000.zip"}   # look-alike dropped
    assert "site:samsung.com" in sess.calls[0]["params"]["q"]
    z = [h for h in hits if h.file_name][0]
    assert z.download_url.endswith(".zip") and z.manufacturer == "Samsung"


def test_sourceforge_rss_parser():
    hits = parse_sourceforge_rss(SF_RSS, "tvfw", Query("q", "mainboard", 0.9))
    assert len(hits) == 1 and hits[0].file_size == 4096 and hits[0].other_hashes["md5"].startswith("0123")
    assert hits[0].download_url.endswith("/download") and hits[0].file_name == "TP.MS338.PB801_V1.2.bin"


# ---- matching ---------------------------------------------------------------------------------------
def _hit(**kw):
    base = dict(provider="GitHub", source_type="github", title="", url="https://github.com/a/b")
    base.update(kw)
    return SearchHit(**base)


def test_find_identifier():
    assert matching.find_identifier("Firmware for TP.MS338.PB801 board", "TP.MS338.PB801") == "exact"
    assert matching.find_identifier("UA55AU7000KXXM_T-KTM2.zip", "UA55AU7000") == "variant"
    assert matching.find_identifier("XUA55AU70001234", "UA55AU7000") is None
    assert matching.find_identifier("ua55au7ooo", "UA55AU7000") == "exact"          # OCR-folded
    assert matching.find_identifier("abc", "AB") is None


def test_search_result_never_verified_even_official_with_hash():
    c = SearchCriteria(manufacturer="Samsung", model_number="UA55AU7000", mainboard="BN41-02635A")
    h = _hit(source_type="official", title="UA55AU7000 BN41-02635A firmware", url="https://www.samsung.com/fw.zip",
             sha256="b" * 64, file_name="fw.zip", download_url="https://www.samsung.com/fw.zip", raw={"kind": "web"})
    m = matching.evaluate(h, c)
    assert m.verdict == "HIGH CONFIDENCE MATCH" and m.verification_status.startswith("search result only")


def test_weak_identifiers_capped_and_insufficient():
    c = SearchCriteria(model_number="UA55AU7000", soc="MSD6A648")
    m = matching.evaluate(_hit(title="msrv_msd6a648_touch", raw={"kind": "repository"}), c)
    assert m.verdict == "POSSIBLE MATCH" and m.score <= 30 and m.risk == "High"
    assert matching.evaluate(_hit(title="unrelated project"), c).verdict == "INSUFFICIENT INFORMATION"
    assert matching.evaluate(_hit(title="anything"), SearchCriteria()).verdict == "INSUFFICIENT INFORMATION"


def test_risk_keywords_downgrade_and_critical():
    c = SearchCriteria(model_number="UA55AU7000", mainboard="BN41-02635A")
    m = matching.evaluate(_hit(title="UA55AU7000 BN41-02635A firmware decrypt keys"), c)
    assert m.verdict == "POSSIBLE MATCH" and m.risk == "Critical"


def test_analysis_based_verdicts():
    c = SearchCriteria(model_number="TESTTV55", architecture="ARM (32-bit)")
    h = _hit(title="update.bin", file_name="update.bin", sha256="c" * 64)
    good = [{"attribute": "cpu_architecture", "value": "ARM (32-bit)", "confidence": 0.9},
            {"attribute": "product_model", "value": "TESTTV55", "confidence": 0.9}]
    ok_dl = {"sha256": "c" * 64, "expected_sha256": "c" * 64, "https": True, "official": False}
    assert matching.evaluate(h, c, ok_dl, good).verdict == "VERIFIED MATCH"
    assert matching.evaluate(h, c, None, good).verdict == "HIGH CONFIDENCE MATCH"      # not downloaded/verified
    nohash = {"sha256": "c" * 64, "expected_sha256": None, "https": True, "official": False}
    assert matching.evaluate(h, c, nohash, good).verdict == "HIGH CONFIDENCE MATCH"     # integrity not established
    bad_arch = [{"attribute": "cpu_architecture", "value": "MIPS", "confidence": 0.9}]
    assert matching.evaluate(h, c, ok_dl, bad_arch).verdict == "INCOMPATIBLE"
    other = [{"attribute": "product_model", "value": "OTHERTV43", "confidence": 0.9}]
    assert matching.evaluate(h, c, ok_dl, other).verdict == "INCOMPATIBLE"
    mism = {"sha256": "d" * 64, "expected_sha256": "c" * 64, "https": True, "official": False}
    r = matching.evaluate(h, c, mism, good)
    assert r.verdict == "INCOMPATIBLE" and "DOES NOT MATCH" in r.verification_status


# ---- engine -------------------------------------------------------------------------------------------
def _github_routes(sess, payload: bytes):
    sha = hashlib.sha256(payload).hexdigest()
    sess.add("GET", "api.github.com/search/repositories", FakeResponse(200, json_data={"items": [
        github_repo("acme/tv-fw", "TESTTV55 firmware for TP.MS338.PB801"),
        github_repo("someone/keys", "TESTTV55 decrypt keys collection")]}))
    sess.add("GET", "api.github.com/repos/acme/tv-fw/releases", FakeResponse(200, json_data=[github_release(
        "acme/tv-fw", "v2.0", [("TESTTV55_v2.0.bin", len(payload), f"sha256:{sha}")])]))
    sess.add("GET", "api.github.com/repos/someone/keys/releases", FakeResponse(200, json_data=[]))
    sess.add("GET", "gitlab.com/api/v4/projects", FakeResponse(200, json_data=[
        {"id": 7, "path_with_namespace": "mirror/tv-fw", "web_url": "https://gitlab.com/mirror/tv-fw",
         "description": "TESTTV55", "last_activity_at": "2026-01-01T00:00:00Z"}]))
    sess.add("GET", "gitlab.com/api/v4/projects/7/releases", FakeResponse(500, b"boom"))
    sess.add("GET", "github.com/acme/tv-fw/releases/download", FakeResponse(200, payload,
                                                                            headers={"Content-Type": "application/octet-stream"}))
    return sha


def test_engine_search_rank_dedupe_history(online):
    ctx, sess = online
    _github_routes(sess, b"fw")
    p = ctx.projects.create(TVProject(name="t", model_number="TESTTV55", mainboard="TP.MS338.PB801"))
    with pytest.raises(ValueError):
        ctx.finder.search(SearchCriteria())
    c = SearchCriteria(model_number="TESTTV55", mainboard="TP.MS338.PB801")
    sid = ctx.finder.search(c, p.id, ["GitHub", "GitLab"])
    rows = ctx.finder.results(sid)
    assert rows and all(r["searched_at"] and r["url"] for r in rows)
    order = [matching.VERDICTS.index(r["match_status"]) for r in rows]
    assert order == sorted(order)                                         # ranked by verdict
    asset = [r for r in rows if r["file_name"] == "TESTTV55_v2.0.bin"]
    assert len(asset) == 1                                                # same asset from several queries → one row
    assert asset[0]["match_status"] == "HIGH CONFIDENCE MATCH" and asset[0]["sha256"]
    keys = [r for r in rows if r["title"] == "someone/keys"][0]
    assert keys["risk_assessment"].startswith("Critical")
    sess_row = ctx.finder.sessions(p.id)[0]
    assert sess_row["status"] == "completed" and "GitLab" in json.loads(sess_row["errors_json"])   # release 500 noted
    assert ctx.db.scalar("SELECT COUNT(*) FROM scan_sessions WHERE project_id=? AND session_type='firmware_search'", (p.id,)) == 1


def test_download_verify_import_and_verified_after_analysis(online, tmp_path):
    ctx, sess = online
    f = tmp_path / "TESTTV55_v2.0.bin"
    fb.composite(f)                                       # contains ro.product.model=TESTTV55, ARM uImage
    sha = _github_routes(sess, f.read_bytes())
    p = ctx.projects.create(TVProject(name="t", model_number="TESTTV55", mainboard="TP.MS338.PB801"))
    sid = ctx.finder.search(SearchCriteria(model_number="TESTTV55", mainboard="TP.MS338.PB801",
                                           architecture="ARM (32-bit)"), p.id, ["GitHub"])
    rid = [r for r in ctx.finder.results(sid) if r["file_name"] == "TESTTV55_v2.0.bin"][0]["id"]
    out = ctx.finder.download(rid, analyze=True)
    assert out["sha256"] == sha and out["expected_sha256"] == sha
    rec = ctx.library.get(out["firmware_id"])
    assert rec.category == "Community" and rec.download_url.endswith("TESTTV55_v2.0.bin") and rec.project_id == p.id
    r = ctx.finder.result(rid)
    assert r["match_status"] == "VERIFIED MATCH" and "matches the value published" in r["verification_status"]
    assert ctx.db.query_one("SELECT status FROM firmware_downloads WHERE result_id=?", (rid,))[0] == "completed"


def test_download_hash_mismatch_quarantined(online, tmp_path):
    ctx, sess = online
    _github_routes(sess, b"expected content")
    sess.add("GET", "github.com/acme/tv-fw/releases/download", FakeResponse(200, b"tampered content",
                                                                            headers={"Content-Type": "application/octet-stream"}))
    sid = ctx.finder.search(SearchCriteria(model_number="TESTTV55"), None, ["GitHub"])
    rid = [r for r in ctx.finder.results(sid) if r["file_name"]][0]["id"]
    n_before = len(ctx.library.list())
    with pytest.raises(DownloadRefused, match="mismatch"):
        ctx.finder.download(rid)
    assert len(ctx.library.list()) == n_before
    q = ctx.config.data_dir / "storage" / "downloads" / "quarantine"
    assert any(q.iterdir())
    assert "DOES NOT MATCH" in ctx.finder.result(rid)["verification_status"]


def test_download_refusals(online):
    ctx, sess = online
    _github_routes(sess, b"x")
    sid = ctx.finder.search(SearchCriteria(model_number="TESTTV55"), None, ["GitHub"])
    repo = [r for r in ctx.finder.results(sid) if not r["download_url"]][0]
    with pytest.raises(DownloadRefused, match="not a downloadable file"):
        ctx.finder.download(repo["id"])
    asset = [r for r in ctx.finder.results(sid) if r["download_url"]][0]
    ctx.db.execute("UPDATE firmware_search_results SET distribution_status='unknown' WHERE id=?", (asset["id"],))
    with pytest.raises(DownloadRefused, match="rights"):
        ctx.finder.download(asset["id"])
    ctx.db.execute("UPDATE firmware_search_results SET distribution_status=NULL, sha256=NULL WHERE id=?", (asset["id"],))
    sess.add("GET", "github.com/acme/tv-fw/releases/download", FakeResponse(200, b"<html>login</html>",
                                                                            headers={"Content-Type": "text/html"}))
    with pytest.raises(DownloadRefused, match="HTML page"):
        ctx.finder.download(asset["id"])
    ctx.config.set("finder.max_download_bytes", 10)
    sess.add("GET", "github.com/acme/tv-fw/releases/download", FakeResponse(200, b"x" * 100))
    with pytest.raises(DownloadRefused, match="limit"):
        ctx.finder.download(asset["id"])


def test_malware_scanner_threat_quarantines(online, tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("fake clamscan uses a POSIX shell script")
    ctx, sess = online
    _github_routes(sess, b"payload")
    fake = tmp_path / "bin" / "clamscan"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\necho 'FOUND Eicar-Test'\nexit 1\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    sid = ctx.finder.search(SearchCriteria(model_number="TESTTV55"), None, ["GitHub"])
    rid = [r for r in ctx.finder.results(sid) if r["download_url"]][0]["id"]
    with pytest.raises(DownloadRefused, match="threat"):
        ctx.finder.download(rid)
    assert ctx.db.query_one("SELECT status FROM firmware_downloads WHERE result_id=?", (rid,))[0] == "quarantined"


# ---- secrets ---------------------------------------------------------------------------------------------
def test_secrets_without_secure_backend_stay_in_memory(ctx):
    from keyring.backends import fail
    s = SecretStore(backend=fail.Keyring())
    assert not s.secure
    assert "session memory" in s.set("github_token", "ghp_abcdefghijk")
    assert s.get("github_token") == "ghp_abcdefghijk" and s.mask("ghp_abcdefghijk") == "ghp_…jk"
    ctx.config.save()
    assert "ghp_" not in ctx.config.settings_path.read_text()
    assert not any("ghp_" in str(e) for e in ctx.audit.entries(limit=1000))


def test_secrets_with_keyring_backend():
    from keyring.backend import KeyringBackend

    class MemoryKeyring(KeyringBackend):
        priority = 1
        store = {}

        def set_password(self, s, u, p):
            self.store[(s, u)] = p

        def get_password(self, s, u):
            return self.store.get((s, u))

        def delete_password(self, s, u):
            self.store.pop((s, u), None)
    kr = MemoryKeyring()
    s = SecretStore(backend=kr)
    assert s.secure and s.set("gitlab_token", "glpat-xyz") == "credential store"
    assert SecretStore(backend=kr).get("gitlab_token") == "glpat-xyz"    # persisted in the backend
    s.set("gitlab_token", "")
    assert s.get("gitlab_token") is None


# ---- reports -----------------------------------------------------------------------------------------------
def test_search_reports(online):
    from pypdf import PdfReader
    ctx, sess = online
    _github_routes(sess, b"x")
    sid = ctx.finder.search(SearchCriteria(model_number="TESTTV55"), None, ["GitHub"])
    R = ctx.search_reports
    text = " ".join(p.extract_text() for p in PdfReader(R.generate_pdf(sid)).pages)
    assert "Firmware Search Report" in text and "NOT a verified firmware" in text and "acme/tv-fw" in text
    js = json.loads(R.export_json(sid).read_text(encoding="utf-8"))
    assert js["session"]["criteria"]["model_number"] == "TESTTV55" and js["results"][0]["match_details"]["verdict"]
    assert "match_status" in R.export_csv(sid).read_text(encoding="utf-8-sig").splitlines()[0]


# ---- real network (skipped without connectivity) ------------------------------------------------------------
def _net(host):
    if os.environ.get("TVIS_NO_NETWORK"):
        return False
    try:
        socket.create_connection((host, 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _net("api.github.com"), reason="no network access to api.github.com")
def test_real_github_search(ctx):
    ctx.config.set("network.offline_mode", False)
    sid = ctx.finder.search(SearchCriteria(manufacturer=None, model_number=None, soc="MStar", mainboard=None,
                                           firmware_filename="mstar tv firmware"), None, ["GitHub"], max_queries=1)
    rows = ctx.finder.results(sid)
    assert rows, ctx.finder.sessions()[0]["errors_json"]
    assert all(r["url"].startswith("https://github.com/") for r in rows)
    assert all(r["match_status"] != "VERIFIED MATCH" for r in rows)


@pytest.mark.skipif(not _net("gitlab.com"), reason="no network access to gitlab.com")
def test_real_gitlab_search(ctx):
    ctx.config.set("network.offline_mode", False)
    sid = ctx.finder.search(SearchCriteria(firmware_filename="mstar-bin-tool"), None, ["GitLab"], max_queries=1)
    rows = ctx.finder.results(sid)
    assert any("mstar-bin-tool" in r["title"] for r in rows)
