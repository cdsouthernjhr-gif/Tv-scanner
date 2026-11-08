"""Universal Firmware Search Engine.

search()      parallel provider queries → URL validation → de-duplication →
              matching/ranking → stored in search history with timestamps.
download()    only URLs the source itself returned; size limit; SHA-256 while
              streaming; compared with the published hash; malware scan;
              hash mismatch or threat → quarantine (never imported).
reevaluate()  after the downloaded file was analysed, the match is recomputed
              with the analysis (only then can a result become VERIFIED).
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

from app.modules.firmware_finder import matching
from app.modules.firmware_finder.criteria import SearchCriteria, build_queries
from app.modules.firmware_finder.http import HttpClient, OfflineError, UrlRejected, normalize_url, validate_url
from app.modules.firmware_finder.providers.archive import ArchiveSearchProvider
from app.modules.firmware_finder.providers.base import (ProviderUnavailable, SearchHit, file_format, official_brand)
from app.modules.firmware_finder.providers.github import GitHubProvider, OpenSourceFirmwareProvider
from app.modules.firmware_finder.providers.gitlab import GitLabProvider
from app.modules.firmware_finder.providers.websearch import (CommunitySearchProvider, OfficialManufacturerProvider,
                                                             SourceForgeProvider, TechnicalDocumentationProvider)
from app.modules.firmware_library.library import DuplicateFirmware
from app.security import malware_scan
from app.security.file_protection import safe_component

log = logging.getLogger(__name__)
PROVIDER_CLASSES = [OfficialManufacturerProvider, GitHubProvider, GitLabProvider, OpenSourceFirmwareProvider,
                    SourceForgeProvider, ArchiveSearchProvider, CommunitySearchProvider, TechnicalDocumentationProvider]
VERDICT_RANK = {v: i for i, v in enumerate(matching.VERDICTS)}
API_DOWNLOAD_SOURCES = {"github", "gitlab", "archive", "open_source"}


class DownloadRefused(Exception):
    pass


class FirmwareFinder:
    def __init__(self, config, db, audit, library, firmware_analyzer, secrets, http: HttpClient | None = None):
        self.config, self.db, self.audit = config, db, audit
        self.library, self.analyzer, self.secrets = library, firmware_analyzer, secrets
        self.http = http or HttpClient(config)
        self._providers = None

    # ---- providers ------------------------------------------------------------------------
    def providers(self):
        if self._providers is None:
            self._providers = [cls(self.http, self.secrets, self.config) for cls in PROVIDER_CLASSES]
        return self._providers

    def provider_status(self) -> list[dict]:
        out = []
        for p in self.providers():
            ok, reason = p.availability()
            if not self.http.online:
                ok, reason = False, "offline mode"
            out.append({"name": p.name, "available": ok, "reason": reason, "description": p.description,
                        "status": dict(p.status)})
        return out

    # ---- search -----------------------------------------------------------------------------
    def search(self, criteria: SearchCriteria, project_id: int | None = None, provider_names: list[str] | None = None,
               max_queries: int = 6) -> int:
        if criteria.is_empty():
            raise ValueError("No search criteria — enter at least a model, mainboard, chassis or SoC.")
        if not self.http.online:
            raise OfflineError("Offline mode is on — enable online search first.")
        queries = build_queries(criteria, max_queries)
        provs = [p for p in self.providers() if provider_names is None or p.name in provider_names]
        sid = self.db.execute("INSERT INTO search_sessions(project_id, criteria_json, providers, queries_json)"
                              " VALUES (?,?,?,?)", (project_id, json.dumps(criteria.as_dict()),
                                                    ", ".join(p.name for p in provs),
                                                    json.dumps([asdict(q) for q in queries])))
        self.audit.record("finder.search.start", "search_session", sid, project_id=project_id,
                          queries=[q.text for q in queries])
        errors: dict[str, list[str]] = {}

        def run_provider(p):
            hits, errs = [], []
            for k in [k for k in p.status if k.endswith("_errors")]:
                p.status.pop(k)                      # warnings are per search
            ok, reason = p.availability()
            if not ok:
                return hits, [f"skipped: {reason}"]
            for q in queries:
                if not p.accepts(q):
                    continue
                try:
                    hits += p.search(q, criteria)
                except ProviderUnavailable as exc:
                    errs.append(f"skipped: {exc}")
                    break
                except Exception as exc:
                    errs.append(f"{q.text!r}: {str(exc)[:200]}")
                    if "rate limit" in str(exc).lower():
                        break
            for k, v in p.status.items():
                if k.endswith("_errors"):
                    errs += [f"warning ({k.replace('_errors', '')}): {x}" for x in v[:5]]
            return hits, errs

        all_hits: list[SearchHit] = []
        with ThreadPoolExecutor(max_workers=max(1, len(provs))) as pool:
            for p, (hits, errs) in zip(provs, pool.map(run_provider, provs)):
                all_hits += hits
                if errs:
                    errors[p.name] = errs
        unique = self._dedupe(all_hits, errors)
        rows = []
        for h in unique:
            m = matching.evaluate(h, criteria)
            rows.append((h, m))
        rows.sort(key=lambda hm: (VERDICT_RANK[hm[1].verdict], -hm[1].score, -hm[0].query_weight))
        with self.db.transaction() as tx:
            for h, m in rows:
                tx.execute(
                    "INSERT INTO firmware_search_results(project_id, session_id, query, provider, title, url, version,"
                    " file_size, published_at, sha256, compatibility_score, match_status, risk_assessment, raw_json,"
                    " source_type, source_site, description, file_name, file_format, download_url, manufacturer,"
                    " supported_models, supported_mainboards, sha256_source, signature_status, verification_status,"
                    " distribution_status, match_details_json, url_key)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (project_id, sid, h.query, h.provider, h.title, h.url, h.version, h.file_size, h.published_at,
                     h.sha256, m.score, m.verdict, f"{m.risk}: " + "; ".join(m.risk_reasons),
                     json.dumps({**h.raw, "other_hashes": h.other_hashes, "found_by": h.raw.get("found_by")}),
                     h.source_type, h.site, h.description[:2000], h.file_name, file_format(h.file_name),
                     h.download_url, h.manufacturer or official_brand(h.url),
                     _mentioned(h, criteria, ("model_number", "product_code")),
                     _mentioned(h, criteria, ("mainboard", "chassis")), h.sha256_source, m.signature_status,
                     m.verification_status, h.distribution_status, json.dumps(m.as_dict()),
                     normalize_url(h.download_url or h.url)))
            tx.execute("UPDATE search_sessions SET status='completed', result_count=?, errors_json=?,"
                       " finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                       (len(rows), json.dumps(errors) if errors else None, sid))
        if project_id:
            self.db.execute("INSERT INTO scan_sessions(project_id, session_type, summary, finished_at)"
                            " VALUES (?, 'firmware_search', ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                            (project_id, f"Firmware search #{sid}: {len(rows)} results"))
        self.audit.record("finder.search.finish", "search_session", sid, results=len(rows),
                          errors=sum(len(v) for v in errors.values()))
        return sid

    def _dedupe(self, hits: list[SearchHit], errors: dict) -> list[SearchHit]:
        best: dict[str, SearchHit] = {}
        for h in hits:
            try:
                validate_url(h.url)
                if h.download_url:
                    validate_url(h.download_url)
            except UrlRejected as exc:
                errors.setdefault("URL validation", []).append(str(exc))
                continue
            key = normalize_url(h.download_url or h.url) + "|" + (h.file_name or "")
            if h.sha256:
                key = "sha256:" + h.sha256.lower()
            if key in best:
                kept = best[key]
                kept.raw.setdefault("found_by", [kept.provider])
                if h.provider not in kept.raw["found_by"]:
                    kept.raw["found_by"].append(h.provider)
                if h.query_weight > kept.query_weight:
                    kept.query, kept.query_kind, kept.query_weight = h.query, h.query_kind, h.query_weight
            else:
                best[key] = h
        return list(best.values())

    # ---- history / results -----------------------------------------------------------------------
    def sessions(self, project_id: int | None = None) -> list[dict]:
        if project_id is None:
            rows = self.db.query("SELECT * FROM search_sessions ORDER BY id DESC")
        else:
            rows = self.db.query("SELECT * FROM search_sessions WHERE project_id=? ORDER BY id DESC", (project_id,))
        return [dict(r) for r in rows]

    def results(self, session_id: int) -> list[dict]:
        rows = [dict(r) for r in self.db.query("SELECT * FROM firmware_search_results WHERE session_id=?", (session_id,))]
        rows.sort(key=lambda r: (VERDICT_RANK.get(r["match_status"], 9), -(r["compatibility_score"] or 0), r["id"]))
        return rows

    def result(self, result_id: int) -> dict:
        r = self.db.query_one("SELECT * FROM firmware_search_results WHERE id=?", (result_id,))
        if r is None:
            raise KeyError(result_id)
        return dict(r)

    def criteria_for(self, result_id: int) -> SearchCriteria:
        r = self.result(result_id)
        s = self.db.query_one("SELECT criteria_json FROM search_sessions WHERE id=?", (r["session_id"],))
        return SearchCriteria(**json.loads(s[0]))

    # ---- download ----------------------------------------------------------------------------------
    def download(self, result_id: int, accept_unknown_distribution: bool = False, analyze: bool = False) -> dict:
        r = self.result(result_id)
        url = r["download_url"]
        if not url:
            raise DownloadRefused("This result is a page or repository, not a downloadable file. Use 'View Source'.")
        did = self.db.execute("INSERT INTO firmware_downloads(result_id, url, status, expected_sha256)"
                              " VALUES (?,?,?,?)", (result_id, url, "started", r["sha256"]))

        def finish(status, **kw):
            sets = ", ".join(f"{k}=?" for k in kw)
            self.db.execute(f"UPDATE firmware_downloads SET status=?{', ' + sets if sets else ''},"
                            " finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                            (status, *kw.values(), did))
            self.audit.record("finder.download", "firmware_search_result", result_id, status=status, url=url,
                              **{k: v for k, v in kw.items() if k != "message"})

        if r["distribution_status"] == "unknown" and not accept_unknown_distribution:
            finish("refused", message="redistribution rights unknown")
            raise DownloadRefused("Redistribution rights of this item are unknown. Confirm you are entitled to obtain "
                                  "this file before downloading.")
        dl_dir = self.config.data_dir / "storage" / "downloads"
        part_dir, q_dir = dl_dir / "partial", dl_dir / "quarantine"
        part_dir.mkdir(parents=True, exist_ok=True)
        q_dir.mkdir(parents=True, exist_ok=True)
        name = safe_component(r["file_name"] or unquote(urlsplit(url).path.rsplit("/", 1)[-1]) or "download.bin")
        # unique folder, real file name: the library keeps the source's file name (TV updaters and
        # documented package names depend on it)
        tmp_dir = part_dir / f"{result_id}_{int(time.time() * 1000)}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp = tmp_dir / name
        limit = int(self.config.get("finder.max_download_bytes", 8 * 1024 ** 3))
        respect_robots = r["source_type"] not in API_DOWNLOAD_SOURCES
        h = hashlib.sha256()
        n = 0
        try:
            resp = self.http.request("GET", url, stream=True, respect_robots=respect_robots)
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code} {resp.reason}")
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit() and int(clen) > limit:
                raise DownloadRefused(f"File is {int(clen):,} bytes — above the configured limit {limit:,}")
            ctype = resp.headers.get("Content-Type", "")
            if ctype.startswith("text/html"):
                raise DownloadRefused("Server returned an HTML page instead of a file (login, consent or "
                                      "landing page). Open the source in a browser instead.")
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_content(1 << 20):
                    n += len(chunk)
                    if n > limit:
                        raise DownloadRefused(f"Download exceeded the size limit ({limit:,} bytes)")
                    h.update(chunk)
                    fh.write(chunk)
        except (DownloadRefused, OfflineError) as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            finish("refused", message=str(exc))
            raise
        except Exception as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            finish("failed", message=str(exc)[:300])
            raise RuntimeError(f"Download failed: {exc}") from exc
        digest = h.hexdigest()
        expected = (r["sha256"] or "").lower() or None
        if expected and digest != expected:
            q = q_dir / f"{tmp_dir.name}_{tmp.name}"
            shutil.move(str(tmp), q)
            finish("hash_mismatch", bytes=n, sha256=digest, message=f"quarantined at {q}")
            self.db.execute("UPDATE firmware_search_results SET verification_status=? WHERE id=?",
                            ("downloaded; SHA-256 DOES NOT MATCH the published value (quarantined)", result_id))
            raise DownloadRefused(f"SHA-256 mismatch: published {expected}, downloaded {digest}. "
                                  "File quarantined and NOT added to the library.")
        scan = malware_scan.scan_file(str(tmp))
        if scan.status == "threat":
            q = q_dir / f"{tmp_dir.name}_{tmp.name}"
            shutil.move(str(tmp), q)
            finish("quarantined", bytes=n, sha256=digest, malware_scan=f"{scan.scanner}: threat",
                   message=scan.detail[:300])
            raise DownloadRefused(f"Malware scanner ({scan.scanner}) reported a threat. File quarantined.")

        official = bool(official_brand(url)) or r["source_type"] == "official"
        project = None
        if r["project_id"]:
            try:
                project = self.db.query_one("SELECT * FROM tv_projects WHERE id=?", (r["project_id"],))
            except Exception:
                project = None
        try:
            rec = self.library.import_file(
                tmp, category="Official" if official else "Community",
                manufacturer=(project["manufacturer"] if project else None) or r["manufacturer"],
                model_number=project["model_number"] if project else None,
                mainboard=project["mainboard"] if project else None, version=r["version"],
                project_id=r["project_id"], download_url=url, source_type=r["provider"],
                notes=f"Downloaded from search result #{result_id} ({r['provider']}, {r['url']}). "
                      f"Published SHA-256: {expected or 'none'}.")
            fid = rec.id
        except DuplicateFirmware as dup:
            fid = dup.record.id
        finally:
            tmp.unlink(missing_ok=True)
            shutil.rmtree(tmp_dir, ignore_errors=True)
        self.db.execute("UPDATE firmware_files SET downloaded_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),"
                        " download_url=COALESCE(download_url, ?) WHERE id=?", (url, fid))
        finish("completed", bytes=n, sha256=digest, malware_scan=f"{scan.scanner or 'none'}: {scan.status}",
               firmware_id=fid)
        self.db.execute("UPDATE firmware_search_results SET firmware_id=?, downloaded_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')"
                        " WHERE id=?", (fid, result_id))
        if expected and digest == expected:
            # independent check: the file equals the hash published by its source → library status 'verified'
            self.db.execute("UPDATE firmware_files SET verification_status='verified',"
                            " last_integrity_check=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?", (fid,))
            self.audit.record("firmware.verified", "firmware_file", fid, reason="SHA-256 equals value published by "
                              f"{r['provider']}", search_result=result_id)
        self._store_download_info(result_id, {"sha256": digest, "expected_sha256": expected,
                                              "https": url.lower().startswith("https://"), "official": official,
                                              "malware_scan": scan.status})
        if analyze:
            self.analyzer.analyze(fid)
        res = self.reevaluate(result_id)
        return {"firmware_id": fid, "sha256": digest, "bytes": n, "expected_sha256": expected,
                "malware_scan": f"{scan.scanner or 'none'}: {scan.status}", "verdict": res.verdict,
                "verification": res.verification_status}

    def _store_download_info(self, result_id: int, info: dict) -> None:
        raw = json.loads(self.result(result_id)["raw_json"] or "{}")
        raw["download"] = info
        self.db.execute("UPDATE firmware_search_results SET raw_json=? WHERE id=?", (json.dumps(raw), result_id))

    # ---- re-evaluation ---------------------------------------------------------------------------------
    def reevaluate(self, result_id: int) -> matching.MatchResult:
        r = self.result(result_id)
        raw = json.loads(r["raw_json"] or "{}")
        hit = SearchHit(r["provider"], r["source_type"], r["title"], r["url"], r["query"], "", 0.5,
                        r["description"] or "", file_name=r["file_name"], file_size=r["file_size"],
                        download_url=r["download_url"], version=r["version"], published_at=r["published_at"],
                        sha256=r["sha256"], distribution_status=r["distribution_status"], raw=raw)
        analysis = None
        if r["firmware_id"]:
            run = self.analyzer.latest_run(r["firmware_id"])
            if run:
                analysis = self.analyzer.metadata(run["id"])
        m = matching.evaluate(hit, self.criteria_for(result_id), raw.get("download"), analysis)
        self.db.execute("UPDATE firmware_search_results SET match_status=?, compatibility_score=?, risk_assessment=?,"
                        " signature_status=?, verification_status=?, match_details_json=? WHERE id=?",
                        (m.verdict, m.score, f"{m.risk}: " + "; ".join(m.risk_reasons), m.signature_status,
                         m.verification_status, json.dumps(m.as_dict()), result_id))
        self.audit.record("finder.reevaluate", "firmware_search_result", result_id, verdict=m.verdict)
        return m


def _mentioned(hit: SearchHit, c: SearchCriteria, fields) -> str | None:
    found = [getattr(c, f) for f in fields if getattr(c, f) and matching.find_identifier(hit.text(), getattr(c, f))]
    return ", ".join(found) if found else None
