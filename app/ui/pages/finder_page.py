"""Universal Firmware Finder page."""
from __future__ import annotations

import json
import logging

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from app.modules.firmware_finder.criteria import SearchCriteria, build_queries, from_project
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id
from app.ui.worker import run_async

log = logging.getLogger(__name__)
FIELDS = [("manufacturer", "Manufacturer"), ("model_number", "Model"), ("product_code", "Product code"),
          ("chassis", "Chassis"), ("mainboard", "Mainboard"), ("pcb_revision", "PCB revision"), ("soc", "SoC"),
          ("panel", "Panel"), ("firmware_version", "Firmware version"), ("firmware_build", "Build"),
          ("firmware_filename", "Firmware file name"), ("sha256", "SHA-256")]
RESULT_COLS = ["ID", "Verdict", "Score", "Risk", "Firmware name", "Version", "Manufacturer", "Supported models",
               "Supported mainboard", "Size", "Format", "Source website", "URL", "Published", "SHA-256",
               "Signature", "Verification"]


class FinderPage(QWidget):
    open_firmware = Signal(int)
    compare_firmware = Signal(int, int)

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.session_id: int | None = None
        self.sources: dict = {}
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Universal Firmware Finder"))
        lay.addWidget(notice(
            "Searches public, permitted sources through official APIs (GitHub, GitLab, Internet Archive) and, when "
            "configured, web search APIs restricted to manufacturer, community and documentation sites. Robots.txt "
            "and rate limits are respected; no login, CAPTCHA or paywall is bypassed. A search result is never "
            "'verified': that requires download, hash check and analysis."))
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx, allow_none=True)
        top.addWidget(self.project, 1)
        b_load = QPushButton("Load criteria from project")
        b_load.clicked.connect(self._guard(self.load_from_project))
        top.addWidget(b_load)
        self.online = QCheckBox("Online search enabled")
        self.online.toggled.connect(self._set_online)
        top.addWidget(self.online)
        lay.addLayout(top)

        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        grid = QGridLayout()
        self.inputs: dict[str, QLineEdit] = {}
        for i, (key, label) in enumerate(FIELDS):
            w = QLineEdit()
            w.setPlaceholderText("unknown")
            w.textChanged.connect(self._update_queries)
            self.inputs[key] = w
            grid.addWidget(QLabel(label), i, 0)
            grid.addWidget(w, i, 1)
        ll.addLayout(grid)
        ll.addWidget(QLabel("Queries that will be sent:"))
        self.queries = QPlainTextEdit()
        self.queries.setReadOnly(True)
        self.queries.setMaximumHeight(90)
        ll.addWidget(self.queries)
        ll.addWidget(QLabel("Providers:"))
        self.providers = QListWidget()
        ll.addWidget(self.providers, 1)
        self.btn_search = QPushButton("Search")
        self.btn_search.clicked.connect(self.search_async)
        ll.addWidget(self.btn_search)
        split.addWidget(left)

        right = QTabWidget()
        self.tabs = right
        rw = QWidget()
        rl = QVBoxLayout(rw)
        self.table = make_table(RESULT_COLS)
        self.table.itemSelectionChanged.connect(self._show_details)
        rl.addWidget(self.table, 3)
        br = QHBoxLayout()
        self.btn_view = QPushButton("View Source")
        self.btn_view.clicked.connect(self._guard(self._view_source))
        self.btn_dl = QPushButton("Download Firmware")
        self.btn_dl.clicked.connect(self._download_async)
        self.btn_an = QPushButton("Analyze Firmware")
        self.btn_an.clicked.connect(self._analyze_async)
        self.btn_cmp = QPushButton("Compare Firmware")
        self.btn_cmp.clicked.connect(self._guard(self._compare))
        self.btn_lib = QPushButton("Add to Firmware Library")
        self.btn_lib.clicked.connect(self._download_async)
        for b in (self.btn_view, self.btn_dl, self.btn_an, self.btn_cmp, self.btn_lib):
            br.addWidget(b)
        br.addStretch()
        rl.addLayout(br)
        self.details = make_table(["Criterion", "Expected", "Status", "Evidence"])
        rl.addWidget(self.details, 2)
        self.reasons = QLabel()
        self.reasons.setWordWrap(True)
        rl.addWidget(self.reasons)
        right.addTab(rw, "Results")
        hw = QWidget()
        hl = QVBoxLayout(hw)
        self.history = make_table(["Search", "Project", "Started (UTC)", "Status", "Results", "Providers", "Notes"])
        self.history.doubleClicked.connect(lambda: self.load_session(selected_id(self.history)))
        hl.addWidget(self.history, 1)
        hb = QHBoxLayout()
        for fmt in ("PDF", "CSV", "JSON"):
            b = QPushButton(f"Search report {fmt}")
            b.clicked.connect(self._guard(lambda _=False, f=fmt: self._report(f)))
            hb.addWidget(b)
        hb.addStretch()
        hl.addLayout(hb)
        right.addTab(hw, "Search history")
        split.addWidget(right)
        split.setSizes([380, 1000])
        lay.addWidget(split, 1)
        self.status = QLabel()
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.refresh()

    # ---- helpers -------------------------------------------------------------------------------
    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Finder action failed")
                QMessageBox.warning(self, "Firmware Finder", str(exc))
        return run

    def _set_online(self, on: bool):
        self.ctx.config.set("network.offline_mode", not on)
        try:
            self.ctx.config.save()
        except OSError:
            pass
        self.ctx.audit.record("settings.network", details=("online" if on else "offline"))
        self._load_providers()

    def refresh(self) -> None:
        self.project.reload()
        self.online.blockSignals(True)
        self.online.setChecked(not self.ctx.config.get("network.offline_mode", True))
        self.online.blockSignals(False)
        self._load_providers()
        self._load_history()
        self._update_queries()

    def _load_providers(self):
        checked = {self.providers.item(i).data(Qt.UserRole) for i in range(self.providers.count())
                   if self.providers.item(i).checkState() == Qt.Checked}
        first = self.providers.count() == 0
        self.providers.clear()
        for s in self.ctx.finder.provider_status():
            it = QListWidgetItem(f"{s['name']} — {s['reason']}")
            it.setData(Qt.UserRole, s["name"])
            it.setToolTip(s["description"])
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            on = s["available"] and (first or s["name"] in checked or not checked)
            it.setCheckState(Qt.Checked if on else Qt.Unchecked)
            if not s["available"]:
                it.setFlags(it.flags() & ~Qt.ItemIsEnabled)
            self.providers.addItem(it)

    def selected_providers(self) -> list[str]:
        return [self.providers.item(i).data(Qt.UserRole) for i in range(self.providers.count())
                if self.providers.item(i).checkState() == Qt.Checked]

    def criteria(self) -> SearchCriteria:
        c = SearchCriteria(**{k: (w.text().strip() or None) for k, w in self.inputs.items()})
        c.sources = {k: v for k, v in self.sources.items() if getattr(c, k)}
        for k in self.inputs:
            if getattr(c, k) and k not in c.sources:
                c.sources[k] = "entered by operator"
        return c

    def _update_queries(self, *_):
        qs = build_queries(self.criteria())
        self.queries.setPlainText("\n".join(f"[{q.kind}] {q.text}" for q in qs) or "(enter criteria)")

    def load_from_project(self):
        pid = self.project.currentData()
        if pid is None:
            raise ValueError("Select a project")
        c = from_project(self.ctx, pid)
        self.sources = dict(c.sources)
        for k, w in self.inputs.items():
            w.setText(getattr(c, k) or "")
            w.setToolTip(c.sources.get(k, ""))
        return c

    # ---- search --------------------------------------------------------------------------------------
    def search(self) -> int:
        sid = self.ctx.finder.search(self.criteria(), self.project.currentData(), self.selected_providers())
        self.load_session(sid)
        return sid

    def search_async(self):
        c, pid, provs = self.criteria(), self.project.currentData(), self.selected_providers()
        self.status.setText("Searching… (" + ", ".join(provs) + ")")
        run_async(lambda: self.ctx.finder.search(c, pid, provs),
                  lambda sid: (self.load_session(sid), self._load_providers()),
                  lambda msg: (self.status.setText("Search failed."), QMessageBox.warning(self, "Search", msg)),
                  busy=[self.btn_search])

    def load_session(self, sid):
        if sid is None:
            return
        self.session_id = sid
        rows = self.ctx.finder.results(sid)
        fill_table(self.table, [[r["id"], r["match_status"], int(r["compatibility_score"] or 0),
                                 (r["risk_assessment"] or "").split(":")[0], r["file_name"] or r["title"], r["version"],
                                 r["manufacturer"], r["supported_models"], r["supported_mainboards"],
                                 f"{r['file_size']:,}" if r["file_size"] else "", r["file_format"],
                                 r["source_site"], r["download_url"] or r["url"], (r["published_at"] or "")[:10],
                                 r["sha256"] or "", r["signature_status"], r["verification_status"]] for r in rows],
                   ids=[r["id"] for r in rows])
        sess = [s for s in self.ctx.finder.sessions() if s["id"] == sid][0]
        errs = json.loads(sess["errors_json"] or "{}")
        self.status.setText(f"Search #{sid}: {len(rows)} result(s)." +
                            (" Notes: " + " | ".join(f"{k}: {v[0]}" for k, v in errs.items())[:400] if errs else ""))
        self._load_history()
        self.tabs.setCurrentIndex(0)

    def _load_history(self):
        ss = self.ctx.finder.sessions()
        fill_table(self.history, [[s["id"], s["project_id"], s["started_at"], s["status"], s["result_count"],
                                   s["providers"], (s["errors_json"] or "")[:120]] for s in ss], ids=[s["id"] for s in ss])

    def _show_details(self):
        rid = selected_id(self.table)
        if rid is None:
            return
        r = self.ctx.finder.result(rid)
        m = json.loads(r["match_details_json"] or "{}")
        fill_table(self.details, [[c["criterion"], c["expected"], c["status"], c["evidence"]]
                                  for c in m.get("criteria", []) if c["status"] != "not_applicable"])
        self.reasons.setText(f"<b>{r['match_status']}</b> — " + "; ".join(m.get("reasons", [])) +
                             f"<br><b>Risk {m.get('risk')}</b>: " + "; ".join(m.get("risk_reasons", [])) +
                             f"<br>Description: {(r['description'] or '')[:300]}")

    # ---- actions ------------------------------------------------------------------------------------------
    def _rid(self):
        rid = selected_id(self.table)
        if rid is None:
            raise ValueError("Select a result")
        return rid

    def _view_source(self):
        QDesktopServices.openUrl(QUrl(self.ctx.finder.result(self._rid())["url"]))

    def download(self, rid: int, accept_unknown: bool = False, analyze: bool = False) -> dict:
        out = self.ctx.finder.download(rid, accept_unknown_distribution=accept_unknown, analyze=analyze)
        self.load_session(self.session_id)
        return out

    def _download_async(self):
        try:
            rid = self._rid()
        except ValueError as exc:
            QMessageBox.warning(self, "Download", str(exc))
            return
        r = self.ctx.finder.result(rid)
        if r["firmware_id"]:
            QMessageBox.information(self, "Already downloaded", f"In Firmware Library as #{r['firmware_id']}.")
            return
        accept = False
        if r["distribution_status"] == "unknown":
            accept = QMessageBox.question(
                self, "Distribution rights unknown",
                "The source does not state that redistribution is permitted.\n\nDownload only if you are entitled "
                "to obtain this file (e.g. you own the TV and the manufacturer provides it). Continue?") == QMessageBox.Yes
            if not accept:
                return
        if QMessageBox.question(self, "Download firmware",
                                f"Download from:\n{r['download_url'] or r['url']}\n\nThe file will be hashed, compared "
                                "with any published SHA-256, malware-scanned and stored read-only in the Firmware "
                                "Library. Nothing is installed or flashed.") != QMessageBox.Yes:
            return
        self.status.setText("Downloading…")
        run_async(lambda: self.ctx.finder.download(rid, accept_unknown_distribution=accept),
                  lambda out: (self.load_session(self.session_id), self.status.setText(
                      f"Downloaded → firmware #{out['firmware_id']} | SHA-256 {out['sha256'][:16]}… | "
                      f"{out['verification']} | malware scan: {out['malware_scan']} | verdict {out['verdict']}")),
                  lambda msg: (self.status.setText("Download not completed."),
                               QMessageBox.warning(self, "Download", msg)),
                  busy=[self.btn_dl, self.btn_lib])

    def _analyze_async(self):
        try:
            rid = self._rid()
        except ValueError as exc:
            QMessageBox.warning(self, "Analyze", str(exc))
            return
        fid = self.ctx.finder.result(rid)["firmware_id"]
        if not fid:
            QMessageBox.information(self, "Analyze", "Download the firmware first.")
            return
        self.status.setText("Analysing downloaded firmware…")

        def work():
            self.ctx.firmware.analyze(fid)
            return self.ctx.finder.reevaluate(rid)
        run_async(work, lambda m: (self.load_session(self.session_id),
                                   self.status.setText(f"Re-evaluated with analysis: {m.verdict} ({m.score})")),
                  lambda msg: QMessageBox.warning(self, "Analyze", msg), busy=[self.btn_an])

    def _compare(self):
        r = self.ctx.finder.result(self._rid())
        if not r["firmware_id"]:
            raise ValueError("Download the firmware first.")
        current = [f for f in self.ctx.library.list(project_id=r["project_id"]) if f.id != r["firmware_id"]] \
            if r["project_id"] else []
        if not current:
            raise ValueError("No other firmware of this project in the library to compare with.")
        self.compare_firmware.emit(current[-1].id, r["firmware_id"])

    def _report(self, fmt: str):
        if self.session_id is None:
            raise ValueError("Open a search first")
        R = self.ctx.search_reports
        path = {"PDF": R.generate_pdf, "CSV": R.export_csv, "JSON": R.export_json}[fmt](self.session_id)
        self.status.setText(f"Saved {path}")
        open_in_file_manager(path.parent)
