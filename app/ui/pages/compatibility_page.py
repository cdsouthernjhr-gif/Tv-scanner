"""Compatibility Analyzer page."""
from __future__ import annotations

import logging

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from app.modules.reports.upgrade_report import VERDICT_COLOR
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id

log = logging.getLogger(__name__)


class CompatibilityPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.last_id = None
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Compatibility Analyzer"))
        lay.addWidget(notice(
            "Evaluates an analysed firmware against everything known about the TV: identification, confirmed hardware, "
            "software facts and the TV's own (baseline) firmware. Every criterion shows the evidence; unproven criteria "
            "stay 'unknown'. Any hard mismatch makes the firmware INCOMPATIBLE."))
        r = QHBoxLayout()
        r.addWidget(QLabel("TV project:"))
        self.project = ProjectSelector(ctx)
        self.project.currentIndexChanged.connect(self._load_firmware)
        r.addWidget(self.project, 2)
        r.addWidget(QLabel("Candidate firmware:"))
        self.candidate = QComboBox()
        r.addWidget(self.candidate, 2)
        r.addWidget(QLabel("Baseline (TV's own):"))
        self.baseline = QComboBox()
        r.addWidget(self.baseline, 2)
        b = QPushButton("Evaluate")
        b.clicked.connect(self._guard(self.evaluate))
        r.addWidget(b)
        rep = QPushButton("Compatibility Report (PDF)")
        rep.clicked.connect(self._guard(self._report))
        r.addWidget(rep)
        lay.addLayout(r)
        self.verdict = QLabel("—")
        self.verdict.setStyleSheet("font-size: 15pt; font-weight: 700;")
        lay.addWidget(self.verdict)
        self.reasons = QLabel()
        self.reasons.setWordWrap(True)
        lay.addWidget(self.reasons)
        self.table = make_table(["Criterion", "TV", "Firmware", "Status", "Evidence"])
        lay.addWidget(self.table, 3)
        lay.addWidget(QLabel("History (double-click to show)"))
        self.history = make_table(["ID", "Firmware", "Verdict", "Score", "Baseline", "Time"])
        self.history.doubleClicked.connect(self._guard(lambda: self.show(selected_id(self.history))))
        lay.addWidget(self.history, 1)
        self.refresh()

    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Compatibility action failed")
                QMessageBox.warning(self, "Compatibility Analyzer", str(exc))
        return run

    def refresh(self):
        self.project.reload()
        self._load_firmware()

    def _load_firmware(self, *_):
        pid = self.project.currentData()
        fws = self.ctx.library.list()
        for combo, auto in ((self.candidate, None), (self.baseline, "auto (Original firmware of the project)")):
            keep = combo.currentData()
            combo.clear()
            if auto:
                combo.addItem(auto, None)
            for f in fws:
                analysed = "analysed" if self.ctx.firmware.latest_run(f.id) else "NOT analysed"
                combo.addItem(f"#{f.id} {f.original_filename} [{f.category}, {analysed}]", f.id)
            if keep is not None:
                combo.setCurrentIndex(max(0, combo.findData(keep)))
        if pid is not None:
            hist = self.ctx.compatibility.history(pid)
            fill_table(self.history, [[h["id"], h["original_filename"], h["verdict"], int(h["score"] or 0),
                                       h["baseline_firmware_id"], h["created_at"]] for h in hist],
                       ids=[h["id"] for h in hist])

    def evaluate(self):
        pid, fid = self.project.currentData(), self.candidate.currentData()
        if pid is None or fid is None:
            raise ValueError("Select a TV project and a candidate firmware")
        r = self.ctx.compatibility.evaluate(pid, fid, self.baseline.currentData())
        self.show(r.id)
        self._load_firmware()
        return r

    def show(self, cid):
        if cid is None:
            return
        c = self.ctx.compatibility.get(cid)
        self.last_id = cid
        self.verdict.setText(f"{c['verdict']}  (score {int(c['score'] or 0)})")
        self.verdict.setStyleSheet(f"font-size: 15pt; font-weight: 700; color: {VERDICT_COLOR[c['verdict']]};")
        self.reasons.setText("\n".join("• " + r for r in c["reasons"]))
        fill_table(self.table, [[x["criterion"] + (" (hard)" if x["hard"] and x["status"] == "mismatch" else ""),
                                 x["tv_value"], x["fw_value"], x["status"], x["evidence"]] for x in c["criteria"]])

    def _report(self):
        if self.last_id is None:
            raise ValueError("Evaluate first")
        path = self.ctx.upgrade_reports.compatibility_pdf(self.last_id)
        open_in_file_manager(path.parent)
