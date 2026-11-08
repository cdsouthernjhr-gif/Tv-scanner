"""Reports page: every report type of the specification in every export format."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from app.modules.reports.report_center import FORMATS, REPORT_TYPES
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import fill_table, make_table, notice, page_title, selected_id

log = logging.getLogger(__name__)


class ReportsPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Reports"))
        lay.addWidget(notice("All ten technical reports in PDF, XLSX, CSV, JSON and HTML. Each report shows dates, "
                             "sources, results and confidence; HTML embeds the evidence images. Every generated file is "
                             "hashed (SHA-256) and listed below."))
        r = QHBoxLayout()
        r.addWidget(QLabel("Report:"))
        self.rtype = QComboBox()
        for key, (title, _) in REPORT_TYPES.items():
            self.rtype.addItem(title, key)
        self.rtype.currentIndexChanged.connect(self._load_subjects)
        r.addWidget(self.rtype, 2)
        r.addWidget(QLabel("Subject:"))
        self.subject = QComboBox()
        r.addWidget(self.subject, 3)
        r.addWidget(QLabel("Format:"))
        self.fmt = QComboBox()
        for f in FORMATS:
            self.fmt.addItem(f.upper(), f)
        r.addWidget(self.fmt)
        b = QPushButton("Generate")
        b.clicked.connect(self._on_generate)
        r.addWidget(b)
        lay.addLayout(r)
        self.table = make_table(["ID", "Project", "Type", "Format", "Created (UTC)", "SHA-256", "Path"])
        self.table.doubleClicked.connect(self._on_open)
        lay.addWidget(self.table, 1)
        lay.addWidget(QLabel("Double-click a report to open it."))
        self.refresh()

    def _load_subjects(self, *_):
        keep = self.subject.currentData()
        self.subject.clear()
        for sid, label in self.ctx.report_center.subjects(self.rtype.currentData()):
            self.subject.addItem(label, sid)
        if keep is not None:
            self.subject.setCurrentIndex(max(0, self.subject.findData(keep)))

    def generate(self, rtype: str, subject_id: int, fmt: str) -> Path:
        out = self.ctx.report_center.generate(rtype, subject_id, fmt)
        self.refresh()
        return out

    # kept for compatibility with earlier callers/tests
    def generate_identification(self, project_id: int) -> Path:
        return self.generate("tv_identification", project_id, "pdf")

    def _on_generate(self) -> None:
        sid = self.subject.currentData()
        if sid is None:
            QMessageBox.warning(self, "Reports", "Nothing to report on yet for this report type.")
            return
        try:
            out = self.generate(self.rtype.currentData(), sid, self.fmt.currentData())
            if QMessageBox.question(self, "Report generated", f"{out}\n\nOpen it now?") == QMessageBox.Yes:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(out)))
        except Exception as exc:
            log.exception("Report generation failed")
            QMessageBox.critical(self, "Report failed", str(exc))

    def _on_open(self) -> None:
        rid = selected_id(self.table)
        if rid is None:
            return
        row = self.ctx.db.query_one("SELECT file_path FROM technical_reports WHERE id=?", (rid,))
        if row and Path(row[0]).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(row[0]))
        elif row:
            open_in_file_manager(Path(row[0]).parent)

    def refresh(self) -> None:
        self._load_subjects()
        reps = [dict(r) for r in self.ctx.db.query("SELECT * FROM technical_reports ORDER BY id DESC")]
        fill_table(self.table, [[r["id"], r["project_id"], r["report_type"], r["format"], r["created_at"],
                                 r["sha256"], r["file_path"]] for r in reps], ids=[r["id"] for r in reps])
