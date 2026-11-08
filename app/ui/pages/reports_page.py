from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtWidgets import QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id

log = logging.getLogger(__name__)


class ReportsPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Reports"))
        lay.addWidget(notice("Available: TV Identification Report (PDF) and Hardware Report (PDF, XLSX, CSV, "
                             "JSON — also from the Hardware Analyzer page). Firmware, search, compatibility and "
                             "upgrade reports are added with their modules in later phases."))
        row = QHBoxLayout()
        row.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx)
        row.addWidget(self.project, 1)
        self.btn_pdf = QPushButton("Generate TV Identification Report (PDF)")
        self.btn_pdf.clicked.connect(self._on_generate)
        row.addWidget(self.btn_pdf)
        self.btn_hw = QPushButton("Hardware Report (PDF)")
        self.btn_hw.clicked.connect(self._on_hw)
        row.addWidget(self.btn_hw)
        lay.addLayout(row)
        self.table = make_table(["ID", "Project", "Type", "Format", "Created (UTC)", "SHA-256", "Path"])
        self.table.doubleClicked.connect(self._on_open)
        lay.addWidget(self.table, 1)
        lay.addWidget(QLabel("Double-click a report to open it."))
        self.refresh()

    def generate(self, project_id: int) -> Path:
        out = self.ctx.reports.generate_identification_report(project_id)
        self.refresh()
        return out

    def _on_generate(self) -> None:
        pid = self.project.currentData()
        if pid is None:
            QMessageBox.warning(self, "No project", "Register a TV project first.")
            return
        try:
            out = self.generate(pid)
            QMessageBox.information(self, "Report generated", str(out))
        except Exception as exc:
            log.exception("Report generation failed")
            QMessageBox.critical(self, "Report failed", str(exc))

    def _on_hw(self) -> None:
        pid = self.project.currentData()
        if pid is None:
            QMessageBox.warning(self, "No project", "Register a TV project first.")
            return
        try:
            out = self.ctx.hardware_reports.generate_pdf(pid)
            self.refresh()
            QMessageBox.information(self, "Report generated", str(out))
        except Exception as exc:
            log.exception("Hardware report failed")
            QMessageBox.critical(self, "Report failed", str(exc))

    def _on_open(self) -> None:
        rid = selected_id(self.table)
        if rid is None:
            return
        row = self.ctx.db.query_one("SELECT file_path FROM technical_reports WHERE id=?", (rid,))
        if row and Path(row[0]).exists():
            open_in_file_manager(Path(row[0]))

    def refresh(self) -> None:
        self.project.reload()
        reps = self.ctx.reports.list_reports()
        fill_table(self.table, [[r["id"], r["project_id"], r["report_type"], r["format"], r["created_at"],
                                 r["sha256"], r["file_path"]] for r in reps], ids=[r["id"] for r in reps])
