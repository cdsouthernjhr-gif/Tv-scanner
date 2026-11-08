from __future__ import annotations

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout,
                               QWidget)

from app.services.project_service import TVProject
from app.ui.pages.project_form import ProjectForm
from app.ui.widgets import fill_table, make_table, notice, page_title, selected_id

log = logging.getLogger(__name__)


class NewProjectPage(QWidget):
    project_created = Signal(int)
    open_project = Signal(int)

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("New TV Project"))
        lay.addWidget(notice("Register any TV, including ones whose brand or model is unknown. "
                             "Fill in only what you can actually read or confirm; leave the rest empty. "
                             "Manually entered data is recorded as unverified."))
        self.form = ProjectForm()
        lay.addWidget(self.form)
        row = QHBoxLayout()
        self.btn_register = QPushButton("Register TV project")
        self.btn_register.clicked.connect(self._on_register)
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.form.clear)
        row.addWidget(self.btn_register)
        row.addWidget(self.btn_clear)
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(QLabel("Registered projects (double-click to open in TV Identification)"))
        self.table = make_table(["ID", "Name", "Manufacturer", "Model", "Mainboard", "Status",
                                 "Confidence", "Created (UTC)"])
        self.table.doubleClicked.connect(self._on_open)
        lay.addWidget(self.table, 1)
        del_row = QHBoxLayout()
        self.btn_delete = QPushButton("Delete selected project")
        self.btn_delete.clicked.connect(self._on_delete)
        del_row.addStretch()
        del_row.addWidget(self.btn_delete)
        lay.addLayout(del_row)
        self.refresh()

    def register(self) -> TVProject:
        """Create a project from the form (raises ValueError on invalid input)."""
        project = self.ctx.projects.create(TVProject(**self.form.values()))
        self.form.clear()
        self.refresh()
        self.project_created.emit(project.id)
        return project

    def _on_register(self) -> None:
        try:
            p = self.register()
            QMessageBox.information(self, "Project registered",
                                    f"Project #{p.id} registered.\nStatus: {p.identification_status}")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid input", str(exc))
        except Exception as exc:
            log.exception("Project registration failed")
            QMessageBox.critical(self, "Error", str(exc))

    def _on_open(self) -> None:
        pid = selected_id(self.table)
        if pid is not None:
            self.open_project.emit(pid)

    def _on_delete(self) -> None:
        pid = selected_id(self.table)
        if pid is None:
            return
        if QMessageBox.question(self, "Delete project",
                                f"Delete project #{pid}? Evidence records are removed from the database; "
                                "firmware in the library is kept.") == QMessageBox.Yes:
            self.ctx.projects.delete(pid)
            self.refresh()
            self.project_created.emit(pid)  # triggers refresh of other pages

    def refresh(self) -> None:
        projects = self.ctx.projects.list()
        fill_table(self.table, [[p.id, p.name, p.manufacturer, p.model_number, p.mainboard,
                                 p.identification_status, f"{p.identification_confidence:.0%}",
                                 p.created_at] for p in projects], ids=[p.id for p in projects])
