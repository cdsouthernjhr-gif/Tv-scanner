from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QScrollArea, QSplitter, QVBoxLayout,
                               QWidget)

from app.services.evidence_service import EVIDENCE_TYPES
from app.ui.pages.project_form import ProjectForm
from app.ui.widgets import (ProjectSelector, fill_table, make_table, notice, page_title,
                            selected_id)

log = logging.getLogger(__name__)


class IdentificationPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("TV Identification"))
        lay.addWidget(notice("Phase 1: manual identification + evidence image storage. "
                             "OCR of labels/menus and database matching are delivered in Phase 2; "
                             "until then no value is extracted automatically from images."))
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.selector = ProjectSelector(ctx)
        self.selector.currentIndexChanged.connect(self.load_project)
        top.addWidget(self.selector, 1)
        self.status = QLabel()
        top.addWidget(self.status)
        lay.addLayout(top)

        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        self.form = ProjectForm()
        ll.addWidget(self.form)
        self.btn_save = QPushButton("Save identification data")
        self.btn_save.clicked.connect(self._on_save)
        ll.addWidget(self.btn_save)
        ll.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(left)
        split.addWidget(scroll)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(QLabel("Evidence images"))
        add_row = QHBoxLayout()
        self.ev_type = QComboBox()
        for key, label in EVIDENCE_TYPES.items():
            self.ev_type.addItem(label, key)
        self.ev_desc = QLineEdit()
        self.ev_desc.setPlaceholderText("description (optional)")
        self.btn_add = QPushButton("Add image…")
        self.btn_add.clicked.connect(self._on_add_image)
        add_row.addWidget(self.ev_type)
        add_row.addWidget(self.ev_desc, 1)
        add_row.addWidget(self.btn_add)
        rl.addLayout(add_row)
        self.ev_table = make_table(["ID", "Type", "File", "Size (px)", "SHA-256"])
        self.ev_table.itemSelectionChanged.connect(self._show_preview)
        rl.addWidget(self.ev_table, 1)
        self.preview = QLabel("Select an image to preview")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumHeight(240)
        rl.addWidget(self.preview, 1)
        split.addWidget(right)
        split.setSizes([420, 600])
        lay.addWidget(split, 1)
        self.load_project()

    # ---- programmatic API (used by UI and tests) ----------------------------
    def current_project_id(self):
        return self.selector.currentData()

    def save(self):
        pid = self.current_project_id()
        if pid is None:
            raise ValueError("No project selected")
        p = self.ctx.projects.update(pid, **self.form.values())
        self.selector.reload()
        self._update_status(p)
        return p

    def add_evidence(self, path: str | Path, evidence_type: str, description: str | None = None):
        pid = self.current_project_id()
        if pid is None:
            raise ValueError("No project selected")
        ev = self.ctx.evidence.add_image(pid, path, evidence_type, description)
        self._load_evidence(pid)
        return ev

    # ---- slots -----------------------------------------------------------------
    def refresh(self) -> None:
        self.selector.reload()
        self.load_project()

    def load_project(self, *_):
        pid = self.current_project_id()
        enabled = pid is not None
        for w in (self.btn_save, self.btn_add, self.form):
            w.setEnabled(enabled)
        if not enabled:
            self.form.clear()
            self.status.setText("No projects yet — register one in 'New TV Project'.")
            fill_table(self.ev_table, [])
            return
        p = self.ctx.projects.get(pid)
        self.form.set_values(p)
        self._update_status(p)
        self._load_evidence(pid)

    def _update_status(self, p) -> None:
        self.status.setText(f"Status: {p.identification_status} | confidence {p.identification_confidence:.0%}"
                            f" | source: {p.identification_source}")

    def _load_evidence(self, pid: int) -> None:
        evs = self.ctx.evidence.list_for_project(pid)
        fill_table(self.ev_table, [[e.id, EVIDENCE_TYPES.get(e.evidence_type), e.original_filename,
                                    f"{e.width}x{e.height}", e.sha256] for e in evs],
                   ids=[e.id for e in evs])
        self.preview.setText("Select an image to preview")

    def _show_preview(self) -> None:
        eid = selected_id(self.ev_table)
        if eid is None:
            return
        ev = self.ctx.evidence.get(eid)
        pm = QPixmap(ev.stored_path)
        if pm.isNull():
            self.preview.setText("Preview not available for this format")
        else:
            self.preview.setPixmap(pm.scaled(self.preview.width(), self.preview.height(),
                                             Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def _on_save(self) -> None:
        try:
            self.save()
        except Exception as exc:
            QMessageBox.warning(self, "Cannot save", str(exc))

    def _on_add_image(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select evidence images", "", "Images (*.jpg *.jpeg *.png *.bmp *.tif *.tiff *.webp)")
        for path in paths:
            try:
                self.add_evidence(path, self.ev_type.currentData(), self.ev_desc.text() or None)
            except Exception as exc:
                log.exception("Adding evidence failed")
                QMessageBox.warning(self, "Cannot add image", f"{path}\n\n{exc}")
        self.ev_desc.clear()
