from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QScrollArea, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

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
        lay.addWidget(notice("Add photos of the rear label, product label or System Information menu, then "
                             "'Run OCR'. Values read from images appear as candidates with confidence and "
                             "source line; only values you accept are written to the project. Accepted "
                             "manufacturer + model from evidence raise the status to 'verified'."))
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

        right = QTabWidget()
        self.right_tabs = right
        ev_tab = QWidget()
        rl = QVBoxLayout(ev_tab)
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
        right.addTab(ev_tab, "Evidence images")

        cand_tab = QWidget()
        cl = QVBoxLayout(cand_tab)
        crow = QHBoxLayout()
        self.btn_ocr_new = QPushButton("Run OCR on new evidence")
        self.btn_ocr_new.clicked.connect(lambda: self.run_ocr_async(only_new=True))
        self.btn_ocr_all = QPushButton("Re-run OCR on all")
        self.btn_ocr_all.clicked.connect(lambda: self.run_ocr_async(only_new=False))
        crow.addWidget(self.btn_ocr_new)
        crow.addWidget(self.btn_ocr_all)
        crow.addStretch()
        cl.addLayout(crow)
        self.cand_table = make_table(["Field", "Value", "Confidence", "Images", "Method", "Status"])
        cl.addWidget(self.cand_table, 1)
        arow = QHBoxLayout()
        self.btn_accept = QPushButton("Accept selected value")
        self.btn_accept.clicked.connect(self._guard(self._accept_selected))
        self.btn_reject = QPushButton("Reject selected value")
        self.btn_reject.clicked.connect(self._guard(self._reject_selected))
        arow.addWidget(self.btn_accept)
        arow.addWidget(self.btn_reject)
        arow.addStretch()
        cl.addLayout(arow)
        cl.addWidget(QLabel("Confidence combines OCR certainty with how the value was found; the same value "
                            "found in several images is combined as 1 − Π(1 − p)."))
        right.addTab(cand_tab, "OCR candidates")

        cat_tab = QWidget()
        kl = QVBoxLayout(cat_tab)
        krow = QHBoxLayout()
        self.btn_match = QPushButton("Find matching models in catalog")
        self.btn_match.clicked.connect(self._guard(self.find_matches))
        self.btn_apply = QPushButton("Use selected match as candidates")
        self.btn_apply.clicked.connect(self._guard(self._apply_match))
        self.btn_catalog = QPushButton("Save this TV to catalog")
        self.btn_catalog.clicked.connect(self._guard(self.save_to_catalog))
        for b in (self.btn_match, self.btn_apply, self.btn_catalog):
            krow.addWidget(b)
        krow.addStretch()
        kl.addLayout(krow)
        self.match_table = make_table(["Catalog ID", "Manufacturer", "Model", "Chassis", "Mainboard",
                                       "Score", "Level", "Reasons"])
        kl.addWidget(self.match_table, 1)
        self.catalog_info = QLabel()
        kl.addWidget(self.catalog_info)
        right.addTab(cat_tab, "Catalog matching")
        self._matches = []
        self._groups = []
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

    def run_ocr(self, only_new: bool = True):
        pid = self.current_project_id()
        if pid is None:
            raise ValueError("No project selected")
        res = self.ctx.identification.run_ocr_for_project(pid, only_new=only_new)
        self._load_evidence(pid)
        self._load_candidates()
        self.right_tabs.setCurrentIndex(1)
        return res

    def run_ocr_async(self, only_new: bool = True):
        from app.ui.worker import run_async
        pid = self.current_project_id()
        if pid is None:
            return

        def done(res):
            self._load_evidence(pid)
            self._load_candidates()
            self.right_tabs.setCurrentIndex(1)
            self.status.setText(f"OCR finished for {len(res)} image(s).")
        self.status.setText("OCR running…")
        run_async(lambda: self.ctx.identification.run_ocr_for_project(pid, only_new=only_new), done,
                  lambda msg: QMessageBox.warning(self, "OCR failed", msg),
                  busy=[self.btn_ocr_new, self.btn_ocr_all])

    def accept(self, row: int):
        group = self._groups[row]
        p = self.ctx.identification.accept_candidate(group["candidate_ids"][0])
        self.form.set_values(p)
        self._update_status(p)
        self.selector.reload()
        self._load_candidates()
        return p

    def reject(self, row: int):
        group = self._groups[row]
        p = None
        for cid in group["candidate_ids"]:
            p = self.ctx.identification.reject_candidate(cid)
        if p:
            self._update_status(p)
        self._load_candidates()
        return p

    def find_matches(self):
        pid = self.current_project_id()
        if pid is None:
            raise ValueError("No project selected")
        self._matches = self.ctx.identification.find_catalog_matches(pid)
        fill_table(self.match_table, [[m.tv_model_id, m.manufacturer, m.model_number, m.chassis, m.mainboard,
                                       f"{m.score:.0%}", m.level, "; ".join(m.reasons)] for m in self._matches],
                   ids=list(range(len(self._matches))))
        if not self._matches:
            self.catalog_info.setText("No catalog entry matches (catalog only contains TVs saved from projects).")
        return self._matches

    def save_to_catalog(self):
        pid = self.current_project_id()
        if pid is None:
            raise ValueError("No project selected")
        tid = self.ctx.catalog.save_project(self.ctx.projects.get(pid))
        self.catalog_info.setText(f"Saved as catalog model #{tid}. Catalog entries: {self.ctx.catalog.count()}")
        return tid

    def _apply_match(self):
        idx = selected_id(self.match_table)
        if idx is None:
            raise ValueError("Select a match first")
        self.ctx.identification.apply_catalog_match(self.current_project_id(), self._matches[idx])
        self._load_candidates()
        self.right_tabs.setCurrentIndex(1)

    def _load_candidates(self):
        pid = self.current_project_id()
        self._groups = self.ctx.identification.aggregated_candidates(pid) if pid is not None else []
        fill_table(self.cand_table, [[g["field"], g["value"], f"{g['confidence']:.0%}", g["evidence_count"],
                                      ", ".join(g["methods"]), g["status"]] for g in self._groups],
                   ids=list(range(len(self._groups))))

    def _accept_selected(self):
        row = selected_id(self.cand_table)
        if row is None:
            raise ValueError("Select a candidate first")
        self.accept(row)

    def _reject_selected(self):
        row = selected_id(self.cand_table)
        if row is None:
            raise ValueError("Select a candidate first")
        self.reject(row)

    def _guard(self, fn):
        def run():
            QGuiApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                fn()
            except Exception as exc:
                log.exception("Identification action failed")
                QMessageBox.warning(self, "TV Identification", str(exc))
            finally:
                QGuiApplication.restoreOverrideCursor()
        return run

    # ---- slots -----------------------------------------------------------------
    def refresh(self) -> None:
        self.selector.reload()
        self.load_project()

    def load_project(self, *_):
        pid = self.current_project_id()
        enabled = pid is not None
        for w in (self.btn_save, self.btn_add, self.form, self.btn_ocr_new, self.btn_ocr_all,
                  self.btn_accept, self.btn_reject, self.btn_match, self.btn_catalog):
            w.setEnabled(enabled)
        ocr_ok = bool(self.ctx.identification.available_engines())
        self.btn_ocr_new.setEnabled(enabled and ocr_ok)
        self.btn_ocr_all.setEnabled(enabled and ocr_ok)
        self.catalog_info.setText(f"Catalog entries: {self.ctx.catalog.count()} (built only from TVs you saved)."
                                  + ("" if ocr_ok else "  OCR engine not installed."))
        if not enabled:
            self.form.clear()
            self.status.setText("No projects yet — register one in 'New TV Project'.")
            fill_table(self.ev_table, [])
            fill_table(self.cand_table, [])
            return
        p = self.ctx.projects.get(pid)
        self.form.set_values(p)
        self._update_status(p)
        self._load_evidence(pid)
        self._load_candidates()

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
