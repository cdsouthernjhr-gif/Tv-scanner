"""Visual Scanner: crop, enhance, OCR and chip/PCB marking recognition on evidence images."""
from __future__ import annotations

import logging

from PySide6.QtCore import QPoint, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QRubberBand, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

from app.modules.visual_scanner import preprocess as pp
from app.services.evidence_service import EVIDENCE_TYPES
from app.ui.widgets import (ProjectSelector, fill_table, make_table, ndarray_to_pixmap, notice,
                            page_title, selected_id)

log = logging.getLogger(__name__)


class CropLabel(QLabel):
    """Shows an image scaled to fit; drag with the mouse to select a crop region
    (reported in *original image* pixel coordinates)."""
    crop_changed = Signal(object)

    def __init__(self):
        super().__init__("Select an evidence image")
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumSize(QSize(420, 320))
        self._band = QRubberBand(QRubberBand.Rectangle, self)
        self._origin = QPoint()
        self._img_size = (0, 0)
        self._scale = 1.0
        self._offset = QPoint()
        self._source = None
        self.crop_rect: tuple[int, int, int, int] | None = None

    def set_image(self, pixmap, img_w: int, img_h: int) -> None:
        self._source = pixmap
        self._img_size = (img_w, img_h)
        self.crop_rect = None
        self._band.hide()
        self._render()

    def _render(self) -> None:
        if self._source is None:
            return
        scaled = self._source.scaled(self.width() - 4, self.height() - 4, Qt.KeepAspectRatio,
                                     Qt.SmoothTransformation)
        self._scale = scaled.width() / max(1, self._img_size[0])
        self._offset = QPoint((self.width() - scaled.width()) // 2, (self.height() - scaled.height()) // 2)
        self.setPixmap(scaled)

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self._render()

    def mousePressEvent(self, e):  # noqa: N802
        if self._source is None:
            return
        self._origin = e.position().toPoint()
        self._band.setGeometry(QRect(self._origin, QSize()))
        self._band.show()

    def mouseMoveEvent(self, e):  # noqa: N802
        if self._band.isVisible():
            self._band.setGeometry(QRect(self._origin, e.position().toPoint()).normalized())

    def mouseReleaseEvent(self, e):  # noqa: N802
        if not self._band.isVisible():
            return
        r = self._band.geometry()
        if r.width() < 8 or r.height() < 8:
            self._band.hide()
            self.set_crop(None)
            return
        x = int((r.x() - self._offset.x()) / self._scale)
        y = int((r.y() - self._offset.y()) / self._scale)
        w, h = int(r.width() / self._scale), int(r.height() / self._scale)
        W, H = self._img_size
        x, y = max(0, x), max(0, y)
        self.set_crop((x, y, min(w, W - x), min(h, H - y)))

    def set_crop(self, rect) -> None:
        self.crop_rect = rect
        if rect is None:
            self._band.hide()
        self.crop_changed.emit(rect)


class VisualScannerPage(QWidget):
    PSM = [("Auto", None), ("Sparse text (labels, PCB) — 11", 11), ("Uniform block (menus) — 6", 6),
           ("Columns — 4", 4), ("Single line — 7", 7)]

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.rotation = 0
        self._last = None
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Visual Scanner"))
        lay.addWidget(notice(
            "Drag on the image to crop (e.g. one chip or the model line), choose a preset, then Run OCR. "
            "Results are candidates only: recognised chips/boards must be confirmed by you before they "
            "become hardware records. Vendor names come from part-number conventions, never from guesses "
            "about capacity or specification."))

        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx)
        self.project.currentIndexChanged.connect(self._load_evidence_list)
        top.addWidget(self.project, 1)
        top.addWidget(QLabel("Evidence:"))
        self.evidence = QComboBox()
        self.evidence.currentIndexChanged.connect(self._load_image)
        top.addWidget(self.evidence, 2)
        lay.addLayout(top)

        ctl = QHBoxLayout()
        self.preset = QComboBox()
        self.preset.addItem("Auto (by evidence type)", None)
        for name in pp.PRESETS:
            self.preset.addItem(name, name)
        self.psm = QComboBox()
        for label, v in self.PSM:
            self.psm.addItem(label, v)
        self.engine = QComboBox()
        self.btn_rl = QPushButton("⟲ 90°")
        self.btn_rr = QPushButton("⟳ 90°")
        self.btn_clear = QPushButton("Clear crop")
        self.btn_preview = QPushButton("Preview processing")
        self.btn_save = QPushButton("Save processed copy")
        self.btn_ocr = QPushButton("Run OCR")
        self.btn_rl.clicked.connect(lambda: self._rotate(-90))
        self.btn_rr.clicked.connect(lambda: self._rotate(90))
        self.btn_clear.clicked.connect(lambda: self.canvas.set_crop(None))
        self.btn_preview.clicked.connect(self._guard(self.preview))
        self.btn_save.clicked.connect(self._guard(self._save_processed))
        self.btn_ocr.clicked.connect(self._guard(self.run_ocr))
        for w in (QLabel("Preset"), self.preset, QLabel("Layout"), self.psm, QLabel("Engine"), self.engine,
                  self.btn_rl, self.btn_rr, self.btn_clear, self.btn_preview, self.btn_save, self.btn_ocr):
            ctl.addWidget(w)
        ctl.addStretch()
        lay.addLayout(ctl)
        self.crop_info = QLabel("Crop: whole image")
        lay.addWidget(self.crop_info)

        split = QSplitter(Qt.Horizontal)
        self.canvas = CropLabel()
        self.canvas.crop_changed.connect(
            lambda r: self.crop_info.setText(f"Crop: x={r[0]} y={r[1]} w={r[2]} h={r[3]}" if r else "Crop: whole image"))
        split.addWidget(self.canvas)
        self.tabs = QTabWidget()
        self.processed = QLabel("Processed image / OCR boxes appear here")
        self.processed.setAlignment(Qt.AlignCenter)
        self.tabs.addTab(self.processed, "Processed")
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.tabs.addTab(self.text, "OCR text")
        mw = QWidget()
        ml = QVBoxLayout(mw)
        self.markings = make_table(["ID", "Kind", "Marking", "Vendor (convention)", "Type", "Conf.",
                                    "Status", "Note"])
        ml.addWidget(self.markings, 1)
        mrow = QHBoxLayout()
        self.part_edit = QLineEdit()
        self.part_edit.setPlaceholderText("corrected part number (optional)")
        self.btn_confirm = QPushButton("Confirm as hardware component")
        self.btn_reject = QPushButton("Reject")
        self.btn_confirm.clicked.connect(self._guard(self._confirm_marking))
        self.btn_reject.clicked.connect(self._guard(self._reject_marking))
        for w in (self.part_edit, self.btn_confirm, self.btn_reject):
            mrow.addWidget(w)
        ml.addLayout(mrow)
        self.tabs.addTab(mw, "Chip / PCB markings")
        self.quality = QPlainTextEdit()
        self.quality.setReadOnly(True)
        self.tabs.addTab(self.quality, "Image quality")
        split.addWidget(self.tabs)
        split.setSizes([600, 600])
        lay.addWidget(split, 1)
        self.status = QLabel()
        lay.addWidget(self.status)
        self.refresh()

    # ---- helpers ------------------------------------------------------------------
    def _guard(self, fn):
        def run():
            QGuiApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                fn()
            except Exception as exc:
                log.exception("Visual scanner action failed")
                QMessageBox.warning(self, "Visual Scanner", str(exc))
            finally:
                QGuiApplication.restoreOverrideCursor()
        return run

    def current_evidence_id(self):
        return self.evidence.currentData()

    def refresh(self) -> None:
        self.project.reload()
        self.engine.clear()
        engines = self.ctx.identification.available_engines()
        for e in engines:
            self.engine.addItem(e, e)
        if not engines:
            self.engine.addItem("no OCR engine installed", None)
        self.btn_ocr.setEnabled(bool(engines))
        self._load_evidence_list()

    def _load_evidence_list(self, *_):
        pid = self.project.currentData()
        self.evidence.blockSignals(True)
        self.evidence.clear()
        if pid is not None:
            for ev in self.ctx.evidence.list_for_project(pid):
                prefix = "  ↳ processed " if ev.parent_evidence_id else ""
                self.evidence.addItem(f"{prefix}#{ev.id} {EVIDENCE_TYPES.get(ev.evidence_type)} — "
                                      f"{ev.original_filename}", ev.id)
        self.evidence.blockSignals(False)
        self._load_image()
        self._load_markings()

    def select_evidence(self, evidence_id: int) -> None:
        ev = self.ctx.evidence.get(evidence_id)
        self.project.select_project(ev.project_id)
        self._load_evidence_list()
        self.evidence.setCurrentIndex(self.evidence.findData(evidence_id))

    def _load_image(self, *_):
        eid = self.current_evidence_id()
        self.rotation = 0
        if eid is None:
            self.canvas.clear()
            self.canvas.setText("No evidence images for this project — add them in TV Identification.")
            return
        self._show_original()
        ev = self.ctx.evidence.get(eid)
        q = pp.quality_report(pp.load_image(ev.stored_path))
        self.quality.setPlainText("\n".join(f"{k}: {v}" for k, v in q.items() if k != "warnings") + "\n\n" +
                                  ("\n".join("⚠ " + w for w in q["warnings"]) or "No quality warnings."))
        if ev.ocr_text:
            self.text.setPlainText(ev.ocr_text)

    def _show_original(self):
        ev = self.ctx.evidence.get(self.current_evidence_id())
        img = pp.load_image(ev.stored_path)
        if self.rotation:
            img = pp.rotate(img, self.rotation)
        self.canvas.set_image(ndarray_to_pixmap(img), img.shape[1], img.shape[0])

    def _rotate(self, deg: int):
        if self.current_evidence_id() is None:
            return
        self.rotation = (self.rotation + deg) % 360
        self._show_original()

    def _show_processed(self, img, tokens=None):
        pm = ndarray_to_pixmap(img)
        if tokens:
            painter = QPainter(pm)
            pen = QPen(QColor(255, 140, 0))
            pen.setWidth(max(2, pm.width() // 400))
            painter.setPen(pen)
            for t in tokens:
                x, y, w, h = t.bbox
                painter.setPen(QPen(QColor(0, 200, 90) if t.conf >= 0.8 else QColor(255, 140, 0),
                                    pen.width()))
                painter.drawRect(x, y, w, h)
            painter.end()
        self.processed.setPixmap(pm.scaled(self.processed.width() - 4, self.processed.height() - 4,
                                           Qt.KeepAspectRatio, Qt.SmoothTransformation))

    # ---- actions (programmatic API used by buttons and tests) ------------------------
    def preview(self):
        eid = self.current_evidence_id()
        if eid is None:
            raise ValueError("No evidence selected")
        _, preset, img, steps = self.ctx.identification.process(eid, self.preset.currentData(),
                                                                 self.canvas.crop_rect, self.rotation)
        self._show_processed(img)
        self.tabs.setCurrentIndex(0)
        self.status.setText(f"Preset '{preset}': " + " → ".join(s["op"] for s in steps))
        return img

    def _save_processed(self):
        ev = self.save_processed()
        QMessageBox.information(self, "Saved", f"Processed copy stored as evidence #{ev.id} "
                                               "(original unchanged).")

    def save_processed(self):
        eid = self.current_evidence_id()
        if eid is None:
            raise ValueError("No evidence selected")
        ev = self.ctx.identification.save_processed(eid, self.preset.currentData(),
                                                    self.canvas.crop_rect, self.rotation)
        self._load_evidence_list()
        self.evidence.setCurrentIndex(self.evidence.findData(ev.id))
        return ev

    def run_ocr(self):
        eid = self.current_evidence_id()
        if eid is None:
            raise ValueError("No evidence selected")
        preset = self.preset.currentData()
        psm = self.psm.currentData()
        r = self.ctx.identification.run_ocr(eid, preset=preset, engine=self.engine.currentData(), psm=psm,
                                            crop_rect=self.canvas.crop_rect, rotation=self.rotation,
                                            auto=preset is None and psm is None)
        self._last = r
        self.text.setPlainText(r.text)
        self._show_processed(r.processed_image, r.tokens)
        self._load_markings()
        self.status.setText(f"{r.engine} | best: {r.preset}/psm{r.psm} | mean confidence "
                            f"{r.mean_confidence:.0%} | {len(r.candidates)} identification candidates "
                            f"(review in TV Identification) | {len(r.markings)} markings")
        if r.markings:
            self.tabs.setCurrentIndex(2)
        return r

    def _load_markings(self):
        pid = self.project.currentData()
        rows = self.ctx.identification.markings(pid) if pid is not None else []
        fill_table(self.markings, [[m["id"], m["kind"], m["normalized"], m["candidate_vendor"] or "—",
                                    m["candidate_type"] or "unrecognised", f"{m['confidence']:.0%}",
                                    m["status"], m["note"]] for m in rows], ids=[m["id"] for m in rows])

    def _confirm_marking(self):
        mid = selected_id(self.markings)
        if mid is None:
            raise ValueError("Select a marking first")
        hid = self.ctx.identification.confirm_marking(mid, self.part_edit.text().strip() or None)
        self.part_edit.clear()
        self._load_markings()
        self.status.setText(f"Hardware component #{hid} recorded (verified by user).")

    def _reject_marking(self):
        mid = selected_id(self.markings)
        if mid is None:
            raise ValueError("Select a marking first")
        self.ctx.identification.reject_marking(mid)
        self._load_markings()
