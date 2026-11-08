from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget)

from app.modules.firmware_library.library import CATEGORIES, DuplicateFirmware
from app.ui.widgets import (ProjectSelector, fill_table, make_table, notice, page_title,
                            selected_id)

log = logging.getLogger(__name__)


def open_in_file_manager(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class FirmwareLibraryPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Firmware Library"))
        lay.addWidget(notice(
            "Imported firmware is copied into the library, verified by SHA-256 and stored read-only. "
            "Your source file is never modified. Identical files (same SHA-256) are stored only once. "
            "'hash_ok' means the stored copy is intact — it does NOT mean the firmware is authentic "
            "or compatible with any TV."))
        form = QFormLayout()
        self.project = ProjectSelector(ctx, allow_none=True)
        self.project.currentIndexChanged.connect(self._prefill_from_project)
        form.addRow("Project", self.project)
        self.manufacturer = QLineEdit()
        self.model = QLineEdit()
        self.mainboard = QLineEdit()
        self.version = QLineEdit()
        self.url = QLineEdit()
        self.url.setPlaceholderText("original download URL if known (never invented)")
        self.category = QComboBox()
        self.category.addItems(CATEGORIES)
        row1 = QHBoxLayout()
        for w, ph in ((self.manufacturer, "Manufacturer"), (self.model, "Model"),
                      (self.mainboard, "Mainboard"), (self.version, "Version")):
            w.setPlaceholderText(ph)
            row1.addWidget(w)
        form.addRow("Metadata", row1)
        form.addRow("Category", self.category)
        form.addRow("Source URL", self.url)
        lay.addLayout(form)

        btns = QHBoxLayout()
        self.btn_import = QPushButton("Import firmware file…")
        self.btn_import.clicked.connect(self._on_import)
        self.btn_verify = QPushButton("Verify integrity of selected")
        self.btn_verify.clicked.connect(self._on_verify)
        self.btn_open = QPushButton("Open library folder")
        self.btn_open.clicked.connect(lambda: open_in_file_manager(self.ctx.library.root))
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("filter by mainboard…")
        self.filter.textChanged.connect(self.refresh)
        for b in (self.btn_import, self.btn_verify, self.btn_open):
            btns.addWidget(b)
        btns.addStretch()
        btns.addWidget(self.filter)
        lay.addLayout(btns)
        self.table = make_table(["ID", "File", "Manufacturer", "Model", "Mainboard", "Version",
                                 "Category", "Format", "Size", "Integrity", "SHA-256", "Stored path"])
        lay.addWidget(self.table, 1)
        self.summary = QLabel()
        lay.addWidget(self.summary)
        self.refresh()

    def _prefill_from_project(self, *_):
        pid = self.project.currentData()
        if pid is None:
            return
        p = self.ctx.projects.get(pid)
        self.manufacturer.setText(p.manufacturer or "")
        self.model.setText(p.model_number or "")
        self.mainboard.setText(p.mainboard or "")

    def import_firmware(self, path: str | Path):
        rec = self.ctx.library.import_file(
            path, category=self.category.currentText(),
            manufacturer=self.manufacturer.text().strip() or None,
            model_number=self.model.text().strip() or None,
            mainboard=self.mainboard.text().strip() or None,
            version=self.version.text().strip() or None,
            project_id=self.project.currentData(),
            download_url=self.url.text().strip() or None)
        self.refresh()
        return rec

    def _on_import(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select firmware files", "",
            "Firmware (*.bin *.img *.rom *.pkg *.zip *.tar *.tgz *.gz *.epk *.upg);;All files (*)")
        for path in paths:
            try:
                rec = self.import_firmware(path)
                QMessageBox.information(self, "Imported",
                                        f"{rec.original_filename}\nSHA-256: {rec.sha256}\n"
                                        f"Detected format: {rec.detected_format}")
            except DuplicateFirmware as dup:
                QMessageBox.information(self, "Already in library", str(dup))
            except Exception as exc:
                log.exception("Firmware import failed")
                QMessageBox.critical(self, "Import failed", f"{path}\n\n{exc}")

    def _on_verify(self) -> None:
        fid = selected_id(self.table)
        if fid is None:
            return
        rec = self.ctx.library.verify_integrity(fid)
        self.refresh()
        if rec.verification_status == "hash_mismatch":
            QMessageBox.critical(self, "Integrity FAILED",
                                 f"Stored file does not match its recorded SHA-256:\n{rec.stored_path}")
        else:
            QMessageBox.information(self, "Integrity OK", f"SHA-256 matches: {rec.sha256}")

    def refresh(self) -> None:
        self.project.reload()
        recs = self.ctx.library.list(mainboard=self.filter.text().strip() or None)
        fill_table(self.table, [[r.id, r.original_filename, r.manufacturer, r.model_number, r.mainboard,
                                 r.version, r.category, r.detected_format, f"{r.file_size:,}",
                                 r.verification_status, r.sha256, r.stored_path] for r in recs],
                   ids=[r.id for r in recs])
        self.summary.setText(f"{len(recs)} firmware file(s) | library: {self.ctx.library.root}")
