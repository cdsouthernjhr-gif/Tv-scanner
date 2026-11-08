"""Hardware Analyzer page: components, specifications with sources, board summary,
datasheet library and reference database."""
from __future__ import annotations

import json
import logging
from urllib.parse import quote_plus

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

from app.modules.hardware_analyzer.service import BOARDS, CATEGORIES, SUMMARY_LABELS, category_for
from app.modules.reports.hardware_report import STATUS_TEXT, display_value
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id
from app.ui.worker import run_async

log = logging.getLogger(__name__)


class HardwarePage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Hardware Analyzer"))
        lay.addWidget(notice(
            "Components come from markings confirmed in the Visual Scanner or are added here. 'Analyze' looks up "
            "numbering conventions, vendor part-number decoders, the reference database and your local datasheet "
            "library. Every value shows its source; nothing is assumed (e.g. RAM size is only totalled when every "
            "RAM chip has capacity evidence)."))
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx)
        self.project.currentIndexChanged.connect(self.load_project)
        top.addWidget(self.project, 1)
        self.btn_analyze_all = QPushButton("Analyze all components")
        self.btn_analyze_all.clicked.connect(self._on_analyze_all)
        self.export_fmt = QComboBox()
        self.export_fmt.addItems(["PDF report", "XLSX", "CSV", "JSON"])
        self.btn_export = QPushButton("Generate")
        self.btn_export.clicked.connect(self._guard(lambda: self._show_export(self.export(self.export_fmt.currentText()))))
        for w in (self.btn_analyze_all, QLabel("Hardware report:"), self.export_fmt, self.btn_export):
            top.addWidget(w)
        lay.addLayout(top)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self._build_components_tab()
        self._build_summary_tab()
        self._build_datasheet_tab()
        self._build_reference_tab()
        self.status = QLabel()
        lay.addWidget(self.status)
        self.refresh()

    # ---- tabs -------------------------------------------------------------------------
    def _build_components_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        split = QSplitter(Qt.Vertical)
        self.table = make_table(["ID", "Board", "Pos.", "Category", "Part number", "Manufacturer", "Qty",
                                 "Identification", "Conf.", "Specification"])
        self.table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.table)

        detail = QWidget()
        dl = QHBoxLayout(detail)
        left = QWidget()
        ll = QVBoxLayout(left)
        form = QFormLayout()
        self.f_cat = QComboBox()
        for k, label in CATEGORIES.items():
            self.f_cat.addItem(label, k)
        self.f_part = QLineEdit()
        self.f_part.setPlaceholderText("exact marking / part number")
        self.f_mfr = QLineEdit()
        self.f_mfr.setPlaceholderText("leave empty if unknown")
        self.f_board = QComboBox()
        self.f_board.addItems(BOARDS)
        self.f_pos = QLineEdit()
        self.f_pos.setPlaceholderText("e.g. U12")
        self.f_qty = QSpinBox()
        self.f_qty.setRange(1, 64)
        for label, wid in (("Category", self.f_cat), ("Part number", self.f_part), ("Manufacturer", self.f_mfr),
                           ("Board", self.f_board), ("Position", self.f_pos), ("Quantity", self.f_qty)):
            form.addRow(label, wid)
        ll.addLayout(form)
        b1 = QHBoxLayout()
        self.btn_add = QPushButton("Add")
        self.btn_add.clicked.connect(self._guard(self.add_from_form))
        self.btn_update = QPushButton("Update selected")
        self.btn_update.clicked.connect(self._guard(self.update_from_form))
        self.btn_delete = QPushButton("Delete")
        self.btn_delete.clicked.connect(self._guard(self._on_delete))
        for b in (self.btn_add, self.btn_update, self.btn_delete):
            b1.addWidget(b)
        ll.addLayout(b1)
        b2 = QHBoxLayout()
        self.btn_analyze = QPushButton("Analyze selected")
        self.btn_analyze.clicked.connect(self._guard(lambda: self.analyze_selected()))
        self.btn_ref = QPushButton("Save to reference DB")
        self.btn_ref.clicked.connect(self._guard(self._on_save_ref))
        self.btn_web = QPushButton("Search datasheet in browser")
        self.btn_web.clicked.connect(self._guard(self._on_web))
        for b in (self.btn_analyze, self.btn_ref, self.btn_web):
            b2.addWidget(b)
        ll.addLayout(b2)
        self.evidence_img = QLabel("No evidence image")
        self.evidence_img.setAlignment(Qt.AlignCenter)
        self.evidence_img.setMinimumHeight(120)
        ll.addWidget(self.evidence_img, 1)
        dl.addWidget(left, 2)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(QLabel("Specification (each value with its source)"))
        self.facts = make_table(["Attribute", "Value", "Source", "Reference", "Conf."])
        rl.addWidget(self.facts, 1)
        self.warnings = QLabel()
        self.warnings.setWordWrap(True)
        self.warnings.setStyleSheet("color: #f0d48a;")
        rl.addWidget(self.warnings)
        fr = QHBoxLayout()
        self.u_attr = QLineEdit()
        self.u_attr.setPlaceholderText("attribute")
        self.u_val = QLineEdit()
        self.u_val.setPlaceholderText("value")
        self.u_unit = QLineEdit()
        self.u_unit.setPlaceholderText("unit")
        self.u_unit.setMaximumWidth(60)
        self.u_ref = QLineEdit()
        self.u_ref.setPlaceholderText("source reference (required)")
        self.btn_fact = QPushButton("Add value")
        self.btn_fact.clicked.connect(self._guard(self._on_add_fact))
        for x in (self.u_attr, self.u_val, self.u_unit, self.u_ref, self.btn_fact):
            fr.addWidget(x)
        rl.addLayout(fr)
        dl.addWidget(right, 3)
        split.addWidget(detail)
        split.setSizes([300, 360])
        v.addWidget(split)
        self.tabs.addTab(w, "Components")

    def _build_summary_tab(self):
        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.tabs.addTab(self.summary, "Board summary")

    def _build_datasheet_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(notice("Import datasheet PDFs you obtained from the manufacturer. They are stored read-only "
                           "with SHA-256 and indexed offline. Record where each one came from — the URL is never "
                           "guessed by the application."))
        r = QHBoxLayout()
        self.ds_vendor = QLineEdit()
        self.ds_vendor.setPlaceholderText("vendor")
        self.ds_url = QLineEdit()
        self.ds_url.setPlaceholderText("source URL (where you downloaded it)")
        self.btn_ds_import = QPushButton("Import datasheet PDF…")
        self.btn_ds_import.clicked.connect(self._on_import_ds)
        for x in (self.ds_vendor, self.ds_url, self.btn_ds_import):
            r.addWidget(x)
        v.addLayout(r)
        self.ds_table = make_table(["ID", "Vendor", "Title", "Pages", "Part numbers", "Source", "SHA-256"])
        self.ds_table.doubleClicked.connect(self._on_open_ds)
        v.addWidget(self.ds_table, 1)
        s = QHBoxLayout()
        self.ds_query = QLineEdit()
        self.ds_query.setPlaceholderText("find datasheets mentioning a part number…")
        self.ds_query.returnPressed.connect(self._guard(lambda: self.search_datasheets(self.ds_query.text())))
        s.addWidget(self.ds_query)
        v.addLayout(s)
        self.ds_results = make_table(["Datasheet", "Title", "Match", "Matched part", "Page"])
        v.addWidget(self.ds_results)
        self.tabs.addTab(w, "Datasheet library")

    def _build_reference_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Reference database — components saved from analysed TVs, with all their facts and "
                           "sources. Reused automatically when the same part is analysed again."))
        self.ref_table = make_table(["Kind", "ID", "Vendor", "Part number", "Type", "Facts", "Source"])
        v.addWidget(self.ref_table, 1)
        self.tabs.addTab(w, "Reference database")

    # ---- helpers ------------------------------------------------------------------------
    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Hardware page action failed")
                QMessageBox.warning(self, "Hardware Analyzer", str(exc))
        return run

    def pid(self):
        return self.project.currentData()

    def refresh(self) -> None:
        self.project.reload()
        self.load_project()
        self._load_datasheets()
        self._load_reference()

    def load_project(self, *_):
        pid = self.pid()
        rows = self.ctx.hardware.list(pid) if pid is not None else []
        fill_table(self.table, [[c["id"], c["board"], c["position"], CATEGORIES.get(category_for(c["component_type"])),
                                 c["part_number"], c["manufacturer"], c["quantity"],
                                 STATUS_TEXT.get(c["match_status"], c["match_status"]),
                                 f"{(c['confidence'] or 0):.0%}", c["specification"]] for c in rows],
                   ids=[c["id"] for c in rows])
        self._load_summary()
        self.facts.setRowCount(0)
        self.warnings.clear()

    def _load_summary(self):
        pid = self.pid()
        if pid is None:
            self.summary.setPlainText("No project selected.")
            return
        s = self.ctx.hardware.board_summary(pid)
        lines = []
        for k, label in SUMMARY_LABELS:
            v = s[k]
            if isinstance(v, dict):
                lines.append(f"{label}: {v['text'].split(': ', 1)[-1]}")
                lines += [f"      {c}" for c in v["chips"]]
            elif isinstance(v, list):
                lines.append(f"{label}: " + ("; ".join(v) if v else "—"))
            else:
                lines.append(f"{label}: {v}")
        self.summary.setPlainText("\n".join(lines))

    def _load_datasheets(self):
        ds = self.ctx.datasheets.list()
        fill_table(self.ds_table, [[d["id"], d["vendor"], d["title"] or d["original_filename"], d["page_count"],
                                    d["part_count"], d["source_url"] or "not recorded", d["sha256"]] for d in ds],
                   ids=[d["id"] for d in ds])

    def _load_reference(self):
        rows = self.ctx.hardware.reference_entries()
        fill_table(self.ref_table, [[r["kind"], r["id"], r["vendor"], r["part_number"], r["type"], r["facts"],
                                     r["source"]] for r in rows])

    def _on_select(self):
        cid = selected_id(self.table)
        if cid is None:
            return
        c = self.ctx.hardware.get(cid)
        self.f_cat.setCurrentIndex(self.f_cat.findData(category_for(c["component_type"])))
        self.f_part.setText(c["part_number"] or "")
        self.f_mfr.setText(c["manufacturer"] or "")
        self.f_board.setCurrentText(c["board"] or "other")
        self.f_pos.setText(c["position"] or "")
        self.f_qty.setValue(c["quantity"] or 1)
        facts = self.ctx.hardware.facts(cid)
        fill_table(self.facts, [[f["attribute"], display_value(f["attribute"], f["value"], f["unit"]),
                                 f["source_type"], f["source_reference"], f"{f['confidence']:.0%}"] for f in facts])
        ws = json.loads(c["analysis_warnings"] or "[]")
        self.warnings.setText("\n".join("⚠ " + w for w in ws))
        pm = None
        if c["evidence_id"]:
            try:
                pm = QPixmap(self.ctx.evidence.get(c["evidence_id"]).stored_path)
            except KeyError:
                pm = None
        if pm and not pm.isNull():
            self.evidence_img.setPixmap(pm.scaled(320, 160, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.evidence_img.setText("No evidence image")

    # ---- programmatic API (buttons + tests) ------------------------------------------------
    def add_from_form(self) -> int:
        if self.pid() is None:
            raise ValueError("Register a TV project first")
        cid = self.ctx.hardware.add_component(self.pid(), self.f_cat.currentData(), self.f_part.text(),
                                              self.f_mfr.text(), self.f_board.currentText(), self.f_pos.text(),
                                              self.f_qty.value())
        self.load_project()
        return cid

    def update_from_form(self):
        cid = selected_id(self.table)
        if cid is None:
            raise ValueError("Select a component")
        self.ctx.hardware.update_component(
            cid, component_type=self.f_cat.currentData(), part_number=self.f_part.text().strip().upper() or None,
            manufacturer=self.f_mfr.text().strip() or None, board=self.f_board.currentText(),
            position=self.f_pos.text().strip() or None, quantity=self.f_qty.value())
        self.load_project()

    def analyze_selected(self, component_id: int | None = None):
        cid = component_id or selected_id(self.table)
        if cid is None:
            raise ValueError("Select a component")
        a = self.ctx.hardware.analyze(cid)
        self.load_project()
        self._reselect(cid)
        self.status.setText(f"#{cid}: {STATUS_TEXT[a.match_status]} — confidence {a.confidence:.0%}")
        return a

    def analyze_all(self):
        res = self.ctx.hardware.analyze_project(self.pid())
        self.load_project()
        return res

    def _on_analyze_all(self):
        if self.pid() is None:
            return
        pid = self.pid()
        self.status.setText("Analysing…")
        run_async(lambda: self.ctx.hardware.analyze_project(pid),
                  lambda res: (self.load_project(), self.status.setText(f"{len(res)} component(s) analysed.")),
                  lambda msg: QMessageBox.warning(self, "Analysis failed", msg),
                  busy=[self.btn_analyze_all, self.btn_analyze])

    def export(self, fmt: str):
        if self.pid() is None:
            raise ValueError("No project selected")
        R = self.ctx.hardware_reports
        fn = {"PDF report": R.generate_pdf, "XLSX": R.export_xlsx, "CSV": R.export_csv, "JSON": R.export_json}[fmt]
        return fn(self.pid())

    def _show_export(self, path):
        self.status.setText(f"Saved {path}")
        if QMessageBox.question(self, "Report generated", f"{path}\n\nOpen the reports folder?") == QMessageBox.Yes:
            open_in_file_manager(path.parent)

    def _reselect(self, cid):
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).data(Qt.UserRole) == cid:
                self.table.selectRow(r)
                break

    def _on_delete(self):
        cid = selected_id(self.table)
        if cid is None:
            return
        if QMessageBox.question(self, "Delete component", f"Delete component #{cid} and its facts?") == QMessageBox.Yes:
            self.ctx.hardware.delete_component(cid)
            self.load_project()

    def _on_save_ref(self):
        cid = selected_id(self.table)
        if cid is None:
            raise ValueError("Select a component")
        kind, rid = self.ctx.hardware.save_to_reference(cid)
        self._load_reference()
        self.status.setText(f"Saved to reference database ({kind} #{rid}).")

    def _on_web(self):
        part = self.f_part.text().strip()
        if not part:
            raise ValueError("No part number")
        # Opens a web *search* in the user's browser; the application does not download anything.
        QDesktopServices.openUrl(QUrl("https://duckduckgo.com/?q=" + quote_plus(f"{part} datasheet")))

    def _on_add_fact(self):
        cid = selected_id(self.table)
        if cid is None:
            raise ValueError("Select a component")
        self.ctx.hardware.add_user_fact(cid, self.u_attr.text(), self.u_val.text(), self.u_unit.text() or None,
                                        self.u_ref.text())
        for x in (self.u_attr, self.u_val, self.u_unit, self.u_ref):
            x.clear()
        self._on_select()

    def import_datasheet(self, path, vendor=None, source_url=None) -> int:
        did = self.ctx.datasheets.import_pdf(path, vendor=vendor, source_url=source_url)
        self._load_datasheets()
        return did

    def _on_import_ds(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select datasheet PDFs", "", "PDF (*.pdf)")
        vendor, url = self.ds_vendor.text().strip() or None, self.ds_url.text().strip() or None
        for path in paths:
            def done(did, path=path):
                self._load_datasheets()
                self.status.setText(f"Imported datasheet #{did} ({path})")

            def failed(msg, path=path):
                QMessageBox.warning(self, "Import failed", f"{path}\n\n{msg}")
            run_async(lambda path=path: self.ctx.datasheets.import_pdf(path, vendor=vendor, source_url=url),
                      done, failed, busy=[self.btn_ds_import])

    def search_datasheets(self, part: str):
        res = self.ctx.datasheets.find(part)
        fill_table(self.ds_results, [[m.datasheet_id, m.title, m.level, m.matched_part, m.page] for m in res])
        return res

    def _on_open_ds(self):
        did = selected_id(self.ds_table)
        if did is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.ctx.datasheets.get(did)["stored_path"]))
