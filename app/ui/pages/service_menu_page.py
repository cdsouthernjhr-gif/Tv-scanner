"""Factory & Service Menu page."""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from app.modules.service_menu.service import MENU_CATEGORIES, RISK_LEVELS, SOURCE_TYPES
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id

log = logging.getLogger(__name__)


class ServiceMenuPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Factory & Service Menu"))
        lay.addWidget(notice(
            "Database of service/factory menus documented and sanctioned by manufacturers. Every record must cite "
            "official documentation (service manual page or official web page). No password guessing, brute force "
            "or bypass is supported. This application never changes TV settings itself — changes you make are "
            "planned, backed up (when a documented backup exists), confirmed and recorded here."))
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self._build_db_tab()
        self._build_project_tab()
        self._build_manual_tab()
        self.status = QLabel()
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.refresh()

    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Service menu action failed")
                QMessageBox.warning(self, "Factory & Service Menu", str(exc))
        return run

    # ---- database tab ------------------------------------------------------------------------
    def _build_db_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        f = QHBoxLayout()
        self.f_mfr = QLineEdit()
        self.f_mfr.setPlaceholderText("manufacturer filter")
        self.f_cat = QComboBox()
        self.f_cat.addItem("all categories", None)
        for c in MENU_CATEGORIES:
            self.f_cat.addItem(c, c)
        self.f_text = QLineEdit()
        self.f_text.setPlaceholderText("model / chassis / platform / text")
        for x in (self.f_mfr, self.f_text):
            x.textChanged.connect(self.load_db)
        self.f_cat.currentIndexChanged.connect(self.load_db)
        for x in (self.f_mfr, self.f_cat, self.f_text):
            f.addWidget(x)
        for label, fn in (("Import JSON/CSV…", self._import), ("Export JSON", lambda: self._export("json")),
                          ("Export CSV", lambda: self._export("csv")), ("Delete selected", self._delete)):
            b = QPushButton(label)
            b.clicked.connect(self._guard(fn))
            f.addWidget(b)
        v.addLayout(f)
        self.table = make_table(["ID", "Manufacturer", "Model pattern", "Chassis", "Platform", "Category",
                                 "Access", "Function", "Availability", "Risk", "Backup", "Documentation"])
        self.table.itemSelectionChanged.connect(self._fill_form_from_selection)
        v.addWidget(self.table, 2)
        form = QFormLayout()
        self.e = {}
        for key, label in (("manufacturer", "Manufacturer *"), ("model_pattern", "Model pattern (e.g. UA55AU*)"),
                           ("chassis", "Chassis"), ("platform", "Platform"), ("firmware_version", "Firmware version"),
                           ("region", "Region"), ("access_procedure", "Documented access procedure"),
                           ("function_description", "Function"), ("access_availability", "Access availability"),
                           ("backup_mechanism", "Documented backup mechanism"),
                           ("official_documentation", "Official documentation * (title, section/page or URL)"),
                           ("notes", "Notes")):
            self.e[key] = QLineEdit()
            form.addRow(label, self.e[key])
        self.e_cat = QComboBox()
        self.e_cat.addItems(MENU_CATEGORIES)
        self.e_risk = QComboBox()
        self.e_risk.addItems(RISK_LEVELS)
        self.e_risk.setCurrentText("high")
        self.e_src = QComboBox()
        self.e_src.addItems(SOURCE_TYPES)
        self.e_doc = QComboBox()
        self.e_page = QSpinBox()
        self.e_page.setRange(0, 5000)
        self.e_page.setSpecialValueText("—")
        form.addRow("Menu category *", self.e_cat)
        form.addRow("Configuration risk", self.e_risk)
        form.addRow("Source type", self.e_src)
        form.addRow("Document in library", self.e_doc)
        form.addRow("Page", self.e_page)
        v.addLayout(form)
        b = QHBoxLayout()
        ba = QPushButton("Add record")
        ba.clicked.connect(self._guard(self.add_from_form))
        bu = QPushButton("Update selected")
        bu.clicked.connect(self._guard(self._update_selected))
        b.addWidget(ba)
        b.addWidget(bu)
        b.addStretch()
        v.addLayout(b)
        self.tabs.addTab(w, "Service menu database")

    def form_values(self) -> dict:
        d = {k: w.text().strip() or None for k, w in self.e.items()}
        d.update(menu_category=self.e_cat.currentText(), configuration_risk=self.e_risk.currentText(),
                 source_type=self.e_src.currentText(), document_id=self.e_doc.currentData(),
                 document_page=self.e_page.value() or None)
        return d

    def add_from_form(self) -> int:
        rid = self.ctx.service_menus.add(self.form_values())
        self.load_db()
        self.status.setText(f"Record #{rid} added.")
        return rid

    def _update_selected(self):
        rid = selected_id(self.table)
        if rid is None:
            raise ValueError("Select a record")
        self.ctx.service_menus.update(rid, self.form_values())
        self.load_db()

    def _fill_form_from_selection(self):
        rid = selected_id(self.table)
        if rid is None:
            return
        r = self.ctx.service_menus.get(rid)
        for k, w in self.e.items():
            w.setText(r.get(k) or "")
        self.e_cat.setCurrentText(r["menu_category"])
        self.e_risk.setCurrentText(r["configuration_risk"])
        self.e_src.setCurrentText(r["source_type"])
        self.e_doc.setCurrentIndex(max(0, self.e_doc.findData(r["document_id"])))
        self.e_page.setValue(r["document_page"] or 0)

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import service menu records", "", "Records (*.json *.csv)")
        if path:
            ok, rejected = self.ctx.service_menus.import_file(Path(path))
            self.load_db()
            QMessageBox.information(self, "Import", f"{ok} imported, {len(rejected)} rejected.\n\n" + "\n".join(rejected[:20]))

    def _export(self, fmt):
        d = self.ctx.config.reports_dir / "service_menus"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"service_menus.{fmt}"
        n = (self.ctx.service_menus.export_json if fmt == "json" else self.ctx.service_menus.export_csv)(path)
        self.status.setText(f"{n} record(s) exported to {path}")
        open_in_file_manager(d)

    def _delete(self):
        rid = selected_id(self.table)
        if rid is not None and QMessageBox.question(self, "Delete", f"Delete record #{rid}?") == QMessageBox.Yes:
            self.ctx.service_menus.delete(rid)
            self.load_db()

    # ---- project tab ----------------------------------------------------------------------------------
    def _build_project_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx := self.ctx)
        self.project.currentIndexChanged.connect(self.load_project)
        top.addWidget(self.project, 1)
        br = QPushButton("Service Menu Report (PDF)")
        br.clicked.connect(self._guard(lambda: self._opened(ctx.software_reports.service_report_pdf(self.project.currentData()))))
        top.addWidget(br)
        v.addLayout(top)
        v.addWidget(QLabel("Documented menus that apply to this TV"))
        self.applicable = make_table(["ID", "Category", "Access", "Function", "Risk", "Backup", "Documentation", "Why"])
        v.addWidget(self.applicable, 1)
        r = QHBoxLayout()
        self.a_setting = QLineEdit()
        self.a_setting.setPlaceholderText("setting")
        self.a_old = QLineEdit()
        self.a_old.setPlaceholderText("current value (as read on the TV)")
        self.a_new = QLineEdit()
        self.a_new.setPlaceholderText("new value")
        self.a_reason = QLineEdit()
        self.a_reason.setPlaceholderText("reason")
        bp = QPushButton("Plan change for selected menu")
        bp.clicked.connect(self._guard(self._plan))
        for x in (self.a_setting, self.a_old, self.a_new, self.a_reason, bp):
            r.addWidget(x)
        v.addLayout(r)
        v.addWidget(QLabel("Service actions"))
        self.actions = make_table(["ID", "Setting", "Old", "New", "Status", "Backup required", "Backup", "Confirmed",
                                   "Result"])
        v.addWidget(self.actions, 1)
        r2 = QHBoxLayout()
        for label, fn in (("Record backup…", self._backup), ("Confirm…", self._confirm),
                          ("Mark performed…", self._performed), ("Cancel", self._cancel)):
            b = QPushButton(label)
            b.clicked.connect(self._guard(fn))
            r2.addWidget(b)
        r2.addStretch()
        v.addLayout(r2)
        self.tabs.addTab(w, "TV project && service actions")

    def _opened(self, path):
        self.status.setText(f"Saved {path}")
        open_in_file_manager(path.parent)

    def load_project(self, *_):
        pid = self.project.currentData()
        if pid is None:
            fill_table(self.applicable, [])
            fill_table(self.actions, [])
            return
        recs = self.ctx.service_menus.applicable(self.ctx.projects.get(pid))
        fill_table(self.applicable, [[r["id"], r["menu_category"], r["access_procedure"], r["function_description"],
                                      r["configuration_risk"], r["backup_mechanism"] or "none documented",
                                      r["official_documentation"], r["applies_because"]] for r in recs],
                   ids=[r["id"] for r in recs])
        acts = self.ctx.service_menus.actions(pid)
        fill_table(self.actions, [[a["id"], a["setting"], a["old_value"], a["new_value"], a["status"],
                                   "yes" if a["backup_required"] else "no", a["backup_evidence"],
                                   f"{a['confirmed_by'] or ''} {a['confirmed_at'] or ''}", a["result"]] for a in acts],
                   ids=[a["id"] for a in acts])

    def _plan(self):
        mid = selected_id(self.applicable)
        if mid is None:
            raise ValueError("Select an applicable documented menu record")
        self.ctx.service_menus.plan_action(self.project.currentData(), mid, self.a_setting.text(), self.a_new.text(),
                                           self.a_reason.text(), self.a_old.text() or None)
        self.load_project()

    def _aid(self):
        aid = selected_id(self.actions)
        if aid is None:
            raise ValueError("Select a service action")
        return aid

    def _backup(self):
        aid = self._aid()
        text, ok = QInputDialog.getText(self, "Backup", "Describe the backup (file name, USB export, photo evidence #):")
        if ok:
            self.ctx.service_menus.record_backup(aid, text)
            self.load_project()

    def _confirm(self):
        aid = self._aid()
        phrase = self.ctx.service_menus.confirmation_phrase(aid)
        text, ok = QInputDialog.getText(self, "Confirm change", f"This changes a factory setting.\nType exactly:\n{phrase}")
        if ok:
            self.ctx.service_menus.confirm(aid, text)
            self.load_project()

    def _performed(self):
        aid = self._aid()
        text, ok = QInputDialog.getText(self, "Result", "Describe the result (e.g. picture OK after change):")
        if ok:
            self.ctx.service_menus.mark_performed(aid, text)
            self.load_project()

    def _cancel(self):
        self.ctx.service_menus.cancel(self._aid(), "cancelled by operator")
        self.load_project()

    # ---- service manual tab ----------------------------------------------------------------------------
    def _build_manual_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Find service-mode passages in a service manual (import PDFs in Hardware Analyzer → "
                           "Datasheet library). Use a passage to create a record that cites its page."))
        r = QHBoxLayout()
        self.doc = QComboBox()
        b = QPushButton("Find passages")
        b.clicked.connect(self._guard(self.find_passages))
        r.addWidget(self.doc, 1)
        r.addWidget(b)
        v.addLayout(r)
        self.passages = make_table(["Page", "Keyword", "Excerpt"])
        self.passages.itemSelectionChanged.connect(self._passage_to_form)
        v.addWidget(self.passages, 1)
        self.passage_text = QPlainTextEdit()
        self.passage_text.setReadOnly(True)
        self.passage_text.setMaximumHeight(100)
        v.addWidget(self.passage_text)
        self.tabs.addTab(w, "Service manual search")

    def find_passages(self):
        did = self.doc.currentData()
        if did is None:
            raise ValueError("Import a service manual PDF first (Hardware Analyzer → Datasheet library)")
        self._passages = self.ctx.service_menus.find_passages(did)
        fill_table(self.passages, [[p["page"], p["keyword"], p["excerpt"]] for p in self._passages],
                   ids=list(range(len(self._passages))))
        return self._passages

    def _passage_to_form(self):
        i = selected_id(self.passages)
        if i is None:
            return
        p = self._passages[i]
        self.passage_text.setPlainText(p["excerpt"])
        self.e_doc.setCurrentIndex(max(0, self.e_doc.findData(self.doc.currentData())))
        self.e_page.setValue(p["page"])
        self.status.setText(f"Document and page {p['page']} copied to the record form (Service menu database tab).")

    # ---- refresh ----------------------------------------------------------------------------------------
    def load_db(self, *_):
        recs = self.ctx.service_menus.list(self.f_mfr.text().strip() or None, self.f_cat.currentData(),
                                           self.f_text.text().strip() or None)
        fill_table(self.table, [[r["id"], r["manufacturer"], r["model_pattern"], r["chassis"], r["platform"],
                                 r["menu_category"], r["access_procedure"], r["function_description"],
                                 r["access_availability"], r["configuration_risk"], r["backup_mechanism"],
                                 r["official_documentation"]] for r in recs], ids=[r["id"] for r in recs])

    def refresh(self):
        self.project.reload()
        docs = self.ctx.datasheets.list()
        for combo, none_label in ((self.doc, None), (self.e_doc, "— none —")):
            keep = combo.currentData()
            combo.clear()
            if none_label:
                combo.addItem(none_label, None)
            for d in docs:
                combo.addItem(f"#{d['id']} {d['title'] or d['original_filename']}", d["id"])
            if keep is not None:
                combo.setCurrentIndex(max(0, combo.findData(keep)))
        self.load_db()
        self.load_project()
