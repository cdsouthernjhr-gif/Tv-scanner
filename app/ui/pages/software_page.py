"""Software & OS Analyzer page."""
from __future__ import annotations

import json
import logging

from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QTabWidget, QVBoxLayout, QWidget)

from app.modules.software_analyzer.connectors import ADB_READ_ONLY
from app.modules.software_analyzer.service import CATEGORIES
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title
from app.ui.worker import run_async

log = logging.getLogger(__name__)
INVENTORY_TABS = [("application", "Applications"), ("library", "Libraries"), ("driver", "Drivers"),
                  ("network_interface", "Network"), ("display", "Display"), ("audio", "Audio")]


class SoftwarePage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self._devices: list[dict] = []
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Software Analyzer"))
        lay.addWidget(notice(
            "Combines evidence from analysed firmware, OCR of System Information photos, values you enter with a "
            "reference, and optional authorised read-only device queries. No TV is assumed to offer ADB, SSH, Telnet "
            "or an API; device queries only run when you start them and state your authorisation."))
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.project = ProjectSelector(ctx)
        self.project.currentIndexChanged.connect(self.load)
        top.addWidget(self.project, 1)
        self.btn_analyze = QPushButton("Analyze software")
        self.btn_analyze.clicked.connect(self._analyze_async)
        self.btn_report = QPushButton("OS Report (PDF)")
        self.btn_report.clicked.connect(self._guard(lambda: self._opened(self.ctx.software_reports.os_report_pdf(self.pid()))))
        top.addWidget(self.btn_analyze)
        top.addWidget(self.btn_report)
        lay.addLayout(top)
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self.summary = make_table(["Item", "Value", "Confidence", "Sources"])
        sw = QWidget()
        sl = QVBoxLayout(sw)
        sl.addWidget(self.summary, 1)
        self.conflicts = QLabel()
        self.conflicts.setWordWrap(True)
        self.conflicts.setStyleSheet("color: #f0d48a;")
        sl.addWidget(self.conflicts)
        self.tabs.addTab(sw, "Summary")
        self.inv_tables = {}
        for cat, label in INVENTORY_TABS:
            t = make_table(["Name", "Detail", "Source", "Conf."])
            self.inv_tables[cat] = t
            self.tabs.addTab(t, label)
        # manual entry
        mw = QWidget()
        ml = QVBoxLayout(mw)
        r = QHBoxLayout()
        self.m_cat = QComboBox()
        self.m_cat.addItems(CATEGORIES)
        self.m_name = QLineEdit()
        self.m_name.setPlaceholderText("value, e.g. Android 11 / T-KTM2AKUC-1500.5")
        self.m_ref = QLineEdit()
        self.m_ref.setPlaceholderText("reference, e.g. Settings > Support > About this TV")
        b = QPushButton("Add")
        b.clicked.connect(self._guard(self._add_manual))
        for x in (self.m_cat, self.m_name, self.m_ref, b):
            r.addWidget(x)
        ml.addLayout(r)
        ml.addWidget(QLabel("All facts (every source)"))
        self.all_facts = make_table(["Category", "Name", "Detail", "Source", "Reference", "Conf."])
        ml.addWidget(self.all_facts, 1)
        self.tabs.addTab(mw, "All facts / manual entry")
        # device
        dw = QWidget()
        dl = QVBoxLayout(dw)
        dl.addWidget(notice("Read-only queries only. UPnP: standard LAN discovery of the device description. "
                            "ADB: Android TVs only, after the owner enables debugging and accepts the prompt on the TV; "
                            f"allowed queries: {', '.join(ADB_READ_ONLY)}."))
        self.auth = QLineEdit()
        self.auth.setPlaceholderText("Authorisation (required), e.g. 'Customer-owned TV, owner consent, job 2026-118'")
        dl.addWidget(self.auth)
        r1 = QHBoxLayout()
        self.btn_upnp = QPushButton("Discover UPnP devices on LAN")
        self.btn_upnp.clicked.connect(self._upnp_async)
        self.upnp_pick = QComboBox()
        self.btn_link = QPushButton("Link selected device to project")
        self.btn_link.clicked.connect(self._guard(self._link_upnp))
        for x in (self.btn_upnp, self.upnp_pick, self.btn_link):
            r1.addWidget(x)
        dl.addLayout(r1)
        r2 = QHBoxLayout()
        self.adb_target = QLineEdit()
        self.adb_target.setPlaceholderText("ADB serial or LAN address:port (e.g. 192.168.1.50:5555)")
        self.btn_adb = QPushButton("Collect via ADB (read-only)")
        self.btn_adb.clicked.connect(self._adb_async)
        r2.addWidget(self.adb_target, 1)
        r2.addWidget(self.btn_adb)
        dl.addLayout(r2)
        self.dev_out = QPlainTextEdit()
        self.dev_out.setReadOnly(True)
        dl.addWidget(self.dev_out, 1)
        self.tabs.addTab(dw, "Device (authorised)")
        self.status = QLabel()
        lay.addWidget(self.status)
        self.refresh()

    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Software page action failed")
                QMessageBox.warning(self, "Software Analyzer", str(exc))
        return run

    def _opened(self, path):
        self.status.setText(f"Saved {path}")
        open_in_file_manager(path.parent)

    def pid(self):
        p = self.project.currentData()
        if p is None:
            raise ValueError("Register a TV project first")
        return p

    def refresh(self):
        self.project.reload()
        self.load()

    def load(self, *_):
        pid = self.project.currentData()
        if pid is None:
            return
        s = self.ctx.software.summary(pid)
        rows = []
        for cat in ("os", "os_version", "kernel", "build", "firmware_version", "bootloader", "device_info"):
            vals = s.get(cat) or []
            if not vals:
                rows.append([cat, "not determined", "", "no evidence"])
            for v in vals:
                rows.append([cat, v["value"], f"{v['confidence']:.0%}", " | ".join(v["sources"])])
        fill_table(self.summary, rows)
        self.conflicts.setText("\n".join("⚠ " + c for c in s["conflicts"]))
        facts = self.ctx.software.facts(pid)
        for cat, t in self.inv_tables.items():
            fill_table(t, [[f["name"], f["value"], f"{f['source_type']}: {f['source_ref']}", f"{f['confidence']:.0%}"]
                           for f in facts if f["category"] == cat])
        fill_table(self.all_facts, [[f["category"], f["name"], f["value"], f["source_type"], f["source_ref"],
                                     f"{f['confidence']:.0%}"] for f in facts])
        counts = ", ".join(f"{k.replace('_count', '')}: {v}" for k, v in s.items() if k.endswith("_count"))
        self.status.setText(f"OS: {s['os_best']} | {counts}")

    def analyze(self):
        s = self.ctx.software.analyze(self.pid())
        self.load()
        return s

    def _analyze_async(self):
        try:
            pid = self.pid()
        except ValueError as exc:
            QMessageBox.warning(self, "Software Analyzer", str(exc))
            return
        run_async(lambda: self.ctx.software.analyze(pid), lambda s: self.load(),
                  lambda m: QMessageBox.warning(self, "Software Analyzer", m), busy=[self.btn_analyze])

    def _add_manual(self):
        self.ctx.software.add_operator_fact(self.pid(), self.m_cat.currentText(), self.m_name.text().strip(), None,
                                            self.m_ref.text())
        self.m_name.clear()
        self.load()

    def _upnp_async(self):
        note = self.auth.text()
        self.dev_out.setPlainText("Discovering (3 s)…")

        def done(devs):
            self._devices = devs
            self.upnp_pick.clear()
            for d in devs:
                self.upnp_pick.addItem(f"{d.get('friendlyName') or d.get('modelName') or '?'} — "
                                       f"{d.get('manufacturer', '')} {d.get('modelNumber', '')} ({d['location']})")
            self.dev_out.setPlainText(json.dumps(devs, indent=1) if devs else "No UPnP devices answered.")
        run_async(lambda: self.ctx.software.upnp_discover(note), done,
                  lambda m: self.dev_out.setPlainText("Discovery failed: " + m), busy=[self.btn_upnp])

    def _link_upnp(self):
        i = self.upnp_pick.currentIndex()
        if i < 0:
            raise ValueError("Discover and select a device first")
        self.ctx.software.record_upnp_device(self.pid(), self._devices[i], self.auth.text())
        self.load()

    def _adb_async(self):
        try:
            pid = self.pid()
        except ValueError as exc:
            QMessageBox.warning(self, "ADB", str(exc))
            return
        target, note = self.adb_target.text().strip(), self.auth.text()
        self.dev_out.setPlainText("Querying via ADB (read-only)…")
        run_async(lambda: self.ctx.software.adb_collect(pid, target, note),
                  lambda sid: (self.dev_out.setPlainText(f"ADB session #{sid} stored."), self.load()),
                  lambda m: self.dev_out.setPlainText("ADB failed: " + m), busy=[self.btn_adb])
