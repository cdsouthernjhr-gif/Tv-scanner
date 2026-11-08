"""Firmware Upgrade Manager page."""
from __future__ import annotations

import json
import logging

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QTabWidget,
                               QVBoxLayout, QWidget)

from app.modules.upgrade_manager.adapters import METHODS
from app.modules.upgrade_manager.service import BASIC_FUNCTIONS, STEPS
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import ProjectSelector, fill_table, make_table, notice, page_title, selected_id
from app.ui.worker import run_async

log = logging.getLogger(__name__)
ICON = {"pending": "○", "passed": "✔", "done": "✔", "warning": "⚠", "failed": "✖", "instructions_only": "📄",
        "cancelled": "■"}


class _Progress(QObject):
    changed = Signal(int, int, str)


class UpgradePage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.sid = None
        self._cancel = False
        self._prog = _Progress()
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Firmware Upgrade Manager"))
        lay.addWidget(notice(
            "This application never writes to a TV, its flash memory, partitions or bootloader. Only the Official USB "
            "method can be executed — it prepares the USB stick exactly as documented and verifies the copy; the TV's "
            "own updater installs it. Execution requires a profile verified against its documentation AND a VERIFIED "
            "COMPATIBLE result. Every other method produces technician instructions and a report only."))
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self._build_profiles()
        self._build_session()
        self.status = QLabel()
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self._prog.changed.connect(self._on_progress)
        self.refresh()

    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Upgrade action failed")
                QMessageBox.warning(self, "Firmware Upgrade Manager", str(exc))
        return run

    # ---- profiles ---------------------------------------------------------------------------------
    def _build_profiles(self):
        w = QWidget()
        v = QVBoxLayout(w)
        self.ptable = make_table(["ID", "Manufacturer", "Model pattern", "Chassis", "Board", "Method", "Risk",
                                  "Verified", "Documentation"])
        v.addWidget(self.ptable, 1)
        form = QFormLayout()
        self.pf = {}
        for k, label in (("manufacturer", "Manufacturer *"), ("model_pattern", "Model pattern * (e.g. TESTTV*)"),
                         ("chassis", "Chassis"), ("mainboard_pattern", "Mainboard pattern"),
                         ("documentation_ref", "Documentation * (manual section / official page)"),
                         ("documentation_url", "Documentation URL"), ("package_pattern", "Package file pattern"),
                         ("usb_filesystems", "USB filesystem(s)"), ("usb_target_path", "Path on USB"),
                         ("usb_target_name", "File name on USB (empty = keep)"),
                         ("power_requirements", "Power requirements"), ("recovery_procedure", "Documented recovery")):
            self.pf[k] = QLineEdit()
            form.addRow(label, self.pf[k])
        self.p_method = QComboBox()
        for key, m in METHODS.items():
            self.p_method.addItem(f"{m.label}{'' if m.executes else '  (instructions only)'}", key)
        self.p_instr = QPlainTextEdit()
        self.p_instr.setMaximumHeight(60)
        self.p_rollback = QCheckBox("Rollback is documented by the manufacturer")
        form.addRow("Method", self.p_method)
        form.addRow("Documented steps", self.p_instr)
        form.addRow(self.p_rollback)
        v.addLayout(form)
        r = QHBoxLayout()
        b1 = QPushButton("Add profile")
        b1.clicked.connect(self._guard(self.add_profile))
        b2 = QPushButton("Mark selected profile as verified…")
        b2.clicked.connect(self._guard(self._verify_profile))
        r.addWidget(b1)
        r.addWidget(b2)
        r.addStretch()
        v.addLayout(r)
        self.tabs.addTab(w, "Upgrade profiles")

    def profile_values(self) -> dict:
        d = {k: w.text().strip() or None for k, w in self.pf.items()}
        d.update(method=self.p_method.currentData(), instructions=self.p_instr.toPlainText(),
                 rollback_documented=self.p_rollback.isChecked())
        return d

    def add_profile(self) -> int:
        pid = self.ctx.upgrades.add_profile(self.profile_values())
        self.refresh()
        return pid

    def _verify_profile(self):
        pid = selected_id(self.ptable)
        if pid is None:
            raise ValueError("Select a profile")
        p = self.ctx.upgrades.profile(pid)
        text, ok = QInputDialog.getText(self, "Verify profile",
                                        f"Confirm you checked this profile against:\n{p['documentation_ref']}\n\n"
                                        f"Type exactly: VERIFIED {p['manufacturer']}")
        if ok:
            self.ctx.upgrades.verify_profile(pid, text)
            self.refresh()

    # ---- session -------------------------------------------------------------------------------------
    def _build_session(self):
        w = QWidget()
        v = QVBoxLayout(w)
        r = QHBoxLayout()
        r.addWidget(QLabel("TV:"))
        self.project = ProjectSelector(self.ctx)
        self.project.currentIndexChanged.connect(self._load_project)
        r.addWidget(self.project, 2)
        r.addWidget(QLabel("Profile:"))
        self.profile = QComboBox()
        r.addWidget(self.profile, 2)
        r.addWidget(QLabel("Target firmware:"))
        self.target = QComboBox()
        r.addWidget(self.target, 2)
        bs = QPushButton("Start session")
        bs.clicked.connect(self._guard(self.start))
        r.addWidget(bs)
        v.addLayout(r)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Session:"))
        self.session_pick = QComboBox()
        self.session_pick.currentIndexChanged.connect(lambda *_: self.load_session(self.session_pick.currentData()))
        r2.addWidget(self.session_pick, 1)
        v.addLayout(r2)
        self.steps = make_table(["Step", "Status", "Summary"])
        v.addWidget(self.steps, 2)
        b = QHBoxLayout()
        for label, fn in (("1–3 Identify, check && validate", self.run_checks), ("4 Backup…", self._backup),
                          ("5 Prepare…", self._prepare), ("6 Execute", self._execute), ("Cancel copy", self._cancel_copy),
                          ("7 Verify…", self._verify), ("8 Recovery guidance", self._recovery),
                          ("Upgrade Report (PDF)", self._report)):
            btn = QPushButton(label)
            btn.clicked.connect(self._guard(fn))
            b.addWidget(btn)
            if label == "6 Execute":
                self.btn_exec = btn
        v.addLayout(b)
        self.progress = QProgressBar()
        v.addWidget(self.progress)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        v.addWidget(self.detail, 2)
        self.tabs.addTab(w, "Upgrade session")

    def refresh(self):
        profs = self.ctx.upgrades.profiles()
        fill_table(self.ptable, [[p["id"], p["manufacturer"], p["model_pattern"], p["chassis"], p["mainboard_pattern"],
                                  METHODS[p["method"]].label, p["risk_level"],
                                  f"yes ({p['verified_by']}, {p['verified_at']})" if p["verified"] else "NO",
                                  p["documentation_ref"]] for p in profs], ids=[p["id"] for p in profs])
        self.project.reload()
        self._load_project()

    def _load_project(self, *_):
        pid = self.project.currentData()
        self.profile.clear()
        self.target.clear()
        self.session_pick.blockSignals(True)
        self.session_pick.clear()
        if pid is not None:
            proj = self.ctx.projects.get(pid)
            for p in self.ctx.upgrades.applicable_profiles(proj):
                self.profile.addItem(f"#{p['id']} {METHODS[p['method']].label} — "
                                     f"{'verified' if p['verified'] else 'NOT verified'}", p["id"])
            for f in self.ctx.library.list(project_id=pid):
                self.target.addItem(f"#{f.id} {f.original_filename} ({f.category}, version {f.version or '?'})", f.id)
            for s in self.ctx.upgrades.sessions(pid):
                self.session_pick.addItem(f"#{s['id']} {s['method']} — {s['status']}", s["id"])
        self.session_pick.blockSignals(False)
        self.load_session(self.session_pick.currentData())

    def start(self) -> int:
        pid, prof, fw = self.project.currentData(), self.profile.currentData(), self.target.currentData()
        if None in (pid, prof, fw):
            raise ValueError("Select a TV, an applicable profile and a target firmware")
        sid = self.ctx.upgrades.start(pid, prof, fw)
        self._load_project()
        self.session_pick.setCurrentIndex(self.session_pick.findData(sid))
        return sid

    def load_session(self, sid):
        self.sid = sid
        if sid is None:
            fill_table(self.steps, [])
            self.detail.clear()
            return
        s = self.ctx.upgrades.session(sid)
        rows = []
        for st in STEPS:
            d = s["steps"].get(st, {"status": "pending"})
            summ = d.get("verdict") or d.get("reason") or ", ".join(d.get("missing_required", []) or []) or ""
            rows.append([st, f"{ICON.get(d['status'], '?')} {d['status']}", summ])
        fill_table(self.steps, rows)
        self.detail.setPlainText(json.dumps({k: v for k, v in s["steps"].items() if v.get("status") != "pending"},
                                            indent=1, default=str)[:30000] + "\n\nLOG\n" + (s["log"] or ""))

    def _sid(self):
        if self.sid is None:
            raise ValueError("Start or select a session")
        return self.sid

    def run_checks(self):
        sid = self._sid()
        U = self.ctx.upgrades
        U.step_identification(sid)
        U.step_compatibility(sid)
        U.step_validation(sid)
        self.load_session(sid)

    def _backup(self):
        sid = self._sid()
        text, ok = QInputDialog.getText(self, "Backup", "Official configuration export performed? Describe it "
                                                        "(or leave empty if none exists):")
        if ok:
            self.ctx.upgrades.step_backup(sid, text or None)
            self.load_session(sid)

    def _prepare(self):
        sid = self._sid()
        U = self.ctx.upgrades
        risks = "\n".join(U.risks(sid))
        if QMessageBox.warning(self, "Risks", risks + "\n\nContinue to preparation?",
                               QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        prof = U.profile(U.session(sid)["profile_id"])
        usb = None
        if METHODS[prof["method"]].executes:
            usb = QFileDialog.getExistingDirectory(self, "Select the USB drive (root)")
        power = QMessageBox.question(self, "Power", "Stable power for TV (and PC) confirmed?") == QMessageBox.Yes
        conn = QMessageBox.question(self, "Connection", "USB stick / connection ready as documented?") == QMessageBox.Yes
        text, ok = QInputDialog.getText(self, "Confirm", f"Type exactly: {U.confirmation_phrase(sid)}")
        if ok:
            U.step_preparation(sid, power, conn, text, usb)
            self.load_session(sid)

    def _execute(self):
        sid = self._sid()
        self._cancel = False
        self.progress.setValue(0)
        run_async(lambda: self.ctx.upgrades.step_execution(
                      sid, progress=lambda d, t, s: self._prog.changed.emit(d, t, s), cancel=lambda: self._cancel),
                  lambda r: (self.load_session(sid), self.status.setText(f"Execution: {r['status']}")),
                  lambda m: QMessageBox.warning(self, "Execute", m), busy=[self.btn_exec])

    def _on_progress(self, done, total, stage):
        self.progress.setMaximum(max(1, total))
        self.progress.setValue(done)
        self.status.setText(f"{stage}: {done:,} / {total:,} bytes")

    def _cancel_copy(self):
        # Only the PC-side copy can be cancelled (partial file is removed). Never interrupt the TV's own update.
        self._cancel = True

    def _verify(self):
        sid = self._sid()
        ver, ok = QInputDialog.getText(self, "Verification", "Firmware version shown by the TV after the update:")
        if not ok:
            return
        boot = QMessageBox.question(self, "Boot", "Did the TV boot normally?") == QMessageBox.Yes
        model = QMessageBox.question(self, "Model", "Does the TV still report the correct model?") == QMessageBox.Yes
        funcs = {f: QMessageBox.question(self, "Basic functions", f"OK: {f}?") == QMessageBox.Yes for f in BASIC_FUNCTIONS}
        self.ctx.upgrades.step_verification(sid, ver, model, None, boot, funcs)
        self.load_session(sid)

    def _recovery(self):
        g = self.ctx.upgrades.recovery_guidance(self._sid())
        self.load_session(self.sid)
        QMessageBox.information(self, "Recovery guidance", "\n".join(g["guidance"]))

    def _report(self):
        path = self.ctx.upgrade_reports.upgrade_pdf(self._sid())
        open_in_file_manager(path.parent)
