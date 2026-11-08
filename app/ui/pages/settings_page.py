from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QVBoxLayout, QWidget)

from app.security.secrets import KNOWN_KEYS

from app.core.config import APP_VERSION
from app.services.external_tools import detect_tools
from app.ui.widgets import fill_table, make_table, notice, page_title


class SettingsPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Settings"))
        form = QFormLayout()
        c = ctx.config
        self.labels = {
            "Application version": QLabel(APP_VERSION),
            "Data directory": QLabel(str(c.data_dir)),
            "Database": QLabel(str(c.database_path)),
            "Schema version": QLabel(str(ctx.db.schema_version)),
            "Firmware library": QLabel(str(c.firmware_library_dir)),
            "Analysis workspace": QLabel(str(c.workspace_dir)),
            "Logs": QLabel(str(c.logs_dir)),
            "Offline mode": QLabel("ON" if c.get("network.offline_mode", True) else "OFF"),
        }
        for k, w in self.labels.items():
            w.setWordWrap(True)
            form.addRow(k, w)
        lay.addLayout(form)
        lay.addWidget(QLabel("External tools (optional; configure paths in settings.json → 'tools')"))
        self.tools = make_table(["Tool", "Status", "Path"])
        lay.addWidget(self.tools, 1)
        lay.addWidget(QLabel("OCR engines"))
        self.ocr = make_table(["Engine", "Status", "Languages"])
        lay.addWidget(self.ocr)
        btn = QPushButton("Re-detect tools")
        btn.clicked.connect(self.refresh)
        lay.addWidget(btn)
        lay.addWidget(QLabel("Online sources (Universal Firmware Finder)"))
        net = QFormLayout()
        self.offline = QCheckBox("Offline mode (no network access at all)")
        self.offline.setChecked(bool(ctx.config.get("network.offline_mode", True)))
        net.addRow(self.offline)
        self.cfg_fields = {}
        for key, label in (("finder.google_cse_cx", "Google Programmable Search engine ID (cx)"),
                           ("finder.searxng_url", "SearXNG instance URL"),
                           ("finder.gitlab_url", "GitLab URL (default gitlab.com)")):
            w = QLineEdit(str(ctx.config.get(key, "") or ""))
            self.cfg_fields[key] = w
            net.addRow(label, w)
        b = QPushButton("Save network settings")
        b.clicked.connect(self.save_network)
        net.addRow(b)
        lay.addLayout(net)
        keys = QHBoxLayout()
        self.key_name = QComboBox()
        for k, d in KNOWN_KEYS.items():
            self.key_name.addItem(k, k)
            self.key_name.setItemData(self.key_name.count() - 1, d, Qt.ToolTipRole)
        self.key_value = QLineEdit()
        self.key_value.setEchoMode(QLineEdit.Password)
        self.key_value.setPlaceholderText("paste key (empty = delete)")
        kb = QPushButton("Store key")
        kb.clicked.connect(self.store_key)
        for w in (QLabel("API key:"), self.key_name, self.key_value, kb):
            keys.addWidget(w)
        lay.addLayout(keys)
        self.key_status = QLabel()
        self.key_status.setWordWrap(True)
        lay.addWidget(self.key_status)
        self._key_status()
        self.refresh()

    def save_network(self):
        self.ctx.config.set("network.offline_mode", self.offline.isChecked())
        for k, w in self.cfg_fields.items():
            self.ctx.config.set(k, w.text().strip())
        self.ctx.config.save()
        self.ctx.audit.record("settings.network", offline=self.offline.isChecked())
        self.labels["Offline mode"].setText("ON" if self.offline.isChecked() else "OFF")

    def store_key(self):
        where = self.ctx.secrets.set(self.key_name.currentData(), self.key_value.text())
        self.ctx.audit.record("settings.api_key", key=self.key_name.currentData(), stored_in=where)  # never the value
        self.key_value.clear()
        self._key_status(f"Stored in {where}.")

    def _key_status(self, extra: str = ""):
        S = self.ctx.secrets
        self.key_status.setText(f"Key storage: {S.backend_name}" + ("" if S.secure else
                                " — WARNING: no secure credential store, keys are kept for this session only") + "<br>" +
                                "; ".join(f"{k}: {S.mask(S.get(k))}" for k in KNOWN_KEYS) + (f"<br>{extra}" if extra else ""))

    def refresh(self) -> None:
        ident = self.ctx.identification
        ident._engines = None  # re-detect
        rows = []
        for name, eng in ident.engines().items():
            ok = eng.available()
            langs = ", ".join(eng.languages()) if ok and hasattr(eng, "languages") else ""
            rows.append([name, eng.version() if ok else "not installed", langs])
        fill_table(self.ocr, rows)
        fill_table(self.tools, [[t.label, "available" if t.available else "not found", t.path or ""]
                                for t in detect_tools(self.ctx.config)])
