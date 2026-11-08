from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QPushButton, QVBoxLayout, QWidget

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
        lay.addWidget(notice("API keys (e.g. GitHub token) will be stored via Windows Credential Manager "
                             "in Phase 5 — never in plain-text settings."))
        self.refresh()

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
