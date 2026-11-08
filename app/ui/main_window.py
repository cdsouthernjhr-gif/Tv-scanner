from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QHBoxLayout, QListWidget, QMainWindow, QStackedWidget,
                               QStatusBar, QWidget)

from app.core.config import APP_NAME, APP_VERSION
from app.ui.pages.dashboard_page import DashboardPage
from app.ui.pages.firmware_library_page import FirmwareLibraryPage
from app.ui.pages.hardware_page import HardwarePage
from app.ui.pages.identification_page import IdentificationPage
from app.ui.pages.new_project_page import NewProjectPage
from app.ui.pages.planned_page import PLANNED, PlannedModulePage
from app.ui.pages.reports_page import ReportsPage
from app.ui.pages.settings_page import SettingsPage
from app.ui.pages.visual_scanner_page import VisualScannerPage
from app.ui.widgets import STYLESHEET

SIDEBAR = ["Dashboard", "New TV Project", "TV Identification", "Visual Scanner", "Hardware Analyzer",
           "Firmware Analyzer", "Universal Firmware Finder", "Firmware Library", "Software Analyzer",
           "Factory & Service Menu", "Compatibility Analyzer", "Firmware Upgrade Manager", "Reports",
           "Settings"]


class MainWindow(QMainWindow):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1360, 860)
        self.setStyleSheet(STYLESHEET)

        self.pages: dict[str, QWidget] = {
            "Dashboard": DashboardPage(ctx),
            "New TV Project": NewProjectPage(ctx),
            "TV Identification": IdentificationPage(ctx),
            "Firmware Library": FirmwareLibraryPage(ctx),
            "Reports": ReportsPage(ctx),
            "Settings": SettingsPage(ctx),
            "Visual Scanner": VisualScannerPage(ctx),
            "Hardware Analyzer": HardwarePage(ctx),
        }
        for name, (phase, desc) in PLANNED.items():
            if name not in self.pages:
                self.pages[name] = PlannedModulePage(name, phase, desc)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(280)
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.stack = QStackedWidget()
        for i, name in enumerate(SIDEBAR):
            label = f"{i + 1}. {name}"
            if isinstance(self.pages[name], PlannedModulePage):
                label += f"  · P{self.pages[name].phase}"
            self.sidebar.addItem(label)
            self.stack.addWidget(self.pages[name])
        self.sidebar.currentRowChanged.connect(self._switch)

        central = QWidget()
        lay = QHBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.sidebar)
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(f"Data: {ctx.config.data_dir} | DB schema v{ctx.db.schema_version}"
                                     " | Offline-first")

        np: NewProjectPage = self.pages["New TV Project"]  # type: ignore[assignment]
        np.open_project.connect(self.open_project)
        self.sidebar.setCurrentRow(0)

    def navigate(self, name: str) -> None:
        self.sidebar.setCurrentRow(SIDEBAR.index(name))

    def open_project(self, project_id: int) -> None:
        ident: IdentificationPage = self.pages["TV Identification"]  # type: ignore[assignment]
        self.navigate("TV Identification")
        ident.selector.select_project(project_id)

    def _switch(self, row: int) -> None:
        self.stack.setCurrentIndex(row)
        page = self.stack.currentWidget()
        if hasattr(page, "refresh"):
            page.refresh()
