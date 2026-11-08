"""Honest placeholder for modules scheduled in later phases.

These pages do not pretend to work: they state which phase delivers the
module and what it will do.
"""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.ui.widgets import notice, page_title


class PlannedModulePage(QWidget):
    def __init__(self, title: str, phase: int, description: str):
        super().__init__()
        self.phase = phase
        lay = QVBoxLayout(self)
        lay.addWidget(page_title(title))
        lay.addWidget(notice(f"NOT IMPLEMENTED YET — scheduled for Phase {phase}. "
                             "No results are produced by this page in the current build."))
        d = QLabel(description)
        d.setWordWrap(True)
        lay.addWidget(d)
        lay.addStretch()


PLANNED: dict = {}   # all modules of the specification are implemented

