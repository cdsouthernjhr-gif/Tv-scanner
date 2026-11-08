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


PLANNED = {
    "Universal Firmware Finder": (5, "Provider-based search (official manufacturer pages, GitHub REST API, "
                                     "GitLab, technical docs, archives, community) with rate limiting, "
                                     "robots.txt compliance, deduplication, provenance and match scoring."),
    "Software Analyzer": (6, "OS/kernel/build identification from system menus, official diagnostics "
                             "and firmware contents."),
    "Factory & Service Menu": (6, "Database of documented, manufacturer-sanctioned service menus. "
                                  "No brute-force or authentication bypass."),
    "Compatibility Analyzer": (7, "Evidence-based verdicts (VERIFIED COMPATIBLE … INSUFFICIENT EVIDENCE) "
                                  "with reasons for every decision."),
    "Firmware Upgrade Manager": (7, "Per-model upgrade profiles and plugin adapters for official methods "
                                    "only; validation, backup, explicit confirmation, audit log, "
                                    "recovery guidance. No automatic flashing."),
}
