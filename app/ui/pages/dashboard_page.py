from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QLabel, QVBoxLayout, QWidget

from app.services.dashboard_service import collect_stats
from app.ui.widgets import StatCard, fill_table, make_table, page_title


class DashboardPage(QWidget):
    CARDS = [("total_projects", "Total TV Projects"), ("identified", "Identified TV"),
             ("unknown", "Unknown / partial TV"), ("firmware_in_library", "Firmware in Library"),
             ("firmware_analyzed", "Firmware Analyzed"), ("firmware_found", "Firmware Found (search)"),
             ("verified_firmware", "Verified Firmware"), ("upgrade_sessions", "Upgrade History")]

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Dashboard"))
        grid = QGridLayout()
        self.cards: dict[str, StatCard] = {}
        for i, (key, title) in enumerate(self.CARDS):
            card = StatCard(title)
            self.cards[key] = card
            grid.addWidget(card, i // 4, i % 4)
        lay.addLayout(grid)
        lay.addWidget(QLabel("Recent scans"))
        self.recent = make_table(["Session", "Project", "Type", "Summary", "Started (UTC)", "ID status"])
        lay.addWidget(self.recent, 1)
        self.refresh()

    def refresh(self) -> None:
        s = collect_stats(self.ctx.db)
        for key, card in self.cards.items():
            card.set_value(getattr(s, key))
        fill_table(self.recent, [[r["id"], r["project_name"], r["session_type"], r["summary"],
                                  r["started_at"], r["identification_status"]] for r in s.recent_scans])
