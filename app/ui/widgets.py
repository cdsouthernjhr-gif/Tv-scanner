"""Shared UI helpers."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFrame, QLabel, QMessageBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView,
                               QAbstractItemView)

STYLESHEET = """
QMainWindow, QWidget { background: #14181f; color: #e6e9ef; font-size: 10pt; }
QListWidget#sidebar { background: #0e1117; border: none; padding: 6px; }
QListWidget#sidebar::item { padding: 8px 10px; border-radius: 6px; }
QListWidget#sidebar::item:selected { background: #2b5797; color: white; }
QLabel#pageTitle { font-size: 16pt; font-weight: 600; padding-bottom: 6px; }
QFrame#card { background: #1d2430; border: 1px solid #2c3647; border-radius: 10px; }
QFrame#card QLabel { background: transparent; }
QLabel#cardValue { font-size: 20pt; font-weight: 700; color: #6fb1ff; }
QLabel#cardTitle { color: #9aa6b8; }
QLabel#notice { background: #2a2416; border: 1px solid #6b5a2a; border-radius: 6px; padding: 8px; color: #f0d48a; }
QLineEdit, QComboBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
    background: #0f141b; border: 1px solid #2c3647; border-radius: 5px; padding: 4px; }
QPushButton { background: #2b5797; border: none; border-radius: 5px; padding: 6px 14px; color: white; }
QPushButton:hover { background: #3768b0; }
QPushButton:disabled { background: #39414d; color: #8b93a0; }
QTableWidget { background: #0f141b; gridline-color: #2c3647; alternate-background-color: #151b24; }
QHeaderView::section { background: #1d2430; padding: 4px; border: none; border-right: 1px solid #2c3647; }
"""


def page_title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("pageTitle")
    return lbl


def notice(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("notice")
    lbl.setWordWrap(True)
    return lbl


class StatCard(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        self.value = QLabel("0")
        self.value.setObjectName("cardValue")
        t = QLabel(title)
        t.setObjectName("cardTitle")
        lay.addWidget(self.value)
        lay.addWidget(t)

    def set_value(self, v) -> None:
        self.value.setText(str(v))


def make_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    t.horizontalHeader().setStretchLastSection(True)
    t.verticalHeader().setVisible(False)
    return t


def fill_table(table: QTableWidget, rows: list[list], ids: list | None = None) -> None:
    table.setRowCount(0)
    for r, row in enumerate(rows):
        table.insertRow(r)
        for c, val in enumerate(row):
            item = QTableWidgetItem("" if val is None else str(val))
            if ids is not None and c == 0:
                item.setData(Qt.UserRole, ids[r])
            table.setItem(r, c, item)
    table.resizeColumnsToContents()


def selected_id(table: QTableWidget):
    row = table.currentRow()
    if row < 0:
        return None
    item = table.item(row, 0)
    return item.data(Qt.UserRole) if item else None


class ProjectSelector(QComboBox):
    """Combo box listing TV projects; data = project id."""

    def __init__(self, ctx, allow_none: bool = False):
        super().__init__()
        self.ctx = ctx
        self.allow_none = allow_none
        self.reload()

    def reload(self) -> None:
        current = self.currentData()
        self.blockSignals(True)
        self.clear()
        if self.allow_none:
            self.addItem("— no project —", None)
        for p in self.ctx.projects.list():
            ident = " ".join(x for x in (p.manufacturer, p.model_number) if x) or "unidentified"
            self.addItem(f"#{p.id} {p.name} — {ident}", p.id)
        if current is not None:
            idx = self.findData(current)
            if idx >= 0:
                self.setCurrentIndex(idx)
        self.blockSignals(False)

    def select_project(self, project_id: int) -> None:
        idx = self.findData(project_id)
        if idx >= 0:
            self.setCurrentIndex(idx)


def ndarray_to_pixmap(img):
    """Convert an OpenCV image (gray or BGR numpy array) to a QPixmap (copied)."""
    import numpy as np
    from PySide6.QtGui import QImage, QPixmap
    a = np.ascontiguousarray(img)
    if a.ndim == 2:
        qi = QImage(a.data, a.shape[1], a.shape[0], a.strides[0], QImage.Format_Grayscale8)
    else:
        rgb = np.ascontiguousarray(a[:, :, ::-1])
        qi = QImage(rgb.data, rgb.shape[1], rgb.shape[0], rgb.strides[0], QImage.Format_RGB888)
    return QPixmap.fromImage(qi.copy())


def error_box(parent: QWidget, title: str, exc: Exception | str) -> None:
    QMessageBox.critical(parent, title, str(exc))
