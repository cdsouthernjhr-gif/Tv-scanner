"""Reusable form for TV project identification fields."""
from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QDoubleSpinBox, QFormLayout, QLineEdit,
                               QPlainTextEdit, QWidget)

from app.services.project_service import PLATFORMS, TV_TYPES, TVProject


class ProjectForm(QWidget):
    TEXT_FIELDS = [
        ("name", "Project name *"), ("manufacturer", "Manufacturer / brand"),
        ("model_number", "Model number"), ("serial_number", "Serial number"),
        ("product_code", "Product code"), ("chassis", "Chassis"),
        ("mainboard", "Mainboard number"), ("pcb_revision", "PCB revision"),
        ("firmware_version", "Firmware version"),
    ]

    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        self.inputs: dict[str, QLineEdit] = {}
        for key, label in self.TEXT_FIELDS:
            w = QLineEdit()
            w.setPlaceholderText("leave empty if unknown")
            self.inputs[key] = w
            form.addRow(label, w)
        self.size = QDoubleSpinBox()
        self.size.setRange(0, 300)
        self.size.setDecimals(1)
        self.size.setSpecialValueText("unknown")
        self.size.setSuffix(" in")
        form.addRow("Screen size", self.size)
        self.tv_type = QComboBox()
        self.tv_type.addItems(TV_TYPES)
        form.addRow("TV type", self.tv_type)
        self.platform = QComboBox()
        self.platform.setEditable(True)
        self.platform.addItems(PLATFORMS)
        form.addRow("Platform / OS", self.platform)
        self.notes = QPlainTextEdit()
        self.notes.setMaximumHeight(70)
        form.addRow("Notes", self.notes)

    def values(self) -> dict:
        v = {k: w.text() for k, w in self.inputs.items()}
        v["screen_size_inches"] = self.size.value() or None
        v["tv_type"] = self.tv_type.currentText()
        v["platform"] = self.platform.currentText()
        v["notes"] = self.notes.toPlainText()
        return v

    def set_values(self, p: TVProject | None) -> None:
        for k, w in self.inputs.items():
            w.setText("" if p is None else (getattr(p, k) or ""))
        self.size.setValue(0 if p is None or p.screen_size_inches is None else p.screen_size_inches)
        self.tv_type.setCurrentText("" if p is None else (p.tv_type or ""))
        self.platform.setCurrentText("" if p is None else (p.platform or ""))
        self.notes.setPlainText("" if p is None else (p.notes or ""))

    def clear(self) -> None:
        self.set_values(None)
