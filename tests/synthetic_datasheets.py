"""Generate small synthetic datasheet PDFs for tests.

They are clearly marked SYNTHETIC TEST DOCUMENT and contain only the kind of
statements real datasheets make (ordering information, density, voltage,
package). They are not copies of any vendor document.
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def make_datasheet(path: Path, title: str, pages: list[list[str]]) -> Path:
    c = canvas.Canvas(str(path), pagesize=A4)
    c.setTitle(title)
    for lines in pages:
        y = 800
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "SYNTHETIC TEST DOCUMENT - " + title)
        c.setFont("Helvetica", 10)
        for ln in lines:
            y -= 18
            c.drawString(40, y, ln)
        c.showPage()
    c.save()
    return path


def ddr3_datasheet(path: Path) -> Path:
    return make_datasheet(path, "4Gb DDR3 SDRAM test sheet", [
        ["4Gb DDR3 SDRAM", "Features:", "VDD = 1.5V +/- 0.075V", "Data rate: DDR3-1600 (1600 Mbps)",
         "96-ball FBGA package", "Operating temperature 0 to 85 C"],
        ["Ordering Information", "K4B4G1646E-BYK0   256M x16   DDR3-1600   96 FBGA",
         "K4B4G0846E-BYK0   512M x8   DDR3-1600   78 FBGA"],
    ])


def spi_nor_datasheet(path: Path) -> Path:
    return make_datasheet(path, "W25Q64JV family test sheet", [
        ["64M-bit Serial NOR flash memory with SPI", "Single 2.7V to 3.6V supply",
         "133MHz clock operation", "Packages: SOIC-8, WSON-8", "-40 C to +85 C"],
        ["Ordering Information", "W25Q64JVSSIQ  SOIC-8 208mil", "W25Q64JVZPIQ  WSON-8 6x5mm"],
    ])
