"""Firmware Analyzer page."""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from app.modules.firmware_analyzer.hexview import hexdump, parse_offset
from app.modules.reports.firmware_report import CAT_COLORS
from app.ui.pages.firmware_library_page import open_in_file_manager
from app.ui.widgets import fill_table, make_table, notice, page_title, selected_id
from app.ui.worker import run_async

log = logging.getLogger(__name__)
HEX_PAGE = 4096


class StructureMap(QWidget):
    """Entropy curve + top-level component bars. Click selects the component under the cursor."""
    component_clicked = Signal(int)   # offset

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(180)
        self.file_size = 0
        self.blocks: list[float] = []
        self.components: list[dict] = []
        self.setMouseTracking(True)

    def set_data(self, file_size: int, blocks: list[float], components: list[dict]) -> None:
        self.file_size, self.blocks = file_size, blocks or []
        self.components = [c for c in components if c["source"] == "native"
                           and c["details"].get("parent_offset") is None]
        self.update()

    def _bar_rect(self):
        return QRectF(8, self.height() - 46, self.width() - 16, 30)

    def paintEvent(self, _e):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor("#0f141b"))
        if not self.file_size:
            p.setPen(QColor("#9aa6b8"))
            p.drawText(self.rect(), Qt.AlignCenter, "Analyse a firmware to see its structure")
            return
        plot = QRectF(8, 8, self.width() - 16, self.height() - 64)
        p.setPen(QPen(QColor("#2c3647")))
        p.drawRect(plot)
        y79 = plot.bottom() - plot.height() * 7.9 / 8
        p.setPen(QPen(QColor("#c62828"), 1, Qt.DashLine))
        p.drawLine(QPointF(plot.left(), y79), QPointF(plot.right(), y79))
        if self.blocks:
            path = QPainterPath()
            n = len(self.blocks)
            for i, e in enumerate(self.blocks):
                pt = QPointF(plot.left() + plot.width() * i / max(1, n - 1), plot.bottom() - plot.height() * e / 8)
                path.moveTo(pt) if i == 0 else path.lineTo(pt)
            p.setPen(QPen(QColor("#6fb1ff"), 1.2))
            p.drawPath(path)
        bar = self._bar_rect()
        p.fillRect(bar, QColor("#1d2430"))
        for c in self.components:
            size = c["size"] or max(1, self.file_size // 400)
            x = bar.left() + bar.width() * c["offset"] / self.file_size
            w = max(1.5, bar.width() * size / self.file_size)
            p.fillRect(QRectF(x, bar.top(), min(w, bar.right() - x), bar.height()),
                       QColor(CAT_COLORS.get(c["category"], "#9e9e9e")))
        p.setPen(QColor("#9aa6b8"))
        p.setFont(QFont("monospace", 8))
        p.drawText(QPointF(bar.left(), self.height() - 4), "0x0  entropy 0–8 (red line 7.9)")
        txt = f"{self.file_size:#x}"
        p.drawText(QPointF(bar.right() - 8 * len(txt), self.height() - 4), txt)

    def component_at(self, x: float) -> dict | None:
        bar = self._bar_rect()
        if not self.file_size or not bar.width():
            return None
        off = (x - bar.left()) / bar.width() * self.file_size
        hits = [c for c in self.components if c["offset"] <= off < c["offset"] + (c["size"] or self.file_size // 400 + 1)]
        return min(hits, key=lambda c: c["size"] or 0) if hits else None

    def mousePressEvent(self, e):  # noqa: N802
        c = self.component_at(e.position().x())
        if c:
            self.component_clicked.emit(c["offset"])

    def mouseMoveEvent(self, e):  # noqa: N802
        c = self.component_at(e.position().x())
        self.setToolTip(f"{c['offset']:#x}  {c['description']}" if c else "")


class FirmwareAnalyzerPage(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.run_id: int | None = None
        self.hex_offset = 0
        lay = QVBoxLayout(self)
        lay.addWidget(page_title("Firmware Analyzer"))
        lay.addWidget(notice(
            "Analysis runs on a hash-verified working copy; the library original is re-hashed afterwards to prove it "
            "is unchanged. Components are reported only after header validation. Encryption statements are "
            "indicators, and every metadata value shows where it was read from."))
        top = QHBoxLayout()
        top.addWidget(QLabel("Firmware:"))
        self.fw = QComboBox()
        self.fw.currentIndexChanged.connect(self._on_fw_changed)
        top.addWidget(self.fw, 2)
        self.opt_extract = QCheckBox("Extract")
        self.opt_extract.setChecked(True)
        self.opt_binwalk = QCheckBox("Binwalk")
        self.opt_binwalk.setChecked(True)
        self.btn_analyze = QPushButton("Analyze")
        self.btn_analyze.clicked.connect(self.analyze_async)
        top.addWidget(self.opt_extract)
        top.addWidget(self.opt_binwalk)
        top.addWidget(self.btn_analyze)
        top.addWidget(QLabel("Run:"))
        self.runs = QComboBox()
        self.runs.currentIndexChanged.connect(self._on_run_changed)
        top.addWidget(self.runs, 1)
        self.btn_pdf = QPushButton("Report PDF")
        self.btn_pdf.clicked.connect(self._guard(lambda: self._done_report(self.report("pdf"))))
        self.btn_json = QPushButton("JSON")
        self.btn_json.clicked.connect(self._guard(lambda: self._done_report(self.report("json"))))
        self.btn_ws = QPushButton("Workspace")
        self.btn_ws.clicked.connect(self._guard(lambda: open_in_file_manager(self.ctx.firmware.run_dir(self.run_id))))
        for b in (self.btn_pdf, self.btn_json, self.btn_ws):
            top.addWidget(b)
        lay.addLayout(top)
        self.integrity = QLabel()
        self.integrity.setWordWrap(True)
        lay.addWidget(self.integrity)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        # overview
        self.meta = make_table(["Attribute", "Value", "Source", "Conf."])
        self.tabs.addTab(self.meta, "Overview")
        # structure
        sw = QWidget()
        sl = QVBoxLayout(sw)
        split = QSplitter(Qt.Vertical)
        self.map = StructureMap()
        self.map.component_clicked.connect(self.show_hex)
        split.addWidget(self.map)
        self.comps = make_table(["Offset", "Size", "Type", "Category", "Validated", "Source", "Description"])
        self.comps.doubleClicked.connect(lambda: self.show_hex(int(self.comps.item(self.comps.currentRow(), 0).text(), 16)))
        split.addWidget(self.comps)
        sl.addWidget(split)
        self.tabs.addTab(sw, "Structure")
        # strings
        stw = QWidget()
        stl = QVBoxLayout(stw)
        r = QHBoxLayout()
        self.str_cat = QComboBox()
        self.str_cat.currentIndexChanged.connect(self._show_strings)
        self.str_search = QLineEdit()
        self.str_search.setPlaceholderText("search all strings (case-insensitive)…")
        self.str_search.returnPressed.connect(self._guard(self._search_strings))
        r.addWidget(self.str_cat)
        r.addWidget(self.str_search, 1)
        stl.addLayout(r)
        self.str_table = make_table(["Offset", "Value", "Context"])
        self.str_table.doubleClicked.connect(lambda: self.show_hex(int(self.str_table.item(self.str_table.currentRow(), 0).text(), 16)))
        stl.addWidget(self.str_table)
        self.tabs.addTab(stw, "Strings")
        # files
        fw = QWidget()
        fl = QVBoxLayout(fw)
        r2 = QHBoxLayout()
        self.file_filter = QComboBox()
        self.file_filter.addItems(["all", "config", "sensitive", "symlink", "file"])
        self.file_filter.currentIndexChanged.connect(self._show_files)
        self.btn_import = QPushButton("Import selected into Firmware Library")
        self.btn_import.clicked.connect(self._guard(self._import_selected))
        self.btn_ghidra = QPushButton("Run Ghidra on selected")
        self.btn_ghidra.clicked.connect(self._ghidra_async)
        for w in (QLabel("Show:"), self.file_filter, self.btn_import, self.btn_ghidra):
            r2.addWidget(w)
        r2.addStretch()
        fl.addLayout(r2)
        self.files = make_table(["Path", "Size", "Kind", "SHA-256", "Note"])
        fl.addWidget(self.files, 2)
        self.extraction = make_table(["Offset", "Type", "Status", "Method", "Files", "Note"])
        fl.addWidget(QLabel("Extraction log"))
        fl.addWidget(self.extraction, 1)
        self.ghidra_out = QPlainTextEdit()
        self.ghidra_out.setReadOnly(True)
        self.ghidra_out.setMaximumHeight(120)
        fl.addWidget(self.ghidra_out)
        self.tabs.addTab(fw, "Extracted files")
        # hex
        hw = QWidget()
        hl = QVBoxLayout(hw)
        r3 = QHBoxLayout()
        self.hex_go = QLineEdit()
        self.hex_go.setPlaceholderText("offset (decimal or 0x…)")
        self.hex_go.returnPressed.connect(self._guard(lambda: self.show_hex(parse_offset(self.hex_go.text()))))
        b_prev = QPushButton("◀ Prev")
        b_prev.clicked.connect(self._guard(lambda: self.show_hex(max(0, self.hex_offset - HEX_PAGE))))
        b_next = QPushButton("Next ▶")
        b_next.clicked.connect(self._guard(lambda: self.show_hex(self.hex_offset + HEX_PAGE)))
        self.btn_hxd = QPushButton("Open in HxD")
        self.btn_hxd.clicked.connect(self._guard(self._open_hxd))
        for w in (self.hex_go, b_prev, b_next, self.btn_hxd):
            r3.addWidget(w)
        hl.addLayout(r3)
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setFont(QFont("Consolas" if __import__("os").name == "nt" else "monospace", 9))
        hl.addWidget(self.hex)
        self.tabs.addTab(hw, "Hex")
        # compare
        cw = QWidget()
        cl = QVBoxLayout(cw)
        r4 = QHBoxLayout()
        self.cmp_other = QComboBox()
        b_cmp = QPushButton("Compare")
        b_cmp.clicked.connect(self._guard(lambda: self.compare(self.cmp_other.currentData())))
        r4.addWidget(QLabel("Compare with:"))
        r4.addWidget(self.cmp_other, 1)
        r4.addWidget(b_cmp)
        cl.addLayout(r4)
        self.cmp_out = QPlainTextEdit()
        self.cmp_out.setReadOnly(True)
        cl.addWidget(self.cmp_out)
        self.tabs.addTab(cw, "Compare")
        self.status = QLabel()
        lay.addWidget(self.status)
        self.refresh()

    # ---- helpers --------------------------------------------------------------------------
    def _guard(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                log.exception("Firmware analyzer action failed")
                QMessageBox.warning(self, "Firmware Analyzer", str(exc))
        return run

    def fid(self):
        return self.fw.currentData()

    def refresh(self) -> None:
        cur = self.fid()
        recs = self.ctx.library.list()
        for combo in (self.fw, self.cmp_other):
            keep = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            for r in recs:
                combo.addItem(f"#{r.id} {r.original_filename} ({r.file_size:,} B)", r.id)
            idx = combo.findData(keep if combo is self.cmp_other else cur)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            combo.blockSignals(False)
        t = self.ctx.firmware.tools()
        self.opt_binwalk.setEnabled(bool(t.get("binwalk_cmd")))
        self.opt_binwalk.setToolTip("binwalk found" if t.get("binwalk_cmd") else "binwalk not found (optional)")
        self.btn_ghidra.setEnabled(bool(t.get("ghidra")))
        self.btn_hxd.setEnabled(bool(t.get("hxd")))
        self._on_fw_changed()

    def select_firmware(self, firmware_id: int) -> None:
        self.refresh()
        self.fw.setCurrentIndex(self.fw.findData(firmware_id))

    def _on_fw_changed(self, *_):
        fid = self.fid()
        self.runs.blockSignals(True)
        self.runs.clear()
        if fid is not None:
            for r in self.ctx.firmware.runs(fid):
                self.runs.addItem(f"#{r['id']} {r['status']} {r['started_at']}", r["id"])
        self.runs.blockSignals(False)
        self._on_run_changed()
        if fid is not None:
            self.show_hex(0)

    def _on_run_changed(self, *_):
        self.run_id = self.runs.currentData()
        self.load_run()

    # ---- display ---------------------------------------------------------------------------------
    def load_run(self):
        F = self.ctx.firmware
        rid = self.run_id
        for b in (self.btn_pdf, self.btn_json, self.btn_ws):
            b.setEnabled(rid is not None)
        if rid is None:
            self.integrity.setText("Not analysed yet." if self.fid() is not None else "Import firmware in the Firmware Library first.")
            for t in (self.meta, self.comps, self.str_table, self.files, self.extraction):
                t.setRowCount(0)
            self.map.set_data(0, [], [])
            return
        run = dict(self.ctx.db.query_one("SELECT * FROM firmware_analysis_runs WHERE id=?", (rid,)))
        self.integrity.setText(
            f"Run #{rid}: {run['status']}"
            + (f" — error: {run['error']}" if run["error"] else "")
            + f" | original SHA-256 {'UNCHANGED ✔' if run['original_unchanged'] else 'CHANGED ✖' if run['original_unchanged'] == 0 else 'n/a'}"
            f" ({(run['original_sha256_before'] or '')[:16]}…)")
        meta = F.metadata(rid)
        fill_table(self.meta, [[m["attribute"], m["value"], m["source"], f"{m['confidence']:.0%}"] for m in meta])
        comps = F.components(rid)
        fill_table(self.comps, [[f"{c['offset']:#010x}", f"{c['size']:,}" if c["size"] else "?",
                                 ("  ↳ " if c["details"].get("parent_offset") is not None else "") + c["type"],
                                 c["category"], "yes" if c["validated"] else "—", c["source"], c["description"]]
                                for c in comps])
        ent = F.result(rid, "entropy") or {}
        rec = self.ctx.library.get(self.fid())
        self.map.set_data(rec.file_size, ent.get("blocks", []), comps)
        st = F.result(rid, "strings") or {"hits": {}}
        self._strings = st
        self.str_cat.blockSignals(True)
        self.str_cat.clear()
        for cat, hits in sorted(st.get("hits", {}).items()):
            self.str_cat.addItem(f"{cat} ({len(hits)})", cat)
        if st.get("chip_mentions"):
            self.str_cat.addItem(f"chip mentions ({len(st['chip_mentions'])})", "__chips__")
        self.str_cat.blockSignals(False)
        self._show_strings()
        self._show_files()
        ex = F.result(rid, "extraction") or []
        fill_table(self.extraction, [[f"{e['offset']:#x}", e["component_type"], e["status"], e["method"], e["files"],
                                      e["message"]] for e in ex])
        g = F.result(rid, "ghidra")
        self.ghidra_out.setPlainText(json.dumps(g.get("summary") or g, indent=1)[:20000] if g else "")

    def _show_strings(self, *_):
        cat = self.str_cat.currentData()
        st = getattr(self, "_strings", {"hits": {}})
        if cat == "__chips__":
            rows = [[f"{h['offset']:#x}", h["part"], f"{h['vendor']} {h['type']} (rule {h['rule']})"]
                    for h in st.get("chip_mentions", [])]
        else:
            rows = [[f"{h['offset']:#x}", h["value"], h["text"]] for h in st.get("hits", {}).get(cat, [])]
        fill_table(self.str_table, rows)

    def search_strings(self, needle: str, limit: int = 500) -> list[tuple[int, str]]:
        st = getattr(self, "_strings", {}) or {}
        path = st.get("dump_path")
        if not path or not Path(path).exists():
            return []
        out, n = [], needle.lower()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if n in line.lower():
                    off, _, text = line.rstrip("\n").partition("  ")
                    out.append((int(off, 16), text))
                    if len(out) >= limit:
                        break
        return out

    def _search_strings(self):
        res = self.search_strings(self.str_search.text())
        fill_table(self.str_table, [[f"{o:#x}", t[:200], ""] for o, t in res])

    def _show_files(self, *_):
        if self.run_id is None:
            return
        kind = self.file_filter.currentText()
        rows = [f for f in self.ctx.firmware.files(self.run_id) if kind == "all" or f["kind"] == kind]
        fill_table(self.files, [[f["rel_path"], f"{f['size']:,}", f["kind"], f["sha256"] or "", f["note"]]
                                for f in rows[:5000]])

    def show_hex(self, offset: int):
        if self.fid() is None:
            return
        self.hex_offset = max(0, offset - offset % 16)
        data = self.ctx.firmware.read_bytes(self.fid(), self.hex_offset, HEX_PAGE)
        self.hex.setPlainText(hexdump(data, self.hex_offset) or "(end of file)")
        if offset:
            self.tabs.setCurrentIndex(4)

    # ---- actions -------------------------------------------------------------------------------------
    def analyze(self) -> int:
        rid = self.ctx.firmware.analyze(self.fid(), extract=self.opt_extract.isChecked(),
                                        use_binwalk=self.opt_binwalk.isChecked() and self.opt_binwalk.isEnabled())
        self._on_fw_changed()
        return rid

    def analyze_async(self):
        fid = self.fid()
        if fid is None:
            return
        ex, bwk = self.opt_extract.isChecked(), self.opt_binwalk.isChecked() and self.opt_binwalk.isEnabled()
        self.status.setText("Analysing… (large images can take several minutes)")

        def done(rid):
            self._on_fw_changed()
            self.status.setText(f"Analysis run #{rid} completed.")

        def failed(msg):
            self._on_fw_changed()
            self.status.setText("Analysis failed.")
            QMessageBox.warning(self, "Analysis failed", msg)
        run_async(lambda: self.ctx.firmware.analyze(fid, extract=ex, use_binwalk=bwk), done, failed,
                  busy=[self.btn_analyze, self.fw])

    def report(self, fmt: str) -> Path:
        R = self.ctx.firmware_reports
        return (R.generate_pdf if fmt == "pdf" else R.export_json)(self.fid(), self.run_id)

    def _done_report(self, path: Path):
        self.status.setText(f"Saved {path}")
        open_in_file_manager(path.parent)

    def _selected_file(self) -> str:
        row = self.files.currentRow()
        if row < 0:
            raise ValueError("Select an extracted file")
        return self.files.item(row, 0).text()

    def _import_selected(self):
        rec = self.ctx.firmware.import_extracted(self.fid(), self.run_id, self._selected_file())
        self.refresh()
        QMessageBox.information(self, "Imported", f"Added to library as firmware #{rec.id} "
                                                  f"(provenance: extracted from #{self.fid()}).")

    def _ghidra_async(self):
        try:
            rel = self._selected_file()
        except ValueError as exc:
            QMessageBox.warning(self, "Ghidra", str(exc))
            return
        fid, rid = self.fid(), self.run_id
        self.ghidra_out.setPlainText("Ghidra running…")
        run_async(lambda: self.ctx.firmware.run_ghidra(fid, rid, rel),
                  lambda res: self.ghidra_out.setPlainText(json.dumps(res.get("summary") or res, indent=1)[:20000]),
                  lambda msg: self.ghidra_out.setPlainText("Ghidra failed: " + msg), busy=[self.btn_ghidra])

    def _open_hxd(self):
        hxd = self.ctx.firmware.tools().get("hxd")
        rec = self.ctx.library.get(self.fid())
        # opens the read-only library copy; HxD will refuse to save over it
        subprocess.Popen([hxd, rec.stored_path])

    def compare(self, other_id: int) -> dict:
        if other_id is None or other_id == self.fid():
            raise ValueError("Choose a different firmware to compare with")
        res = self.ctx.firmware.compare(self.fid(), other_id)
        b = res["binary"]
        lines = [f"A: #{res['a']['id']} {res['a']['name']} ({res['a']['size']:,} B)",
                 f"B: #{res['b']['id']} {res['b']['name']} ({res['b']['size']:,} B)",
                 f"Identical: {'YES' if res['identical'] else 'no'}   size difference: {res['size_difference']:+,} B",
                 f"Blocks identical at same offset: {b['identical_at_same_offset_pct']}%   "
                 f"shared anywhere: {b['shared_blocks_pct']}% ({b['block_size'] // 1024} KiB blocks)", ""]
        if not all(res["analysed"].values()):
            lines.append("Note: structure/metadata/file comparison needs both firmware analysed.")
        if res["structure"]:
            lines.append("Component count differences: " + ", ".join(f"{t}: {v['a']}→{v['b']}" for t, v in res["structure"].items()))
        for k, v in res["metadata"].items():
            lines.append(f"{k}: A={v['a'] or '—'}  B={v['b'] or '—'}")
        if res["metadata_same"]:
            lines.append("Same: " + ", ".join(res["metadata_same"]))
        if res["files"]:
            c = res["files"]["counts"]
            lines.append(f"\nFiles: {c['added']} added, {c['removed']} removed, {c['changed']} changed, "
                         f"{c['unchanged']} unchanged")
            for kind in ("added", "removed", "changed"):
                for p in res["files"][kind][:50]:
                    lines.append(f"  {kind[0].upper()} {p}")
        self.cmp_out.setPlainText("\n".join(lines))
        return res
