"""UI smoke/integration tests (run headless with QT_QPA_PLATFORM=offscreen)."""
from app.ui.main_window import SIDEBAR, MainWindow
from app.ui.pages.planned_page import PlannedModulePage


def test_main_window_navigation(qtbot, ctx):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    assert w.sidebar.count() == 14 == len(SIDEBAR)
    for i in range(len(SIDEBAR)):
        w.sidebar.setCurrentRow(i)
        assert w.stack.currentIndex() == i
    planned = [n for n, p in w.pages.items() if isinstance(p, PlannedModulePage)]
    assert "Universal Firmware Finder" in planned
    assert "Dashboard" not in planned


def test_end_to_end_workflow(qtbot, ctx, sample_image, firmware_file):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    np = w.pages["New TV Project"]
    np.form.inputs["name"].setText("Bench TV 1")
    np.form.inputs["mainboard"].setText("TP.MS338.PB801")
    p = np.register()
    assert p.identification_status == "partial"
    assert np.table.rowCount() == 1

    w.open_project(p.id)
    ident = w.pages["TV Identification"]
    assert ident.current_project_id() == p.id
    ident.form.inputs["manufacturer"].setText("Acme")
    ident.form.inputs["model_number"].setText("A55")
    assert ident.save().identification_status == "identified"
    ident.add_evidence(sample_image, "tv_back_label")
    assert ident.ev_table.rowCount() == 1

    w.navigate("Firmware Library")
    lib = w.pages["Firmware Library"]
    lib.project.select_project(p.id)
    assert lib.mainboard.text() == "TP.MS338.PB801"
    rec = lib.import_firmware(firmware_file)
    assert rec.project_id == p.id and lib.table.rowCount() == 1

    w.navigate("Reports")
    rep = w.pages["Reports"]
    out = rep.generate(p.id)
    assert out.exists() and rep.table.rowCount() == 1

    w.navigate("Dashboard")
    dash = w.pages["Dashboard"]
    assert dash.cards["total_projects"].value.text() == "1"
    assert dash.cards["identified"].value.text() == "1"
    assert dash.cards["firmware_in_library"].value.text() == "1"


def test_settings_page(qtbot, ctx):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    w.navigate("Settings")
    s = w.pages["Settings"]
    assert s.tools.rowCount() == 6
    assert s.labels["Schema version"].text() == str(ctx.db.schema_version)


# ---- Phase 2 UI ---------------------------------------------------------------------
import pytest  # noqa: E402

from app.modules.visual_scanner.ocr import TesseractEngine  # noqa: E402
from app.services.project_service import TVProject  # noqa: E402
from synthetic_images import chip_marking, font, rear_label  # noqa: E402

needs_ocr = pytest.mark.skipif(not TesseractEngine().available() or font(20) is None,
                               reason="Tesseract OCR or TrueType font not available")


def test_visual_scanner_is_real_page(qtbot, ctx):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    assert not isinstance(w.pages["Visual Scanner"], PlannedModulePage)
    assert "P2" not in w.sidebar.item(SIDEBAR.index("Visual Scanner")).text()


def test_visual_scanner_preview_crop_save(qtbot, ctx, sample_image):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    p = ctx.projects.create(TVProject(name="VS"))
    ev = ctx.evidence.add_image(p.id, sample_image, "tv_back_label")
    w.navigate("Visual Scanner")
    vs = w.pages["Visual Scanner"]
    vs.select_evidence(ev.id)
    assert vs.current_evidence_id() == ev.id
    vs.canvas.set_crop((0, 0, 200, 100))
    img = vs.preview()
    assert img.shape[1] > 0
    derived = vs.save_processed()
    assert derived.parent_evidence_id == ev.id
    assert vs.current_evidence_id() == derived.id


@needs_ocr
def test_visual_scanner_ocr_and_confirm_marking(qtbot, ctx, tmp_path):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    p = ctx.projects.create(TVProject(name="Chip"))
    ev = ctx.evidence.add_image(p.id, chip_marking(tmp_path / "c.png", ["MSD6A648"]), "chip")
    w.navigate("Visual Scanner")
    vs = w.pages["Visual Scanner"]
    vs.select_evidence(ev.id)
    r = vs.run_ocr()
    assert "MSD6A648" in [d.normalized for d in r.markings]
    assert vs.markings.rowCount() >= 1
    vs.markings.selectRow(0)
    vs._confirm_marking()
    assert ctx.db.scalar("SELECT COUNT(*) FROM hardware_components WHERE project_id=?", (p.id,)) == 1


@needs_ocr
def test_identification_ocr_accept_to_verified(qtbot, ctx, tmp_path):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    p = ctx.projects.create(TVProject(name="Shop TV"))
    ctx.evidence.add_image(p.id, rear_label(tmp_path / "l.jpg", ["SAMSUNG", "Model Code: UA55AU7000KXXM"]),
                           "tv_back_label")
    w.open_project(p.id)
    ident = w.pages["TV Identification"]
    ident.run_ocr()
    rows = {(g["field"], g["value"]): i for i, g in enumerate(ident._groups)}
    ident.accept(rows[("manufacturer", "Samsung")])
    proj = ident.accept({(g["field"], g["value"]): i for i, g in enumerate(ident._groups)}
                        [("model_number", "UA55AU7000KXXM")])
    assert proj.identification_status == "verified"
    assert ident.form.inputs["model_number"].text() == "UA55AU7000KXXM"
    tid = ident.save_to_catalog()
    assert ident.find_matches()[0].tv_model_id == tid


# ---- Phase 3 UI ---------------------------------------------------------------------
def test_hardware_page_workflow(qtbot, ctx, tmp_path):
    from synthetic_datasheets import ddr3_datasheet
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    assert not isinstance(w.pages["Hardware Analyzer"], PlannedModulePage)
    p = ctx.projects.create(TVProject(name="HW"))
    w.navigate("Hardware Analyzer")
    hp = w.pages["Hardware Analyzer"]
    hp.project.select_project(p.id)
    hp.import_datasheet(ddr3_datasheet(tmp_path / "d.pdf"), vendor="Samsung")
    assert hp.ds_table.rowCount() == 1
    assert hp.search_datasheets("K4B4G1646E-BYK0")[0].level == "exact"
    hp.f_cat.setCurrentIndex(hp.f_cat.findData("ram"))
    hp.f_part.setText("K4B4G1646E-BYK0")
    hp.f_qty.setValue(2)
    cid = hp.add_from_form()
    a = hp.analyze_selected(cid)
    assert a.match_status == "datasheet_exact"
    assert hp.facts.rowCount() > 3                      # selection shows the facts
    assert "1 GB total" in hp.summary.toPlainText()
    for fmt in ("PDF report", "XLSX", "CSV", "JSON"):
        assert hp.export(fmt).exists()


def test_background_worker(qtbot):
    from PySide6.QtWidgets import QPushButton
    from app.ui.worker import busy_count, run_async
    btn = QPushButton()
    qtbot.addWidget(btn)
    got, errs = [], []
    run_async(lambda: 6 * 7, got.append, errs.append, busy=[btn])
    assert not btn.isEnabled()
    qtbot.waitUntil(lambda: got == [42], timeout=5000)
    assert btn.isEnabled() and busy_count() == 0
    run_async(lambda: 1 / 0, got.append, errs.append)
    qtbot.waitUntil(lambda: len(errs) == 1, timeout=5000)
    assert "division" in errs[0]


@needs_ocr
def test_visual_scanner_async_ocr(qtbot, ctx, tmp_path):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    p = ctx.projects.create(TVProject(name="Async"))
    ev = ctx.evidence.add_image(p.id, chip_marking(tmp_path / "c.png", ["MSD6A648"]), "chip")
    w.navigate("Visual Scanner")
    vs = w.pages["Visual Scanner"]
    vs.select_evidence(ev.id)
    vs.run_ocr_async()
    assert not vs.btn_ocr.isEnabled()                   # UI stays responsive, button busy
    qtbot.waitUntil(lambda: vs._last is not None, timeout=60000)
    assert vs.btn_ocr.isEnabled() and vs.markings.rowCount() >= 1
