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
