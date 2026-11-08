"""UI smoke/integration tests (run headless with QT_QPA_PLATFORM=offscreen)."""
from PySide6.QtCore import Qt

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
    assert planned == []                                   # every module is implemented
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
    out = rep.generate("tv_identification", p.id, "pdf")
    assert rep.generate("tv_identification", p.id, "html").read_text().startswith("<!doctype html>")
    assert out.exists() and rep.table.rowCount() == 2 and rep.subject.count() == 1

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


# ---- Phase 4 UI ---------------------------------------------------------------------
def test_firmware_analyzer_page(qtbot, ctx, tmp_path):
    import firmware_builders as fb
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    fb.composite(a, "4.9.118")
    fb.composite(b, "4.9.200")
    ra, rb = ctx.library.import_file(a), ctx.library.import_file(b)
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    assert not isinstance(w.pages["Firmware Analyzer"], PlannedModulePage)
    lib = w.pages["Firmware Library"]
    w.navigate("Firmware Library")
    lib.table.selectRow([lib.table.item(r, 0).data(0x0100) for r in range(lib.table.rowCount())].index(ra.id))
    lib._on_analyze()                                         # jumps to the analyzer with this firmware
    fa = w.pages["Firmware Analyzer"]
    assert w.stack.currentWidget() is fa and fa.fid() == ra.id
    fa.opt_binwalk.setChecked(False)
    rid = fa.analyze()
    assert fa.run_id == rid and "UNCHANGED" in fa.integrity.text()
    assert fa.meta.rowCount() > 5 and fa.comps.rowCount() > 5
    assert fa.map.file_size == ra.file_size and fa.map.component_at(fa.map._bar_rect().left() + 1) is None
    fa.show_hex(0x10000)
    assert fa.hex.toPlainText().startswith("00010000  27 05 19 56")
    assert "Linux version 4.9.118" in fa.search_strings("Linux version")[0][1]
    fa.file_filter.setCurrentText("sensitive")
    assert all(fa.files.item(r, 2).text() == "sensitive" for r in range(fa.files.rowCount()))
    assert fa.report("pdf").exists() and fa.report("json").exists()
    fa.select_firmware(rb.id)
    fa.analyze()
    res = fa.compare(ra.id)
    assert "kernel_version" in res["metadata"] and "Blocks identical" in fa.cmp_out.toPlainText()
    with pytest.raises(ValueError):
        fa.compare(rb.id)


def test_firmware_analyzer_async(qtbot, ctx, tmp_path):
    import firmware_builders as fb
    p = tmp_path / "fw.bin"
    fb.composite(p)
    rec = ctx.library.import_file(p)
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    fa = w.pages["Firmware Analyzer"]
    fa.select_firmware(rec.id)
    fa.opt_binwalk.setChecked(False)
    fa.analyze_async()
    assert not fa.btn_analyze.isEnabled()
    qtbot.waitUntil(lambda: fa.run_id is not None, timeout=120000)
    assert "completed" in fa.integrity.text()


# ---- Phase 5 UI ---------------------------------------------------------------------
def test_finder_page_workflow(qtbot, ctx, tmp_path):
    from app.modules.firmware_finder.http import RateLimiter
    from fake_http import FakeSession
    from test_firmware_finder import _github_routes
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    fp = w.pages["Universal Firmware Finder"]
    assert not isinstance(fp, PlannedModulePage)
    assert not fp.online.isChecked()                                    # offline-first
    sess = FakeSession()
    ctx.finder.http.session, ctx.finder.http.sleep, ctx.finder.http.limiter = sess, (lambda s: None), RateLimiter(1e4)
    _github_routes(sess, b"firmware-bytes")
    p = ctx.projects.create(TVProject(name="Bench", model_number="TESTTV55", mainboard="TP.MS338.PB801"))
    w.navigate("Universal Firmware Finder")
    fp.project.select_project(p.id)
    fp.load_from_project()
    assert fp.inputs["model_number"].text() == "TESTTV55"
    assert "[model] TESTTV55 firmware" in fp.queries.toPlainText()
    fp.online.setChecked(True)
    assert ctx.config.get("network.offline_mode") is False
    for i in range(fp.providers.count()):
        it = fp.providers.item(i)
        it.setCheckState(Qt.Checked if it.data(Qt.UserRole) == "GitHub" else Qt.Unchecked)
    sid = fp.search()
    assert fp.table.rowCount() >= 2 and fp.history.rowCount() == 1
    row = [r for r in range(fp.table.rowCount()) if fp.table.item(r, 4).text() == "TESTTV55_v2.0.bin"][0]
    fp.table.selectRow(row)
    assert fp.details.rowCount() >= 1 and "Risk" in fp.reasons.text()
    out = fp.download(fp.table.item(row, 0).data(Qt.UserRole))
    assert out["firmware_id"] and ctx.library.get(out["firmware_id"]).download_url
    fp.session_id = sid
    for fmt in ("PDF", "CSV", "JSON"):
        path = {"PDF": ctx.search_reports.generate_pdf, "CSV": ctx.search_reports.export_csv,
                "JSON": ctx.search_reports.export_json}[fmt](sid)
        assert path.exists()


def test_settings_api_keys_never_plaintext(qtbot, ctx):
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    s = w.pages["Settings"]
    s.key_name.setCurrentIndex(s.key_name.findData("github_token"))
    s.key_value.setText("ghp_supersecretvalue1")
    s.store_key()
    assert s.key_value.text() == "" and "ghp_…e1" in s.key_status.text()
    s.offline.setChecked(False)
    s.cfg_fields["finder.searxng_url"].setText("https://searx.example.org")
    s.save_network()
    txt = ctx.config.settings_path.read_text()
    assert "searx.example.org" in txt and "ghp_" not in txt
    assert ctx.config.get("network.offline_mode") is False


# ---- Phase 6 UI ---------------------------------------------------------------------
def test_software_page(qtbot, ctx, tmp_path):
    import firmware_builders as fb
    p = ctx.projects.create(TVProject(name="SW", manufacturer="Acme", model_number="TESTTV55"))
    f = tmp_path / "fw.bin"
    fb.composite(f)
    ctx.firmware.analyze(ctx.library.import_file(f, project_id=p.id).id, use_binwalk=False)
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    sp = w.pages["Software Analyzer"]
    assert not isinstance(sp, PlannedModulePage)
    w.navigate("Software Analyzer")
    sp.project.select_project(p.id)
    s = sp.analyze()
    assert s["os_best"] == "Android" and "OS: Android" in sp.status.text()
    assert any(sp.summary.item(r, 1).text() == "4.9.118" for r in range(sp.summary.rowCount()))
    sp.m_cat.setCurrentText("firmware_version")
    sp.m_name.setText("T-KTM2AKUC-1500.5")
    sp.m_ref.setText("Settings > Support > About")
    sp._add_manual()
    assert any(sp.all_facts.item(r, 3).text() == "operator" for r in range(sp.all_facts.rowCount()))


def test_service_menu_page(qtbot, ctx):
    p = ctx.projects.create(TVProject(name="SM", manufacturer="Acme", model_number="TESTTV55", chassis="CH-9"))
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    sm = w.pages["Factory & Service Menu"]
    assert not isinstance(sm, PlannedModulePage)
    w.navigate("Factory & Service Menu")
    sm.e["manufacturer"].setText("Acme")
    sm.e["model_pattern"].setText("TESTTV*")
    sm.e["function_description"].setText("White balance")
    sm.e_cat.setCurrentText("Service Menu")
    with pytest.raises(ValueError, match="official_documentation"):
        sm.add_from_form()                                   # documentation is mandatory
    sm.e["official_documentation"].setText("Acme CH-9 Service Manual, section 4.2")
    rid = sm.add_from_form()
    assert sm.table.rowCount() == 1
    sm.project.select_project(p.id)
    sm.load_project()
    assert sm.applicable.rowCount() == 1
    sm.applicable.selectRow(0)
    sm.a_setting.setText("Backlight")
    sm.a_new.setText("80")
    sm.a_reason.setText("customer request")
    sm._plan()
    assert sm.actions.rowCount() == 1 and sm.actions.item(0, 4).text() == "planned"
    assert ctx.software_reports.service_report_pdf(p.id).exists()
    assert rid


# ---- Phase 7 UI ---------------------------------------------------------------------
def test_compatibility_and_upgrade_pages(qtbot, ctx, tmp_path):
    import firmware_builders as fb
    from test_compatibility_upgrade import PROFILE, probe
    p = ctx.projects.create(TVProject(name="UP", manufacturer="Acme", model_number="TESTTV55",
                                      mainboard="TP.MS338.PB801", firmware_version="V1.0"))
    ctx.hardware.analyze(ctx.hardware.add_component(p.id, "soc", "MSD6A648"))
    ids = []
    for name, cat in (("orig.bin", "Original"), ("upgrade_v2.bin", "Official")):
        f = tmp_path / name
        fb.composite(f, extra_file=b"board=TP.MS338.PB801")
        rec = ctx.library.import_file(f, project_id=p.id, category=cat, version="V2.0" if cat == "Official" else None)
        ctx.firmware.analyze(rec.id, use_binwalk=False)
        ids.append(rec.id)
    w = MainWindow(ctx)
    qtbot.addWidget(w)
    cp = w.pages["Compatibility Analyzer"]
    w.navigate("Compatibility Analyzer")
    cp.project.select_project(p.id)
    cp.candidate.setCurrentIndex(cp.candidate.findData(ids[1]))
    r = cp.evaluate()
    assert r.verdict == "VERIFIED COMPATIBLE" and "VERIFIED COMPATIBLE" in cp.verdict.text()
    assert cp.table.rowCount() >= 15 and cp.history.rowCount() == 1
    up = w.pages["Firmware Upgrade Manager"]
    w.navigate("Firmware Upgrade Manager")
    for k, v in PROFILE.items():
        if k in up.pf:
            up.pf[k].setText(v)
    up.p_method.setCurrentIndex(up.p_method.findData("official_usb"))
    pid = up.add_profile()
    assert up.ptable.rowCount() == 1 and up.ptable.item(0, 7).text() == "NO"
    ctx.upgrades.verify_profile(pid, "VERIFIED Acme")
    up.refresh()
    up.project.select_project(p.id)
    up.target.setCurrentIndex(up.target.findData(ids[1]))
    sid = up.start()
    up.run_checks()
    assert "VERIFIED COMPATIBLE" in up.steps.item(1, 2).text()
    ctx.upgrades.step_backup(sid)
    usb = tmp_path / "USB"
    usb.mkdir()
    ctx.upgrades.step_preparation(sid, True, True, ctx.upgrades.confirmation_phrase(sid), str(usb), fs_probe=probe())
    ctx.upgrades.step_execution(sid, fs_probe=probe())
    up.load_session(sid)
    assert "done" in up.steps.item(5, 1).text() and (usb / "upgrade_v2.bin").exists()
