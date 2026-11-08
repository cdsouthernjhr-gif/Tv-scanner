"""End-to-end OCR with the real Tesseract engine on synthetic photos.

Skipped (reported as SKIPPED, i.e. NOT TESTED) when Tesseract is not installed.
"""
import pytest

from app.modules.visual_scanner.ocr import TesseractEngine
from app.services.project_service import TVProject
from synthetic_images import chip_marking, font, pcb_silkscreen, rear_label, system_menu

pytestmark = [
    pytest.mark.skipif(not TesseractEngine().available(), reason="Tesseract OCR not installed"),
    pytest.mark.skipif(font(20) is None, reason="no TrueType font to render test images"),
]


def _run(ctx, path, etype):
    p = ctx.projects.create(TVProject(name="OCR test"))
    ev = ctx.evidence.add_image(p.id, path, etype)
    r = ctx.identification.run_ocr(ev.id)
    cands = {(c["field"], c["value"]) for c in ctx.identification.candidates(p.id)}
    return p, r, cands


def test_rear_label(ctx, tmp_path):
    path = rear_label(tmp_path / "label.jpg", ["SAMSUNG", "Model Code: UA55AU7000KXXM",
                                               "Serial No: 0B4K3NAR600123", 'LED TV  55" Class'])
    p, r, cands = _run(ctx, path, "tv_back_label")
    assert r.mean_confidence > 0.6
    assert ("manufacturer", "Samsung") in cands
    assert ("model_number", "UA55AU7000KXXM") in cands
    assert ("screen_size_inches", "55") in cands
    # serial: O/0 cannot be distinguished reliably by OCR; accept either reading
    assert {("serial_number", "0B4K3NAR600123"), ("serial_number", "OB4K3NAR600123")} & cands


def test_chip_marking_light_on_dark(ctx, tmp_path):
    path = chip_marking(tmp_path / "chip.png", ["MSD6A648", "XNH-AU 2219B", "TAIWAN"])
    p, r, _ = _run(ctx, path, "chip")
    dets = {d.normalized: d for d in r.markings}
    assert "MSD6A648" in dets and dets["MSD6A648"].rule_id == "mstar_soc"


def test_system_menu(ctx, tmp_path):
    path = system_menu(tmp_path / "menu.jpg", [("Model Name", "43S5400A"),
                                                ("Software Version", "V8-T658T01-LF1V123"),
                                                ("Platform", "Android TV")])
    p, r, cands = _run(ctx, path, "system_info_menu")
    assert ("model_number", "43S5400A") in cands
    assert ("firmware_version", "V8-T658T01-LF1V123") in cands
    assert ("platform", "Android TV") in cands


def test_pcb_silkscreen(ctx, tmp_path):
    path = pcb_silkscreen(tmp_path / "pcb.png", ["TP.MS338.PB801", "BN41-02635A  REV 1.1"])
    p, r, cands = _run(ctx, path, "mainboard")
    found = {d.normalized: d.rule_id for d in r.markings}
    assert found.get("BN41-02635A") == "samsung_bn41"
    assert found.get("TP.MS338.PB801") == "oem_tp_board"
    assert ("mainboard", "BN41-02635A") in cands


def test_report_with_ocr_data(ctx, tmp_path):
    path = chip_marking(tmp_path / "chip.png", ["MSD6A648"])
    p, r, _ = _run(ctx, path, "chip")
    ctx.identification.confirm_marking(ctx.identification.markings(p.id)[0]["id"])
    out = ctx.reports.generate_identification_report(p.id)
    assert out.read_bytes()[:4] == b"%PDF"
