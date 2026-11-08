"""Identification service logic, tested with a deterministic fake OCR engine."""
from pathlib import Path

import pytest

from app.modules.identification.catalog import canonical
from app.modules.visual_scanner.ocr import OcrEngine, OcrResult, OcrToken
from app.security.hashing import sha256_file
from app.services.project_service import TVProject


class FakeEngine(OcrEngine):
    name = "fake"

    def __init__(self, lines):
        self.lines = lines
        self.calls = 0

    def available(self):
        return True

    def version(self):
        return "fake 1.0"

    def recognize(self, image, language="eng", psm=11):
        self.calls += 1
        toks = []
        for li, (text, conf) in enumerate(self.lines):
            for wi, w in enumerate(text.split()):
                toks.append(OcrToken(w, conf, (wi * 80, li * 40, 70, 30), li))
        r = OcrResult("fake", "", toks, 1)
        r.text = "\n".join(t for t, _ in r.lines())
        return r


@pytest.fixture
def fake(ctx):
    def install(lines):
        eng = FakeEngine(lines)
        ctx.identification._engines = {"fake": eng}
        return eng
    return install


def _project_with_image(ctx, sample_image, etype="tv_back_label"):
    p = ctx.projects.create(TVProject(name="Unknown TV"))
    ev = ctx.evidence.add_image(p.id, sample_image, etype)
    return p, ev


def test_migration_0002_applied(ctx):
    assert ctx.db.schema_version >= 2
    cols = {r[1] for r in ctx.db.query("PRAGMA table_info(scan_evidence)")}
    assert {"parent_evidence_id", "processing_json"} <= cols
    assert "panel_model" in {r[1] for r in ctx.db.query("PRAGMA table_info(tv_projects)")}


def test_run_ocr_stores_results_and_candidates(ctx, fake, sample_image):
    eng = fake([("SAMSUNG", 0.95), ("Model Code: UA55AU7000KXXM", 0.9), ("Serial No: 0B4K3NAR600123", 0.9)])
    p, ev = _project_with_image(ctx, sample_image)
    r = ctx.identification.run_ocr(ev.id)
    assert eng.calls >= 2  # auto mode tries several variants
    assert ctx.db.scalar("SELECT COUNT(*) FROM ocr_results WHERE evidence_id=?", (ev.id,)) == eng.calls
    assert "UA55AU7000KXXM" in r.text
    vals = {(c["field"], c["value"]) for c in ctx.identification.candidates(p.id)}
    assert {("manufacturer", "Samsung"), ("model_number", "UA55AU7000KXXM"),
            ("serial_number", "0B4K3NAR600123")} <= vals
    # nothing applied to the project without a decision
    proj = ctx.projects.get(p.id)
    assert proj.manufacturer is None and proj.identification_status == "unknown"
    assert ctx.evidence.get(ev.id).ocr_text


def test_accept_reject_and_verified_status(ctx, fake, sample_image):
    fake([("SAMSUNG", 0.95), ("Model: UA55AU7000KXXM", 0.9), ("Model: YA5S5AU7000KXXM", 0.6)])
    p, ev = _project_with_image(ctx, sample_image)
    ctx.identification.run_ocr(ev.id)
    by = {(c["field"], c["value"]): c for c in ctx.identification.candidates(p.id)}
    proj = ctx.identification.accept_candidate(by[("manufacturer", "Samsung")]["id"])
    assert proj.manufacturer == "Samsung" and proj.identification_source == "evidence"
    assert proj.identification_status == "partial"
    proj = ctx.identification.accept_candidate(by[("model_number", "UA55AU7000KXXM")]["id"])
    assert proj.identification_status == "verified"
    # the competing reading for the same field was rejected automatically
    alt = ctx.db.query_one("SELECT status FROM identification_candidates WHERE id=?",
                           (by[("model_number", "YA5S5AU7000KXXM")]["id"],))
    assert alt["status"] == "rejected"
    # manual edit away from the evidence value removes the 'verified' status
    proj = ctx.projects.update(p.id, model_number="SOMETHING-ELSE1")
    assert proj.identification_status == "identified" and proj.identification_source == "mixed"


def test_reject_candidate_reassesses(ctx, fake, sample_image):
    fake([("SAMSUNG", 0.95), ("Model: ABC12345", 0.9)])
    p, ev = _project_with_image(ctx, sample_image)
    ctx.identification.run_ocr(ev.id)
    ids = {c["field"]: c["id"] for c in ctx.identification.candidates(p.id)}
    ctx.identification.accept_candidate(ids["manufacturer"])
    ctx.identification.accept_candidate(ids["model_number"])
    assert ctx.projects.get(p.id).identification_status == "verified"
    proj = ctx.identification.reject_candidate(ids["model_number"])
    assert proj.identification_status == "identified"  # value kept, but no longer evidence-backed


def test_aggregation_across_images(ctx, fake, sample_image, tmp_path):
    from PIL import Image
    fake([("Model: ABC12345", 0.6)])
    p, ev1 = _project_with_image(ctx, sample_image)
    img2 = tmp_path / "second.png"
    Image.new("RGB", (300, 120), "white").save(img2)
    ev2 = ctx.evidence.add_image(p.id, img2, "product_label")
    ctx.identification.run_ocr_for_project(p.id)
    g = [x for x in ctx.identification.aggregated_candidates(p.id) if x["field"] == "model_number"][0]
    single = 0.95 * 0.6
    assert g["evidence_count"] == 2
    assert g["confidence"] == pytest.approx(1 - (1 - single) ** 2, abs=0.002)
    # only_new skips evidence already processed
    assert ctx.identification.run_ocr_for_project(p.id) == []


def test_markings_confirm_creates_hardware_component(ctx, fake, sample_image):
    fake([("MSD6A648", 0.95), ("2219B TAIWAN", 0.9)])
    p, ev = _project_with_image(ctx, sample_image, "chip")
    r = ctx.identification.run_ocr(ev.id)
    assert [d.normalized for d in r.markings] == ["MSD6A648"]
    m = ctx.identification.markings(p.id)[0]
    hid = ctx.identification.confirm_marking(m["id"])
    hw = ctx.db.query_one("SELECT * FROM hardware_components WHERE id=?", (hid,))
    assert hw["part_number"] == "MSD6A648" and hw["verified_by_user"] == 1 and hw["evidence_id"] == ev.id
    assert ctx.identification.markings(p.id)[0]["status"] == "confirmed"


def test_pcb_marking_becomes_mainboard_candidate(ctx, fake, sample_image):
    fake([("BN41-02635A", 0.9)])
    p, ev = _project_with_image(ctx, sample_image, "mainboard")
    ctx.identification.run_ocr(ev.id)
    c = [c for c in ctx.identification.candidates(p.id) if c["field"] == "mainboard"][0]
    assert c["value"] == "BN41-02635A" and c["method"] == "pcb_rule:samsung_bn41"
    m = ctx.identification.markings(p.id)[0]
    ctx.identification.reject_marking(m["id"])
    assert ctx.identification.markings(p.id)[0]["status"] == "rejected"


def test_save_processed_keeps_original(ctx, sample_image):
    p, ev = _project_with_image(ctx, sample_image)
    before = sha256_file(ev.stored_path)
    d = ctx.identification.save_processed(ev.id, "label", crop_rect=(0, 0, 200, 100))
    assert d.parent_evidence_id == ev.id and "crop" in d.processing_json
    assert sha256_file(ev.stored_path) == before
    assert Path(d.stored_path).exists()
    assert ctx.identification.save_processed(ev.id, "label", crop_rect=(0, 0, 200, 100)).id == d.id


def test_no_engine_raises_clear_error(ctx, sample_image):
    ctx.identification._engines = {}
    p, ev = _project_with_image(ctx, sample_image)
    with pytest.raises(RuntimeError, match="No OCR engine"):
        ctx.identification.run_ocr(ev.id)


# ---- catalog --------------------------------------------------------------------
def test_canonical():
    assert canonical("ua-55 au7000") == canonical("UA55AU7OOO") == "UA55AU7000"


def test_catalog_save_and_match(ctx):
    with pytest.raises(ValueError):
        ctx.catalog.save_project(ctx.projects.create(TVProject(name="x", manufacturer="M")))
    src = ctx.projects.create(TVProject(name="known", manufacturer="Acme", model_number="A55X100",
                                        chassis="CH-1", mainboard="TP.MS338.PB801", panel_model="P55"))
    tid = ctx.catalog.save_project(src)
    assert ctx.catalog.save_project(src) == tid  # idempotent
    assert ctx.catalog.count() == 1
    exact = ctx.catalog.find_matches("A55X100", "Acme")[0]
    assert exact.level == "exact" and exact.mainboard == "TP.MS338.PB801"
    ocr_err = ctx.catalog.find_matches("A55XIOO", "Acme")[0]           # O/0, I/1 confusion
    assert ocr_err.score >= 0.95
    assert ctx.catalog.find_matches("A55X100", "Other") == []  # penalised below threshold
    other_brand = ctx.catalog.find_matches("A55X100", "Other", min_score=0.3)[0]
    assert other_brand.score < exact.score and "different manufacturer" in other_brand.reasons
    # unknown TV: match on mainboard only
    board = ctx.catalog.find_matches(mainboard="tp.ms338.pb801")
    assert board and board[0].tv_model_id == tid
    assert ctx.catalog.find_matches("ZZZ999") == []


def test_catalog_match_is_not_physical_evidence(ctx):
    src = ctx.projects.create(TVProject(name="known", manufacturer="Acme", model_number="A55X100",
                                        mainboard="TP.MS338.PB801"))
    ctx.catalog.save_project(src)
    unknown = ctx.projects.create(TVProject(name="bench", mainboard="TP.MS338.PB801"))
    m = ctx.identification.find_catalog_matches(unknown.id)[0]
    assert ctx.identification.apply_catalog_match(unknown.id, m) >= 2
    assert ctx.identification.apply_catalog_match(unknown.id, m) == 0  # no duplicates
    cands = {c["field"]: c for c in ctx.identification.candidates(unknown.id)}
    ctx.identification.accept_candidate(cands["manufacturer"]["id"])
    p = ctx.identification.accept_candidate(cands["model_number"]["id"])
    assert p.model_number == "A55X100"
    assert p.identification_status == "identified"  # NOT verified: catalog is not evidence of this TV
