import pytest

from app.security.file_protection import is_read_only
from app.security.hashing import sha256_file
from app.services.dashboard_service import collect_stats
from app.services.project_service import TVProject


def test_register_unknown_tv(ctx):
    p = ctx.projects.create(TVProject(name="Unknown TV from shop"))
    assert p.id and p.identification_status == "unknown"
    assert p.identification_confidence == 0.0
    assert ctx.db.scalar("SELECT COUNT(*) FROM scan_sessions WHERE project_id=?", (p.id,)) == 1


def test_register_identified_tv_capped_confidence(ctx):
    p = ctx.projects.create(TVProject(name="Living room", manufacturer=" Brand ", model_number="55X",
                                      chassis="CH1", mainboard="MB-1", product_code="PC",
                                      serial_number="S", screen_size_inches=55, platform="Tizen"))
    assert p.manufacturer == "Brand"
    assert p.identification_status == "identified"
    assert p.identification_confidence == 0.8  # manual data never exceeds 80%


def test_partial_and_update(ctx):
    p = ctx.projects.create(TVProject(name="Board only", mainboard="TP.MS338.PB801"))
    assert p.identification_status == "partial"
    p2 = ctx.projects.update(p.id, manufacturer="X", model_number="Y")
    assert p2.identification_status == "identified"
    with pytest.raises(ValueError):
        ctx.projects.update(p.id, id=5)


def test_validation(ctx):
    with pytest.raises(ValueError):
        ctx.projects.create(TVProject(name="  "))
    with pytest.raises(ValueError):
        ctx.projects.create(TVProject(name="a", screen_size_inches=1000))


def test_audit_entries(ctx):
    p = ctx.projects.create(TVProject(name="a"))
    actions = [e["action"] for e in ctx.audit.entries("tv_project", p.id)]
    assert "project.create" in actions


def test_add_evidence_image(ctx, sample_image):
    p = ctx.projects.create(TVProject(name="a"))
    before = sha256_file(sample_image)
    ev = ctx.evidence.add_image(p.id, sample_image, "tv_back_label", "rear label")
    assert ev.sha256 == before == sha256_file(sample_image)  # source untouched
    assert (ev.width, ev.height) == (400, 200)
    from pathlib import Path
    stored = Path(ev.stored_path)
    assert stored.exists() and is_read_only(stored)
    assert stored.parent == ctx.config.projects_dir / str(p.id) / "evidence"
    # duplicate is not stored twice
    again = ctx.evidence.add_image(p.id, sample_image, "tv_back_label")
    assert again.id == ev.id
    assert len(ctx.evidence.list_for_project(p.id)) == 1


def test_evidence_rejects_bad_input(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="a"))
    fake = tmp_path / "fake.png"
    fake.write_bytes(b"not an image")
    with pytest.raises(ValueError):
        ctx.evidence.add_image(p.id, fake, "chip")
    with pytest.raises(ValueError):
        ctx.evidence.add_image(p.id, fake, "nonsense_type")
    with pytest.raises(KeyError):
        from PIL import Image
        good = tmp_path / "g.png"
        Image.new("RGB", (2, 2)).save(good)
        ctx.evidence.add_image(9999, good, "chip")


def test_dashboard_stats(ctx, firmware_file):
    ctx.projects.create(TVProject(name="a"))
    ctx.projects.create(TVProject(name="b", manufacturer="M", model_number="X"))
    ctx.library.import_file(firmware_file)
    s = collect_stats(ctx.db)
    assert (s.total_projects, s.identified, s.unknown, s.firmware_in_library) == (2, 1, 1, 1)
    assert s.verified_firmware == 0  # import alone never 'verifies' firmware
    assert len(s.recent_scans) == 2
