from pathlib import Path

from app.security.hashing import sha256_file
from app.services.project_service import TVProject


def test_pdf_identification_report(ctx, sample_image, firmware_file):
    p = ctx.projects.create(TVProject(name="Report <TV> & co", manufacturer="M", model_number="X"))
    ctx.evidence.add_image(p.id, sample_image, "product_label", "label photo")
    ctx.library.import_file(firmware_file, project_id=p.id)
    out = ctx.reports.generate_identification_report(p.id)
    assert out.exists() and out.stat().st_size > 2000
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    reps = ctx.reports.list_reports(p.id)
    assert len(reps) == 1 and reps[0]["sha256"] == sha256_file(out)
    assert ctx.config.reports_dir in Path(reps[0]["file_path"]).parents


def test_pdf_report_unknown_tv_without_evidence(ctx):
    p = ctx.projects.create(TVProject(name="Bare"))
    out = ctx.reports.generate_identification_report(p.id)
    assert out.read_bytes()[:4] == b"%PDF"
