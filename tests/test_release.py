"""Phase 8 integration: one TV through every module, then every report in every format."""
import csv
import json

import pytest

from app.modules.reports.report_center import FORMATS, REPORT_TYPES
from demo_scenario import build


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    import os
    from keyring.backends import fail
    from app.core.context import AppContext
    from app.security.secrets import SecretStore
    root = tmp_path_factory.mktemp("demo")
    ctx = AppContext.create(root / "data")
    ctx.secrets = ctx.finder.secrets = SecretStore(backend=fail.Keyring())
    ids = build(ctx, root / "work")
    yield ctx, ids
    ctx.close()


def test_demo_reaches_every_module(demo):
    ctx, ids = demo
    p = ctx.projects.get(ids["project"])
    # fictional brand "Acme" is not in the brand dictionary: only the model is evidence-backed → mixed, not verified
    assert (p.identification_status, p.identification_source, p.firmware_version) == ("identified", "mixed", "V2.0")
    assert ctx.library.get(ids["update_firmware"]).verification_status == "verified"
    assert ctx.compatibility.get(ids["compatibility"])["verdict"] == "VERIFIED COMPATIBLE"
    s = ctx.upgrades.session(ids["upgrade_session"])
    assert s["steps"]["execution"]["status"] == "done" and s["steps"]["verification"]["status"] == "passed"
    from app.services.dashboard_service import collect_stats
    st = collect_stats(ctx.db)
    assert (st.total_projects, st.identified, st.firmware_found, st.verified_firmware, st.upgrade_sessions) == (1, 1, 2, 1, 1)
    assert st.firmware_analyzed == 2


@pytest.mark.parametrize("rtype", list(REPORT_TYPES))
@pytest.mark.parametrize("fmt", FORMATS)
def test_every_report_in_every_format(demo, rtype, fmt):
    ctx, ids = demo
    subject = ids[REPORT_TYPES[rtype][1]]
    path = ctx.report_center.generate(rtype, subject, fmt)
    data = path.read_bytes()
    assert len(data) > 300
    if fmt == "pdf":
        assert data[:4] == b"%PDF"
    elif fmt == "json":
        doc = json.loads(data)
        assert doc["title"] == REPORT_TYPES[rtype][0] and doc["sections"]
    elif fmt == "html":
        t = data.decode()
        assert t.startswith("<!doctype html>") and REPORT_TYPES[rtype][0] in t and "<script" not in t
    elif fmt == "csv":
        rows = list(csv.reader(data.decode("utf-8-sig").splitlines()))
        assert rows[0][0] == REPORT_TYPES[rtype][0]
    elif fmt == "xlsx":
        from openpyxl import load_workbook
        wb = load_workbook(path)
        assert wb.sheetnames[0] == "Report" and len(wb.sheetnames) > 1
    row = ctx.db.query_one("SELECT * FROM technical_reports WHERE file_path=?", (str(path),))
    assert row is not None and row["format"] == fmt


def test_html_embeds_evidence_and_escapes(demo):
    ctx, ids = demo
    ctx.projects.update(ids["project"], notes="<script>alert(1)</script>")
    t = ctx.report_center.generate("tv_identification", ids["project"], "html").read_text()
    assert "data:image/jpeg;base64," in t and "<script>alert" not in t


def test_unknown_report_or_format(demo):
    ctx, ids = demo
    with pytest.raises(ValueError):
        ctx.report_center.generate("nonsense", 1, "pdf")
    with pytest.raises(ValueError):
        ctx.report_center.generate("hardware", ids["project"], "docx")
