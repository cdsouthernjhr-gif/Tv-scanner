import json
from pathlib import Path

import pytest

import firmware_builders as fb
from app.modules.upgrade_manager.adapters import METHODS
from app.modules.upgrade_manager.service import UpgradeBlocked
from app.services.project_service import TVProject

BOARD = b"board=TP.MS338.PB801 soc=MSD6A648"


def probe(fs="FAT32", free=10 ** 10, removable=True):
    return lambda t: {"fs": fs, "free": free, "removable": removable, "root": t}


@pytest.fixture
def tv(ctx, tmp_path):
    """TV project + analysed Original (baseline) firmware + analysed Official candidate."""
    p = ctx.projects.create(TVProject(name="Bench", manufacturer="Acme", model_number="TESTTV55",
                                      mainboard="TP.MS338.PB801", firmware_version="V1.0"))
    ctx.hardware.analyze(ctx.hardware.add_component(p.id, "soc", "MSD6A648"))

    def fw(name, category="Official", version=None, **kw):
        f = tmp_path / name
        fb.composite(f, kw.pop("kernel", "4.9.200"), extra_file=kw.pop("extra", BOARD), **kw)
        rec = ctx.library.import_file(f, project_id=p.id, category=category, version=version)
        ctx.firmware.analyze(rec.id, use_binwalk=False)
        return rec
    base = fw("orig.bin", "Original", kernel="4.9.118")
    return p, base, fw


# ---- compatibility -----------------------------------------------------------------------------------
def test_not_analysed_is_insufficient(ctx, tv, tmp_path):
    p, base, _ = tv
    f = tmp_path / "raw.bin"
    fb.composite(f)
    rec = ctx.library.import_file(f, project_id=p.id)
    r = ctx.compatibility.evaluate(p.id, rec.id)
    assert r.verdict == "INSUFFICIENT EVIDENCE" and "analysed" in r.reasons[0]


def test_verified_compatible(ctx, tv):
    p, base, fw = tv
    cand = fw("upgrade_v2.bin", version="V2.0")
    r = ctx.compatibility.evaluate(p.id, cand.id)
    assert r.verdict == "VERIFIED COMPATIBLE", [(c.criterion, c.status, c.evidence) for c in r.criteria]
    by = {c.criterion: c for c in r.criteria}
    assert by["model"].status == by["architecture"].status == by["mainboard"].status == "match"
    assert by["signing"].status == "match" and r.baseline_firmware_id == base.id
    stored = ctx.compatibility.get(r.id)
    assert stored["verdict"] == r.verdict and len(stored["criteria"]) == len(r.criteria)


def test_likely_without_board_evidence_or_baseline(ctx, tv):
    p, base, fw = tv
    cand = fw("noboard.bin", extra=b"")
    assert ctx.compatibility.evaluate(p.id, cand.id).verdict == "LIKELY COMPATIBLE"
    ctx.db.execute("UPDATE firmware_files SET category='Community' WHERE id=?", (base.id,))   # no baseline any more
    r = ctx.compatibility.evaluate(p.id, fw("c2.bin").id)
    assert r.verdict == "LIKELY COMPATIBLE" and any("baseline" in x for x in r.reasons)


@pytest.mark.parametrize("kwargs,criterion", [
    ({"model": "OTHERTV43"}, "model"),
    ({"arch": "MIPS"}, "architecture"),
    ({"signed": False}, "signing"),
])
def test_hard_mismatches(ctx, tv, kwargs, criterion):
    p, base, fw = tv
    r = ctx.compatibility.evaluate(p.id, fw("bad.bin", **kwargs).id)
    assert r.verdict == "INCOMPATIBLE"
    c = [x for x in r.criteria if x.criterion == criterion][0]
    assert c.status == "mismatch" and c.hard


def test_ram_requirement(ctx, tv):
    p, base, fw = tv
    ctx.hardware.analyze(ctx.hardware.add_component(p.id, "ram", "K4B4G1646E-BYK0", quantity=2))   # 1 GB decoded
    big = fw("big.bin", cmdline="console=ttyS0 mem=2048M")
    r = ctx.compatibility.evaluate(p.id, big.id)
    assert r.verdict == "INCOMPATIBLE" and [c for c in r.criteria if c.criterion == "ram"][0].status == "mismatch"
    ok = fw("ok.bin", cmdline="console=ttyS0 mem=512M")
    assert [c for c in ctx.compatibility.evaluate(p.id, ok.id).criteria if c.criterion == "ram"][0].status == "match"


def test_partition_layout_mismatch(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="eMMC", manufacturer="Acme", model_number="TESTTV55"))
    for name, cat, parts in (("dump.img", "Original", [("boot", 64, b"\0" * 2048), ("system", 128, b"\0" * 4096)]),
                             ("new.img", "Official", [("boot", 64, b"\0" * 2048), ("system", 128, b"\0" * 4096),
                                                      ("vendor", 256, b"\0" * 1024)])):
        f = tmp_path / name
        f.write_bytes(fb.gpt_disk(parts))
        rec = ctx.library.import_file(f, project_id=p.id, category=cat)
        ctx.firmware.analyze(rec.id, use_binwalk=False)
    r = ctx.compatibility.evaluate(p.id, rec.id)
    c = [x for x in r.criteria if x.criterion == "partition_layout"][0]
    assert r.verdict == "INCOMPATIBLE" and c.hard and "vendor" in c.evidence


def test_panel_soft_mismatch(ctx, tv):
    p, base, fw = tv
    ctx.projects.update(p.id, panel_model="LC550EGE")
    other = fw("panel.bin", extra_files={"vendor/config/panel/panel_hv550.ini": b"PanelName = HV550QUB\n"})
    r = ctx.compatibility.evaluate(p.id, other.id)
    c = [x for x in r.criteria if x.criterion == "panel"][0]
    assert c.status == "soft_mismatch" and "damage" in c.evidence
    assert r.verdict != "VERIFIED COMPATIBLE"
    good = fw("panel_ok.bin", extra_files={"vendor/config/panel/panel_lc550ege.ini": b"PanelName = LC550EGE\n"})
    assert [x for x in ctx.compatibility.evaluate(p.id, good.id).criteria if x.criterion == "panel"][0].status == "match"


def test_integrity_failure_incompatible(ctx, tv):
    import os
    import stat
    p, base, fw = tv
    cand = fw("c.bin")
    sp = Path(cand.stored_path)
    os.chmod(sp, stat.S_IWUSR | stat.S_IRUSR)
    with open(sp, "r+b") as fh:
        fh.seek(100)
        fh.write(b"X")
    r = ctx.compatibility.evaluate(p.id, cand.id)
    assert r.verdict == "INCOMPATIBLE" and [c for c in r.criteria if c.criterion == "integrity"][0].hard


# ---- upgrade profiles ---------------------------------------------------------------------------------
PROFILE = dict(manufacturer="Acme", model_pattern="TESTTV*", method="official_usb",
               documentation_ref="Acme TESTTV user manual p.40 'Software update via USB'",
               package_pattern="upgrade_*.bin", usb_filesystems="FAT32", usb_target_path="/", usb_target_name="",
               power_requirements="Do not switch off during update", recovery_procedure="Contact Acme service",
               instructions="Copy the file to the USB root\nInsert the USB stick; the TV offers the update")


def test_profile_validation_and_verification(ctx):
    U = ctx.upgrades
    with pytest.raises(ValueError, match="documentation_ref"):
        U.add_profile({**PROFILE, "documentation_ref": ""})
    with pytest.raises(ValueError, match="method"):
        U.add_profile({**PROFILE, "method": "jtag_flash"})
    with pytest.raises(ValueError, match="model pattern"):
        U.add_profile({**PROFILE, "model_pattern": ""})
    pid = U.add_profile(PROFILE)
    assert U.profile(pid)["verified"] == 0 and U.profile(pid)["risk_level"] == "medium"
    with pytest.raises(ValueError, match="Type exactly"):
        U.verify_profile(pid, "yes")
    U.verify_profile(pid, "VERIFIED Acme")
    assert U.profile(pid)["verified"] == 1 and U.profile(pid)["verified_by"]
    assert set(METHODS) == {"official_usb", "official_network", "service_tool", "authorized_uart",
                            "authorized_usb_device", "vendor_recovery"}
    assert [k for k, m in METHODS.items() if m.executes] == ["official_usb"]


def test_applicability(ctx):
    U = ctx.upgrades
    a = U.add_profile(PROFILE)
    U.add_profile({**PROFILE, "model_pattern": "OTHER*"})
    U.add_profile({**PROFILE, "chassis": "CH-9"})
    p = ctx.projects.create(TVProject(name="t", manufacturer="acme", model_number="testtv55", chassis="CH-1"))
    assert [x["id"] for x in U.applicable_profiles(p)] == [a]
    other = ctx.projects.create(TVProject(name="o", manufacturer="Acme", model_number="ZZZ1"))
    f = ctx.library.list()
    with pytest.raises(UpgradeBlocked):
        U.start(other.id, a, 1)


# ---- upgrade sessions -------------------------------------------------------------------------------------
def _session(ctx, p, cand, verified=True, **prof):
    U = ctx.upgrades
    pid = U.add_profile({**PROFILE, **prof})
    if verified:
        U.verify_profile(pid, "VERIFIED Acme")
    return U, U.start(p.id, pid, cand.id)


def test_full_usb_upgrade(ctx, tv, tmp_path):
    p, base, fw = tv
    cand = fw("upgrade_v2.bin", version="V2.0")
    U, sid = _session(ctx, p, cand)
    with pytest.raises(UpgradeBlocked):
        U.step_validation(sid)                                     # order enforced
    assert U.step_identification(sid)["status"] == "warning"       # panel / PCB rev unknown
    assert U.step_compatibility(sid)["verdict"] == "VERIFIED COMPATIBLE"
    assert U.step_validation(sid)["status"] == "passed"
    b = U.step_backup(sid, "settings exported via Setup > Export (file acme.cfg)")
    assert b["items"]["full_firmware_image"].startswith("YES") and Path(b["items"]["hardware_report"]).exists()
    usb = tmp_path / "USB"
    usb.mkdir()
    prep = U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(usb), fs_probe=probe())
    assert prep["status"] == "passed" and prep["executable"]
    steps = []
    ex = U.step_execution(sid, progress=lambda d, t, s: steps.append(s), fs_probe=probe())
    assert ex["status"] == "done" and ex["ok"] and "verifying" in steps
    on_usb = usb / "upgrade_v2.bin"
    import hashlib
    assert hashlib.sha256(on_usb.read_bytes()).hexdigest() == cand.sha256
    assert not list(usb.glob("*.tvis-partial"))
    v = U.step_verification(sid, "V2.0", True, None, True, {"picture": True, "sound": True})
    assert v["status"] == "passed" and ctx.projects.get(p.id).firmware_version == "V2.0"
    g = U.recovery_guidance(sid)["guidance"]
    assert any("NOT documented" in x for x in g) and any("Contact Acme service" in x for x in g)
    acts = {e["action"] for e in ctx.audit.entries("tv_project", p.id, limit=500)}
    assert {"upgrade.start", "upgrade.step.execution", "upgrade.step.verification"} <= acts


def test_unverified_profile_gives_instructions_only(ctx, tv, tmp_path):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("upgrade_v2.bin"), verified=False)
    for st in (U.step_identification, U.step_compatibility, U.step_validation):
        st(sid)
    U.step_backup(sid)
    (tmp_path / "USB").mkdir()
    prep = U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(tmp_path / "USB"), fs_probe=probe())
    assert not prep["executable"] and "profile not verified" in prep["why_not_executable"][0]
    ex = U.step_execution(sid, fs_probe=probe())
    assert ex["status"] == "instructions_only" and not list((tmp_path / "USB").iterdir())


def test_instruction_only_methods_never_execute(ctx, tv):
    p, base, fw = tv
    for method in ("authorized_uart", "service_tool", "official_network", "vendor_recovery", "authorized_usb_device"):
        U, sid = _session(ctx, p, fw(f"upgrade_{method}.bin"), method=method)
        for st in (U.step_identification, U.step_compatibility, U.step_validation):
            st(sid)
        U.step_backup(sid)
        prep = U.step_preparation(sid, True, True, U.confirmation_phrase(sid), None)
        assert not prep["executable"] and "instruction-only" in prep["why_not_executable"][0]
        assert U.step_execution(sid)["status"] == "instructions_only"
        with pytest.raises(PermissionError):
            METHODS[method].execute({}, None, "x")


def test_incompatible_firmware_not_executable(ctx, tv, tmp_path):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("upgrade_bad.bin", model="OTHERTV43"))
    U.step_identification(sid)
    assert U.step_compatibility(sid)["status"] == "failed"
    # an INCOMPATIBLE firmware cannot even proceed to validation/preparation
    with pytest.raises(UpgradeBlocked):
        U.step_validation(sid)
    U.step_backup(sid)
    (tmp_path / "USB").mkdir()
    with pytest.raises(UpgradeBlocked):
        U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(tmp_path / "USB"), fs_probe=probe())
    with pytest.raises(UpgradeBlocked):
        U.step_execution(sid, fs_probe=probe())
    assert not list((tmp_path / "USB").iterdir())


def test_preparation_checks_fail(ctx, tv, tmp_path):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("upgrade_v2.bin"))
    for st in (U.step_identification, U.step_compatibility, U.step_validation):
        st(sid)
    U.step_backup(sid)
    usb = tmp_path / "USB"
    usb.mkdir()
    bad = {"NTFS": probe(fs="NTFS"), "space": probe(free=10), "fixed": probe(removable=False)}
    for name, pr in bad.items():
        prep = U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(usb), fs_probe=pr)
        assert prep["status"] == "failed", name
        with pytest.raises(UpgradeBlocked):
            U.step_execution(sid, fs_probe=pr)
    assert U.step_preparation(sid, False, True, U.confirmation_phrase(sid), str(usb), fs_probe=probe())["status"] == "failed"
    assert U.step_preparation(sid, True, True, "upgrade", str(usb), fs_probe=probe())["status"] == "failed"


def test_package_name_validation(ctx, tv):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("random_name.bin"))
    U.step_identification(sid)
    U.step_compatibility(sid)
    v = U.step_validation(sid)
    assert v["status"] == "failed" and any(c["name"] == "Package name vs documentation" and c["ok"] is False
                                           for c in v["checks"])


def test_cancel_copy_leaves_nothing(ctx, tv, tmp_path):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("upgrade_v2.bin"))
    for st in (U.step_identification, U.step_compatibility, U.step_validation):
        st(sid)
    U.step_backup(sid)
    usb = tmp_path / "USB"
    usb.mkdir()
    U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(usb), fs_probe=probe())
    r = U.step_execution(sid, cancel=lambda: True, fs_probe=probe())
    assert r["status"] == "cancelled" and list(usb.iterdir()) == []


def test_backup_never_claims_full_image(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55", chassis="C",
                                      firmware_version="V1"))
    f = tmp_path / "upgrade_v2.bin"
    fb.composite(f)
    rec = ctx.library.import_file(f, project_id=p.id, category="Official")
    U, sid = _session(ctx, p, rec)
    U.step_identification(sid)
    b = U.step_backup(sid)
    assert b["status"] == "warning" and b["items"]["full_firmware_image"].startswith("NO — only metadata")


def test_identification_blocks_without_required_data(ctx, tmp_path):
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme", model_number="TESTTV55"))
    f = tmp_path / "upgrade_v2.bin"
    fb.composite(f)
    rec = ctx.library.import_file(f, project_id=p.id)
    U, sid = _session(ctx, p, rec)
    r = U.step_identification(sid)
    assert r["status"] == "failed" and {"current_firmware", "mainboard or chassis"} <= set(r["missing_required"])
    with pytest.raises(UpgradeBlocked):
        U.step_compatibility(sid)


def test_verification_detects_wrong_version(ctx, tv, tmp_path):
    p, base, fw = tv
    U, sid = _session(ctx, p, fw("upgrade_v2.bin", version="V2.0"))
    for st in (U.step_identification, U.step_compatibility, U.step_validation):
        st(sid)
    U.step_backup(sid)
    (tmp_path / "USB").mkdir()
    U.step_preparation(sid, True, True, U.confirmation_phrase(sid), str(tmp_path / "USB"), fs_probe=probe())
    U.step_execution(sid, fs_probe=probe())
    v = U.step_verification(sid, "V1.0", True, None, True, {"sound": True})
    assert v["status"] == "failed" and v["version_check"] == "DIFFERS"
    assert ctx.projects.get(p.id).firmware_version == "V1.0"


def test_reports(ctx, tv, tmp_path):
    from pypdf import PdfReader
    p, base, fw = tv
    cand = fw("upgrade_v2.bin", version="V2.0")
    U, sid = _session(ctx, p, cand)
    U.step_identification(sid)
    U.step_compatibility(sid)
    cid = U.session(sid)["compatibility_id"]
    t = " ".join(pg.extract_text() for pg in PdfReader(ctx.upgrade_reports.compatibility_pdf(cid)).pages)
    assert "Firmware Compatibility Report" in t and "VERIFIED COMPATIBLE" in t and "partition_layout" in t
    t2 = " ".join(pg.extract_text() for pg in PdfReader(ctx.upgrade_reports.upgrade_pdf(sid)).pages)
    assert "Firmware Upgrade Report" in t2 and "never writes to the TV" in t2
    data = json.loads(ctx.upgrade_reports.upgrade_json(sid).read_text())
    assert data["session"]["steps"]["compatibility"]["verdict"] == "VERIFIED COMPATIBLE"
