import gzip
import io
import json
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import firmware_builders as fb
from app.integrations.binwalk import adapter as bw
from app.integrations.ghidra import adapter as gh
from app.modules.firmware_analyzer import entropy, scanner, strings_analysis
from app.modules.firmware_analyzer.extractor import Limits, SafeExtractor
from app.modules.firmware_analyzer.hexview import hexdump, parse_offset
from app.modules.firmware_analyzer.metadata import Fact, merge_facts
from app.modules.firmware_analyzer.service import IntegrityError
from app.security.hashing import sha256_file


@pytest.fixture
def composite(tmp_path):
    p = tmp_path / "TVFW_V8-T658T01-LF1V123.bin"
    parts = fb.composite(p)
    return p, parts


# ---- scanner ---------------------------------------------------------------------------------
def test_scanner_finds_all_native_formats(composite):
    p, parts = composite
    r = scanner.scan(p)
    by = {(c.type, c.offset): c for c in r.components}
    for typ, key in [("uimage", "uimage"), ("dtb", "dtb"), ("gzip", "initrd_gz"), ("tar", "tar"), ("zip", "zip"),
                     ("xz", "xz"), ("bzip2", "bz2"), ("elf", "elf"), ("android_boot", "boot"),
                     ("android_sparse", "sparse"), ("vbmeta", "vbmeta")]:
        assert (typ, parts[key]) in by, typ
        assert by[(typ, parts[key])].validated
    u = by[("uimage", parts["uimage"])]
    assert u.details["arch"] == "ARM" and u.details["os"] == "Linux" and u.details["data_crc_ok"] is True
    gz_in_u = by[("gzip", parts["uimage"] + 64)]
    assert r.components[gz_in_u.parent] is u                     # nesting
    assert by[("elf", parts["elf"])].details["machine"] == "ARM"
    assert by[("android_boot", parts["boot"])].details["cmdline"].startswith("console=ttyS0")
    assert by[("vbmeta", parts["vbmeta"])].details["signed"] is True
    assert by[("android_sparse", parts["sparse"])].details["expanded_size"] == 16384


def test_corrupted_uimage_header_rejected(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(fb.uimage(b"x" * 1000, comp=0, corrupt_header=True))
    r = scanner.scan(p)
    assert not [c for c in r.components if c.type == "uimage"]
    assert r.rejected.get("uimage") == 1


def test_uimage_data_crc_mismatch_reported(tmp_path):
    data = bytearray(fb.uimage(b"y" * 4000, comp=0))
    data[100] ^= 0xFF                                  # payload corrupted, header intact
    p = tmp_path / "u.bin"
    p.write_bytes(bytes(data))
    c = scanner.scan(p).components[0]
    assert c.details["data_crc_ok"] is False and "MISMATCH" in c.description


def test_random_data_has_no_false_positives(tmp_path):
    p = tmp_path / "rand.bin"
    p.write_bytes(os.urandom(4 * 1024 * 1024))
    r = scanner.scan(p)
    assert r.components == []
    assert sum(r.rejected.values()) > 0                 # candidates were seen but rejected


def test_gpt_and_partitions(tmp_path):
    p = tmp_path / "disk.img"
    p.write_bytes(fb.gpt_disk([("boot", 64, fb.uimage(b"k" * 3000, comp=0)), ("rootfs", 128, b"\0" * 4096)]))
    r = scanner.scan(p)
    g = [c for c in r.components if c.type == "gpt"][0]
    assert [x["name"] for x in g.details["partitions"]] == ["boot", "rootfs"]
    assert g.details["partitions"][0]["offset"] == 64 * 512
    assert not [c for c in r.components if c.type == "mbr"]     # protective MBR not reported separately


def test_gaps(composite):
    p, _ = composite
    r = scanner.scan(p)
    assert scanner.gaps(r)[0] == (0, 0x10000)


@pytest.mark.skipif(not fb.have("mksquashfs", "mkfs.ext4", "mkfs.jffs2"), reason="filesystem tools not installed")
def test_scanner_real_filesystem_images(tmp_path):
    src = fb.build_rootfs_dir(tmp_path / "root")
    for builder, typ in ((fb.squashfs, "squashfs"), (fb.ext4, "ext4"), (fb.jffs2, "jffs2")):
        img = builder(tmp_path / f"{typ}.img", src)
        c = scanner.scan(img).components[0]
        assert (c.type, c.offset, c.validated) == (typ, 0, True)
        # filesystem's own size; mksquashfs pads the file to 4 KiB, so size <= file size
        assert 0 < c.size <= img.stat().st_size
        if typ != "squashfs":
            assert c.size == img.stat().st_size


# ---- entropy -------------------------------------------------------------------------------------
def test_entropy_indicator_only_for_unexplained_data(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"\0" * 262144 + os.urandom(524288) + b"\0" * 262144)
    res = entropy.analyze(p)
    assert any(r["class"] == "high" for r in res.regions) and res.indicators
    q = tmp_path / "g.bin"
    q.write_bytes(fb.uimage(gzip.compress(os.urandom(600000), mtime=0)))
    res2 = entropy.analyze(q, scanner.scan(q).components)
    assert res2.indicators == []                         # explained by validated gzip/uImage


def test_shannon_bounds():
    assert entropy.shannon(b"\0" * 100) == 0
    assert abs(entropy.shannon(bytes(range(256))) - 8.0) < 1e-9


# ---- strings ---------------------------------------------------------------------------------------
def test_strings_categories(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(os.urandom(100) + b"\0Linux version 4.9.118 (x@y) (gcc 6)\0" + b"\0ro.product.model=TESTTV55\0" +
                  b"\0U-Boot 2015.04-tv (Jan 01 2020)\0chip MSD6A648 init\0https://update.example.com/fw\0")
    r = strings_analysis.analyze(p, tmp_path / "dump.txt")
    assert r.hits["kernel_version"][0]["value"] == "4.9.118" and r.hits["kernel_version"][0]["offset"] > 100
    assert r.hits["android_property"][0]["value"] == "ro.product.model TESTTV55"
    assert r.hits["uboot_version"][0]["value"].startswith("2015.04")
    assert r.hits["url"][0]["value"] == "https://update.example.com/fw"
    assert r.chip_mentions[0]["part"] == "MSD6A648"
    assert "Linux version" in (tmp_path / "dump.txt").read_text()


# ---- metadata merging ----------------------------------------------------------------------------
def test_merge_facts_and_conflicts():
    out = merge_facts([Fact("android_version", "9", "a", 0.8), Fact("android_version", "9", "b", 0.8),
                       Fact("cpu_architecture", "ARM (32-bit)", "x", 0.9), Fact("cpu_architecture", "MIPS", "y", 0.6)])
    av = [f for f in out if f.attribute == "android_version"]
    assert len(av) == 1 and av[0].confidence == pytest.approx(0.96) and av[0].source.startswith("2 sources")
    assert any(f.attribute == "conflict" and "MIPS" in f.value for f in out)


# ---- extractor safety -------------------------------------------------------------------------------
def _zip_with(names: dict[str, bytes]) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, d in names.items():
            z.writestr(n, d)
    return b.getvalue()


def test_zip_path_traversal_blocked(tmp_path):
    src = tmp_path / "evil.zip"
    src.write_bytes(_zip_with({"ok.txt": b"1", "../../escape.txt": b"2"}))
    ex = SafeExtractor(tmp_path / "out")
    c = scanner.Component(0, src.stat().st_size, "zip", "archive", "")
    e = ex.extract_component(src, c)
    assert e.status == "failed" and "traversal" in e.message
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path.parent / "escape.txt").exists()


def test_tar_symlinks_and_absolute_paths(tmp_path):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        ti = tarfile.TarInfo("etc/passwd_link")
        ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
        t.addfile(ti)
        ti = tarfile.TarInfo("/abs/file.txt")
        ti.size = 3
        t.addfile(ti, io.BytesIO(b"abc"))
    src = tmp_path / "t.tar"
    src.write_bytes(b.getvalue())
    ex = SafeExtractor(tmp_path / "out")
    e = ex.extract_component(src, scanner.Component(0, src.stat().st_size, "tar", "archive", ""))
    assert e.status == "extracted"
    out = Path(e.dest)
    assert (out / "abs" / "file.txt").read_bytes() == b"abc"     # absolute path re-rooted inside workspace
    assert not (out / "etc" / "passwd_link").exists()
    assert e.skipped_links == ["etc/passwd_link -> /etc/passwd"]


def test_decompression_bomb_stopped(tmp_path):
    src = tmp_path / "bomb.gz"
    src.write_bytes(gzip.compress(b"\0" * (40 * 1024 * 1024)))
    ex = SafeExtractor(tmp_path / "out", limits=Limits(max_ratio=100))
    e = ex.extract_component(src, scanner.Component(0, src.stat().st_size, "gzip", "compressed", ""))
    assert e.status == "failed" and "ratio" in e.message


def test_total_size_limit(tmp_path):
    src = tmp_path / "big.zip"
    src.write_bytes(_zip_with({f"f{i}.bin": os.urandom(100_000) for i in range(5)}))
    ex = SafeExtractor(tmp_path / "out", limits=Limits(max_total_bytes=1_000_000))
    e = ex.extract_component(src, scanner.Component(0, src.stat().st_size, "zip", "archive", ""))
    assert e.status == "failed" and "limit" in e.message


def test_cpio_and_sparse_and_uimage_extraction(tmp_path):
    ex = SafeExtractor(tmp_path / "out")
    cp = tmp_path / "r.cpio"
    cp.write_bytes(fb.cpio_newc({"etc/a.conf": b"hello"}, {"bin/sh": "busybox"}))
    e = ex.extract_component(cp, scanner.Component(0, cp.stat().st_size, "cpio", "archive", ""))
    assert (Path(e.dest) / "etc" / "a.conf").read_bytes() == b"hello" and e.skipped_links == ["bin/sh -> busybox"]
    raw = b"A" * 4096 + b"\0" * 8192 + b"B" * 4096
    sp = tmp_path / "s.img"
    sp.write_bytes(fb.android_sparse(raw))
    e = ex.extract_component(sp, scanner.Component(0, sp.stat().st_size, "android_sparse", "filesystem", ""))
    assert (Path(e.dest) / "unsparsed.img").read_bytes() == raw
    ui = tmp_path / "u.bin"
    ui.write_bytes(fb.uimage(gzip.compress(fb.cpio_newc({"init": b"x"}), mtime=0)))
    c = scanner.scan(ui).components[0]
    e = ex.extract_component(ui, c)
    assert e.status == "extracted" and (Path(e.dest) / "cpio_contents" / "init").read_bytes() == b"x"


def test_unsupported_format_is_reported(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\0" * 100)
    ex = SafeExtractor(tmp_path / "out", tools={})
    e = ex.extract_component(p, scanner.Component(0, 100, "cramfs", "filesystem", ""))
    assert e.status == "carved" and "no safe extractor" in e.message


# ---- hex ------------------------------------------------------------------------------------------
def test_hexdump_and_offsets():
    out = hexdump(b"ABC\x00\x01" + b"z" * 20, 0x100)
    assert out.splitlines()[0].startswith("00000100  41 42 43 00 01") and "|ABC..zzzzzzzzzzz|" in out
    assert parse_offset("0x10") == 16 and parse_offset("100") == 100 and parse_offset("ff") == 255


# ---- binwalk / ghidra adapters ---------------------------------------------------------------------
def test_binwalk_parsers_and_wsl_path():
    txt = ("\nDECIMAL       HEXADECIMAL     DESCRIPTION\n" + "-" * 80 +
           "\n400           0x190           Squashfs filesystem, little endian, version 4.0\n")
    assert [(h.offset, h.description[:8]) for h in bw.parse_v2(txt)] == [(400, "Squashfs")]
    v3 = [{"Analysis": {"file_map": [{"offset": 64, "size": 100, "description": "gzip"}]}}]
    assert bw.parse_v3(v3)[0].size == 100
    assert bw.to_wsl_path(r"C:\Users\me\fw.bin") == "/mnt/c/Users/me/fw.bin"


@pytest.mark.skipif(bw.find_binwalk() is None, reason="binwalk not installed")
def test_binwalk_real_run(composite):
    p, parts = composite
    res = bw.scan(p, bw.find_binwalk())
    assert any(h.offset == parts["uimage"] for h in res.hits)


def _fake_headless(tmp_path: Path) -> str:
    """A stand-in for analyzeHeadless that follows the same CLI and writes the JSON summary."""
    py = tmp_path / "fake_headless.py"
    py.write_text(
        "import sys, json\n"
        "a = sys.argv[1:]\n"
        "out = a[a.index('-postScript') + 2]\n"
        "binary = a[a.index('-import') + 1]\n"
        "assert '-deleteProject' in a\n"
        "json.dump({'program': binary.split('/')[-1].split(chr(92))[-1], 'language': 'ARM:LE:32:v8',\n"
        "           'function_count': 3, 'libraries': ['libc.so.6']}, open(out, 'w'))\n")
    if os.name == "nt":
        w = tmp_path / "analyzeHeadless.bat"
        w.write_text(f'@"{sys.executable}" "{py}" %*\n')
    else:
        w = tmp_path / "analyzeHeadless"
        w.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
        w.chmod(w.stat().st_mode | stat.S_IEXEC)
    return str(w)


def test_ghidra_command_and_workspace_guard(tmp_path):
    cmd = gh.build_command("aH", Path("/w/bin"), Path("/w/p"), Path("/w/o.json"), 60, "ARM:LE:32:v8")
    assert cmd[:3] == ["aH", str(Path("/w/p")), "tvis_tmp"]          # OS-native path form (\\w\\p on Windows)
    assert "-deleteProject" in cmd and cmd[-2:] == ["-processor", "ARM:LE:32:v8"]
    with pytest.raises(ValueError):
        gh.analyze("aH", tmp_path / "x", tmp_path / "ws")      # binary outside the workspace


# ---- service (end to end) ----------------------------------------------------------------------------
def test_full_analysis_pipeline(ctx, composite):
    p, parts = composite
    rec = ctx.library.import_file(p, manufacturer="Acme", model_number="A55")
    before = sha256_file(rec.stored_path)
    rid = ctx.firmware.analyze(rec.id, use_binwalk=False)
    run = ctx.firmware.latest_run(rec.id)
    assert run["status"] == "completed" and run["original_unchanged"] == 1
    assert sha256_file(rec.stored_path) == before == rec.sha256
    meta = {(m["attribute"], m["value"]) for m in ctx.firmware.metadata(rid)}
    assert ("kernel_version", "4.9.118") in meta
    assert ("cpu_architecture", "ARM (32-bit)") in meta
    assert ("android_version", "9") in meta and ("product_model", "TESTTV55") in meta
    assert ("os_family", "Android") in meta
    assert ("signing", "Android Verified Boot, SHA256_RSA2048") in meta
    assert any(a == "firmware_version" and v == "V8-T658T01-LF1V123" for a, v in meta)   # from file name
    assert any(a == "bootloader" and "2015.04" in v for a, v in meta)
    fv = [m for m in ctx.firmware.metadata(rid) if m["attribute"] == "firmware_version"][0]
    assert fv["confidence"] < 0.4 and "unverified" in fv["source"]
    files = ctx.firmware.files(rid)
    kinds = {f["rel_path"].rsplit("/", 1)[-1]: f["kind"] for f in files}
    assert kinds["shadow"] == "sensitive" and kinds["app.conf"] == "config"
    assert any(f["kind"] == "symlink" for f in files)
    ex = ctx.firmware.result(rid, "extraction")
    assert {e["component_type"] for e in ex if e["status"] == "extracted"} >= {"uimage", "gzip", "tar", "zip", "xz",
                                                                                "bzip2", "android_sparse"}
    assert ctx.firmware.read_bytes(rec.id, 0, 4) == b"TVFW"
    # everything produced lives in the workspace
    ws = ctx.config.workspace_dir.resolve()
    assert ws in ctx.firmware.run_dir(rid).resolve().parents


def test_working_copy_recreated_if_tampered(ctx, composite):
    p, _ = composite
    rec = ctx.library.import_file(p)
    wc = ctx.firmware.working_copy(rec.id)
    wc.write_bytes(b"tampered by some tool")
    wc2 = ctx.firmware.working_copy(rec.id)
    assert sha256_file(wc2) == rec.sha256


def test_analysis_refused_when_original_altered(ctx, composite):
    p, _ = composite
    rec = ctx.library.import_file(p)
    sp = Path(rec.stored_path)
    os.chmod(sp, stat.S_IWUSR | stat.S_IRUSR)
    sp.write_bytes(b"corrupted")
    with pytest.raises(IntegrityError):
        ctx.firmware.analyze(rec.id)
    assert ctx.library.get(rec.id).verification_status == "hash_mismatch"


def test_import_extracted_with_provenance(ctx, tmp_path):
    inner = b"INNER-UPGRADE-IMAGE" + os.urandom(1000)
    pkg = tmp_path / "package.zip"
    pkg.write_bytes(_zip_with({"upgrade/upgrade_tv.bin": inner}))
    rec = ctx.library.import_file(pkg, manufacturer="Acme", model_number="A55", category="Official",
                                  download_url="https://vendor.example/pkg.zip")
    rid = ctx.firmware.analyze(rec.id, use_binwalk=False)
    rel = [f["rel_path"] for f in ctx.firmware.files(rid) if f["rel_path"].endswith("upgrade_tv.bin")][0]
    new = ctx.firmware.import_extracted(rec.id, rid, rel)
    assert sha256_file(new.stored_path) == __import__("hashlib").sha256(inner).hexdigest()
    assert new.category == "Official" and f"firmware #{rec.id}" in new.notes
    src = ctx.db.query_one("SELECT source_type FROM firmware_sources s JOIN firmware_files f ON f.source_id=s.id "
                           "WHERE f.id=?", (new.id,))[0]
    assert src == "extracted_from_firmware"
    with pytest.raises(ValueError):
        ctx.firmware.extracted_path(rid, "../../../etc/passwd")


def test_compare_two_versions(ctx, tmp_path):
    a, b = tmp_path / "fw_a.bin", tmp_path / "fw_b.bin"
    fb.composite(a, "4.9.118")
    fb.composite(b, "4.9.200", extra_file=b"new setting\n")
    ra, rb = ctx.library.import_file(a), ctx.library.import_file(b)
    for r in (ra, rb):
        ctx.firmware.analyze(r.id, use_binwalk=False)
    res = ctx.firmware.compare(ra.id, rb.id)
    assert not res["identical"] and 0 < res["binary"]["shared_blocks_pct"] < 100
    assert res["metadata"]["kernel_version"] == {"a": ["4.9.118"], "b": ["4.9.200"]}
    assert "cpu_architecture" in res["metadata_same"]
    assert any(p.endswith("etc/app.conf") for p in res["files"]["changed"])


def test_ghidra_run_with_stand_in(ctx, composite, tmp_path):
    p, _ = composite
    rec = ctx.library.import_file(p)
    rid = ctx.firmware.analyze(rec.id, use_binwalk=False)
    ctx.config.set("tools.ghidra_headless", _fake_headless(tmp_path))
    rel = [f["rel_path"] for f in ctx.firmware.files(rid) if f["rel_path"].endswith("payload.bin")][0]
    res = ctx.firmware.run_ghidra(rec.id, rid, rel)
    assert res["summary"]["language"] == "ARM:LE:32:v8" and res["summary"]["program"] == "payload.bin"
    assert ctx.firmware.result(rid, "ghidra")["summary"]["function_count"] == 3


def test_firmware_reports(ctx, composite):
    from pypdf import PdfReader
    p, _ = composite
    rec = ctx.library.import_file(p)
    with pytest.raises(ValueError):
        ctx.firmware_reports.generate_pdf(rec.id)          # not analysed yet
    ctx.firmware.analyze(rec.id, use_binwalk=False)
    pdf = ctx.firmware_reports.generate_pdf(rec.id)
    text = " ".join(pg.extract_text() for pg in PdfReader(pdf).pages)
    assert "Firmware Analysis Report" in text and "SHA-256 identical before and after" in text
    assert "4.9.118" in text and "uimage" in text
    data = json.loads(ctx.firmware_reports.export_json(rec.id).read_text(encoding="utf-8"))
    assert data["run"]["original_unchanged"] == 1 and data["components"]
    assert {r["format"] for r in ctx.db.query("SELECT format FROM technical_reports WHERE report_type='firmware_analysis'")} == {"pdf", "json"}
