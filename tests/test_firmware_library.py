import gzip
import os
import stat
from pathlib import Path

import pytest

from app.modules.firmware_analyzer.signatures import detect_format
from app.modules.firmware_library.library import SUBFOLDERS, DuplicateFirmware
from app.security.file_protection import ensure_within, is_read_only, safe_component
from app.security.hashing import sha256_bytes, sha256_file
from app.services.project_service import TVProject


def test_sha256_known_vector(tmp_path):
    f = tmp_path / "abc"
    f.write_bytes(b"abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_file(f) == sha256_bytes(b"abc") == expected


def test_import_preserves_original_and_layout(ctx, firmware_file):
    original_bytes = firmware_file.read_bytes()
    original_mtime = firmware_file.stat().st_mtime_ns
    p = ctx.projects.create(TVProject(name="t", manufacturer="Acme:TV", model_number="55/X"))
    rec = ctx.library.import_file(firmware_file, manufacturer=p.manufacturer,
                                  model_number=p.model_number, project_id=p.id, version="1.2.3")
    # original unchanged
    assert firmware_file.read_bytes() == original_bytes
    assert firmware_file.stat().st_mtime_ns == original_mtime
    # stored copy correct, read-only, inside sanitized folder layout
    stored = Path(rec.stored_path)
    assert sha256_file(stored) == rec.sha256 == sha256_file(firmware_file)
    assert is_read_only(stored)
    model_dir = ctx.library.root / "Acme_TV" / "55_X"
    assert stored.parent == model_dir / "Original"
    for sub in SUBFOLDERS:
        assert (model_dir / sub).is_dir()
    assert rec.detected_format == "ZIP archive"
    assert rec.verification_status == "hash_ok"
    assert ctx.db.scalar("SELECT COUNT(*) FROM firmware_versions WHERE firmware_id=?", (rec.id,)) == 1
    src = ctx.db.query_one("SELECT * FROM firmware_sources WHERE id=(SELECT source_id FROM firmware_files WHERE id=?)",
                           (rec.id,))
    assert src["source_type"] == "local_import" and src["accessed_at"]


def test_duplicate_detection(ctx, firmware_file, tmp_path):
    rec = ctx.library.import_file(firmware_file)
    copy = tmp_path / "renamed.bin"
    copy.write_bytes(firmware_file.read_bytes())
    with pytest.raises(DuplicateFirmware) as ei:
        ctx.library.import_file(copy)
    assert ei.value.record.id == rec.id


def test_same_name_different_content(ctx, tmp_path):
    a = tmp_path / "a" / "fw.bin"
    b = tmp_path / "b" / "fw.bin"
    a.parent.mkdir()
    b.parent.mkdir()
    a.write_bytes(b"one")
    b.write_bytes(b"two")
    r1 = ctx.library.import_file(a)
    r2 = ctx.library.import_file(b)
    assert r1.stored_path != r2.stored_path


def test_integrity_check_detects_tampering(ctx, firmware_file):
    rec = ctx.library.import_file(firmware_file)
    assert ctx.library.verify_integrity(rec.id).verification_status == "hash_ok"
    p = Path(rec.stored_path)
    os.chmod(p, stat.S_IWUSR | stat.S_IRUSR)
    p.write_bytes(b"tampered")
    assert ctx.library.verify_integrity(rec.id).verification_status == "hash_mismatch"


def test_working_copy_isolated(ctx, firmware_file):
    rec = ctx.library.import_file(firmware_file)
    wc = ctx.library.make_working_copy(rec.id)
    assert wc != Path(rec.stored_path)
    assert ctx.config.workspace_dir in wc.parents
    wc.write_bytes(b"modified by analysis")
    assert sha256_file(rec.stored_path) == rec.sha256


def test_search_by_mainboard(ctx, firmware_file, tmp_path):
    ctx.library.import_file(firmware_file, mainboard="TP.MS338.PB801")
    other = tmp_path / "o.bin"
    other.write_bytes(b"\x00" * 10)
    ctx.library.import_file(other, mainboard="MSD6A648")
    assert [r.mainboard for r in ctx.library.list(mainboard="ms338")] == ["TP.MS338.PB801"]


def test_invalid_category(ctx, firmware_file):
    with pytest.raises(ValueError):
        ctx.library.import_file(firmware_file, category="Hacked")


@pytest.mark.parametrize("data,name,expected", [
    (b"PK\x03\x04rest", "f.zip", "ZIP archive"),
    (gzip.compress(b"x"), "f.gz", "GZIP compressed"),
    (b"\x27\x05\x19\x56" + b"\x00" * 60, "f.bin", "U-Boot uImage"),
    (b"ANDROID!" + b"\x00" * 20, "boot.img", "Android boot image"),
    (b"hsqs" + b"\x00" * 20, "f.img", "SquashFS (LE)"),
    (b"\x7fELF" + b"\x00" * 20, "f", "ELF executable"),
    (b"\x00" * 0x438 + b"\x53\xef" + b"\x00" * 100, "f.img", "ext2/3/4 filesystem"),
], ids=["zip", "gzip", "uimage", "android_boot", "squashfs", "elf", "ext4"])
def test_signature_detection(tmp_path, data, name, expected):
    f = tmp_path / name
    f.write_bytes(data)
    assert detect_format(f).format == expected


def test_tar_and_unknown(tmp_path):
    import tarfile
    t = tmp_path / "x.tar"
    inner = tmp_path / "inner.txt"
    inner.write_text("hi")
    with tarfile.open(t, "w") as tf:
        tf.add(inner, arcname="inner.txt")
    assert detect_format(t).format == "POSIX TAR archive"
    u = tmp_path / "blob.bin"
    u.write_bytes(b"\x01\x02\x03\x04" * 16)
    r = detect_format(u)
    assert (r.confidence, r.category) == ("extension", "unknown")  # never guessed
    n = tmp_path / "notes.txt"
    n.write_bytes(b"hello")
    assert detect_format(n).format == "unknown"


def test_safe_component_and_traversal(tmp_path):
    assert safe_component('a<b>:c"d') == "a_b__c_d"
    assert safe_component("CON") == "_CON"
    assert safe_component("..") == "Unknown"
    assert safe_component(None) == "Unknown"
    with pytest.raises(ValueError):
        ensure_within(tmp_path, tmp_path / ".." / "evil")
