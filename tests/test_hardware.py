import csv
import json
from pathlib import Path

import pytest

from app.modules.hardware_analyzer.datasheets import DuplicateDatasheet, base_family, extract_facts, memory_family
from app.modules.hardware_analyzer.decoders import decode, format_bits, load_decoders
from app.modules.hardware_analyzer.service import category_for, part_number_problem
from app.security.file_protection import is_read_only
from app.security.hashing import sha256_file
from app.services.project_service import TVProject
from synthetic_datasheets import ddr3_datasheet, make_datasheet, spi_nor_datasheet

GBIT, MBIT = 1024 ** 3, 1024 ** 2


# ---- decoders ------------------------------------------------------------------------
@pytest.mark.parametrize("part,dec_id,mtype,bits,org", [
    ("K4B4G1646E-BYK0", "samsung_ddr", "DDR3 SDRAM", 4 * GBIT, "x16"),
    ("K4A8G165WB", "samsung_ddr", "DDR4 SDRAM", 8 * GBIT, "x16"),
    ("H5TQ4G63AFR", "skhynix_ddr3", "DDR3 SDRAM", 4 * GBIT, "x16"),
    ("H5TC4G83", "skhynix_ddr3", "DDR3L SDRAM", 4 * GBIT, "x8"),
    ("H5AN8G6NAFR", "skhynix_ddr4", "DDR4 SDRAM", 8 * GBIT, "x16"),
    ("MT41K256M16TW", "micron_ddr", "DDR3L SDRAM", 4 * GBIT, "x16"),
    ("MT40A512M16", "micron_ddr", "DDR4 SDRAM", 8 * GBIT, "x16"),
    ("NT5CC256M16DP", "nanya_ddr", "DDR3L SDRAM", 4 * GBIT, "x16"),
    ("W25Q64JVSIQ", "winbond_spi_nor", "SPI NOR flash", 64 * MBIT, None),
    ("W25N01GVZEIG", "winbond_spi_nand", "SPI NAND flash", GBIT, None),
    ("GD25Q128CSIG", "gigadevice_spi_nor", "SPI NOR flash", 128 * MBIT, None),
    ("MX25L12835F", "macronix_spi_nor", "SPI NOR flash", 128 * MBIT, None),
])
def test_decoders(part, dec_id, mtype, bits, org):
    d, facts = decode(part)
    f = {x.attribute: x for x in facts}
    assert d.id == dec_id
    assert f["memory_type"].value == mtype
    assert int(f["density_bits"].value) == bits
    assert (f["organization"].value if "organization" in f else None) == org
    assert all(x.source_type == "decoder" and x.source_reference.startswith(f"decoder {dec_id}") for x in facts)


def test_emmc_capacity_in_bytes():
    _, facts = decode("KLMAG1JETD")
    f = {x.attribute: x.value for x in facts}
    assert f["memory_type"] == "eMMC" and int(f["capacity_bytes"]) == 16 * 1024 ** 3


@pytest.mark.parametrize("part", ["MSD6A648", "MT5889", "RTL8822CS", "K4", "W25Q", "W25Q99JV", "RANDOM123"])
def test_no_decode_without_full_match(part):
    assert decode(part) is None


def test_decoder_file_consistent():
    ids = [d.id for d in load_decoders()]
    assert len(ids) == len(set(ids))
    assert all(0 < d.confidence <= 0.8 for d in load_decoders())  # never presented as certain


def test_format_bits():
    assert format_bits(4 * GBIT) == "4 Gbit" and format_bits(64 * MBIT) == "64 Mbit"


# ---- helpers -------------------------------------------------------------------------
@pytest.mark.parametrize("text,cat", [("TV SoC / scaler", "soc"), ("DRAM", "ram"), ("SPI NOR flash", "flash"),
                                      ("eMMC", "flash"), ("Wi-Fi / Bluetooth", "wifi_bt"), ("Audio amplifier", "audio"),
                                      ("Power supply board", "power_supply"), ("PCB part number", "board"),
                                      ("TV SoC, T-Con or display driver IC", "other"), (None, "other"), ("ram", "ram")])
def test_category_for(text, cat):
    assert category_for(text) == cat


def test_part_number_problem():
    assert part_number_problem("W25Q64)V") and part_number_problem("MT58|9")
    assert not part_number_problem("EAX67133404(1.0)")
    assert not part_number_problem("K4B4G1646E-BYK0") and not part_number_problem("TP.MS338.PB801")


def test_memory_family_and_base_family():
    assert memory_family("DDR3 SDRAM") == memory_family("DDR3")
    assert memory_family("Serial NOR") == memory_family("SPI NOR flash")
    assert memory_family("DDR3L") != memory_family("DDR3")
    assert base_family("W25Q64JVSIQ") == base_family("W25Q64JVZPIQ")
    assert base_family("H5TQ4G63AFR").startswith(base_family("H5TQ4G63"))


def test_extract_facts_units_and_pages():
    pages = [(1, "4Gb DDR3 SDRAM VDD = 1.5V 96-ball FBGA DDR3-1600"), (2, "eMMC 8GB storage, 2.7V to 3.6V")]
    f = {(x.attribute, x.value): x for x in extract_facts(pages, 7)}
    assert ("density_bits", str(4 * GBIT)) in f            # 'Gb' = gigabits
    assert ("capacity_bytes", str(8 * 1024 ** 3)) in f     # 'GB' = gigabytes, not bits
    assert ("density_bits", str(8 * GBIT)) not in f
    assert ("supply_voltage", "1.5") in f and ("supply_voltage", "2.7-3.6") in f
    assert f[("supply_voltage", "2.7-3.6")].source_reference == "datasheet #7 p.2"
    assert ("data_rate", "1600") in f and ("memory_type", "DDR3") in f


# ---- datasheet library ----------------------------------------------------------------------
def test_datasheet_import_index_find(ctx, tmp_path):
    src = ddr3_datasheet(tmp_path / "ds.pdf")
    before = sha256_file(src)
    did = ctx.datasheets.import_pdf(src, vendor="Samsung", source_url="https://example.invalid/ds.pdf")
    assert sha256_file(src) == before
    ds = ctx.datasheets.get(did)
    assert is_read_only(Path(ds["stored_path"])) and ds["page_count"] == 2 and ds["text_extracted"] == 1
    assert ds["title"] == "4Gb DDR3 SDRAM test sheet"
    parts = {r["part_number"] for r in ctx.db.query("SELECT * FROM datasheet_parts WHERE datasheet_id=?", (did,))}
    assert {"K4B4G1646E-BYK0", "K4B4G0846E-BYK0"} <= parts
    assert not any(p.startswith("DDR3") for p in parts)
    exact = ctx.datasheets.find("K4B4G1646E-BYK0")[0]
    assert exact.level == "exact" and exact.page == 2
    fam = ctx.datasheets.find("K4B4G1646E-BCMA")[0]   # other speed/temperature suffix
    assert fam.level == "family" and fam.score < exact.score
    assert ctx.datasheets.find("W25Q64JV") == []
    with pytest.raises(DuplicateDatasheet):
        ctx.datasheets.import_pdf(src)


def test_datasheet_rejects_non_pdf(ctx, tmp_path):
    f = tmp_path / "x.pdf"
    f.write_bytes(b"not a pdf")
    with pytest.raises(ValueError):
        ctx.datasheets.import_pdf(f)


# ---- analyzer ---------------------------------------------------------------------------------
@pytest.fixture
def project(ctx):
    return ctx.projects.create(TVProject(name="Bench", mainboard="TP.MS338.PB801", pcb_revision="1.1"))


def test_analyze_exact_datasheet_corroborates_decoder(ctx, project, tmp_path):
    ctx.datasheets.import_pdf(ddr3_datasheet(tmp_path / "d.pdf"))
    cid = ctx.hardware.add_component(project.id, "ram", "k4b4g1646e-byk0", quantity=2, position="U3")
    a = ctx.hardware.analyze(cid)
    assert a.match_status == "datasheet_exact" and a.confidence >= 0.9
    assert a.manufacturer == "Samsung"
    dens = [f for f in a.facts if f.attribute == "density_bits" and f.source_type == "decoder"][0]
    assert dens.confidence == 0.9 and "corroborated" in dens.source_reference
    assert not any("not stated" in w for w in a.warnings)
    assert "4 Gbit" in a.specification
    row = ctx.hardware.get(cid)
    assert row["datasheet_id"] == a.datasheet["id"] and json.loads(row["analysis_warnings"]) == a.warnings


def test_analyze_family_match_warns_and_reduces(ctx, project, tmp_path):
    ctx.datasheets.import_pdf(spi_nor_datasheet(tmp_path / "s.pdf"))
    a = ctx.hardware.analyze(ctx.hardware.add_component(project.id, "flash", "W25Q64JVXGIQ"))
    assert a.match_status == "datasheet_family"
    assert any("variant" in w for w in a.warnings)
    ds_facts = [f for f in a.facts if f.source_type == "datasheet"]
    assert ds_facts and all(f.confidence <= 0.7 * 0.7 + 1e-9 for f in ds_facts)


def test_contradiction_reported(ctx, project, tmp_path):
    make_datasheet(tmp_path / "bad.pdf", "conflicting sheet", [["K4B4G1646E-BYK0", "2Gb DDR3 SDRAM"]])
    ctx.datasheets.import_pdf(tmp_path / "bad.pdf")
    a = ctx.hardware.analyze(ctx.hardware.add_component(project.id, "ram", "K4B4G1646E-BYK0"))
    assert any("density_bits 4 Gbit is not stated" in w for w in a.warnings)


def test_analyze_vendor_only_and_unidentified(ctx, project):
    a = ctx.hardware.analyze(ctx.hardware.add_component(project.id, "soc", "MSD6A648"))
    assert a.match_status == "vendor_only" and a.manufacturer.startswith("MStar")
    assert not any(f.attribute in ("density_bits", "capacity_bytes") for f in a.facts)
    b = ctx.hardware.analyze(ctx.hardware.add_component(project.id, "wifi", "QZX1234"))
    assert b.match_status == "unidentified" and b.facts == [] and b.confidence <= 0.4


def test_ocr_misread_part_not_decoded(ctx, project):
    a = ctx.hardware.analyze(ctx.hardware.add_component(project.id, "flash", "W25Q64)V"))
    assert a.match_status == "unidentified" and a.facts == []
    assert any("OCR misread" in w for w in a.warnings)


def test_reanalyze_keeps_user_facts(ctx, project):
    cid = ctx.hardware.add_component(project.id, "soc", "MSD6A648")
    with pytest.raises(ValueError):
        ctx.hardware.add_user_fact(cid, "cpu_cores", "4", None, "  ")
    ctx.hardware.add_user_fact(cid, "cpu_cores", "4", None, "service manual p.12")
    ctx.hardware.analyze(cid)
    ctx.hardware.analyze(cid)
    facts = ctx.hardware.facts(cid)
    assert [f["source_reference"] for f in facts if f["source_type"] == "user"] == ["service manual p.12"]
    assert len([f for f in facts if f["source_type"] == "marking_rule"]) == 2  # no duplicates


def test_board_summary_totals_only_with_full_evidence(ctx, project):
    H = ctx.hardware
    H.add_component(project.id, "ram", "K4B4G1646E-BYK0", quantity=2)
    H.add_component(project.id, "soc", "MSD6A648")
    H.analyze_project(project.id)
    s = H.board_summary(project.id)
    assert s["ram"]["total"] == 1024 ** 3 and "1 GB" in s["ram"]["text"] and "confirm with datasheet" in s["ram"]["text"]
    assert s["gpu"] == ["not identified (no evidence)"]
    assert s["mainboard"] == "TP.MS338.PB801" and s["pcb_revision"] == "1.1"
    H.analyze(H.add_component(project.id, "ram", "UNKNOWN99X"))
    s = H.board_summary(project.id)
    assert s["ram"]["total"] is None and "1 of 2" in s["ram"]["text"]
    assert "not identified" in s["flash"]["text"]


def test_component_crud_validation(ctx, project):
    H = ctx.hardware
    with pytest.raises(ValueError):
        H.add_component(project.id, "banana", "X")
    with pytest.raises(ValueError):
        H.add_component(project.id, "ram", "X", quantity=0)
    with pytest.raises(KeyError):
        H.add_component(9999, "ram", "X")
    cid = H.add_component(project.id, "ram", "K4B4G1646E")
    H.analyze(cid)
    H.update_component(cid, quantity=4)
    assert H.get(cid)["match_status"] == "not_analyzed"   # edits invalidate the analysis
    with pytest.raises(ValueError):
        H.update_component(cid, confidence=1.0)
    H.delete_component(cid)
    assert H.list(project.id) == [] and H.facts(cid) == []


def test_confirmed_marking_feeds_analyzer(ctx, project, sample_image):
    from fake_ocr import install_fake_ocr
    install_fake_ocr(ctx, [("K4B4G1646E-BYK0", 0.95)])
    ev = ctx.evidence.add_image(project.id, sample_image, "mainboard")
    ctx.identification.run_ocr(ev.id)
    m = ctx.identification.markings(project.id)[0]
    cid = ctx.identification.confirm_marking(m["id"])
    comp = ctx.hardware.get(cid)
    assert comp["component_type"] == "ram" and comp["board"] == "mainboard" and comp["evidence_id"] == ev.id
    a = ctx.hardware.analyze(cid)
    assert a.match_status == "decoded" and "4 Gbit" in a.specification


def test_reference_db_roundtrip(ctx, project, tmp_path):
    ctx.datasheets.import_pdf(ddr3_datasheet(tmp_path / "d.pdf"), source_url="https://vendor.example/ds.pdf")
    H = ctx.hardware
    cid = H.add_component(project.id, "ram", "K4B4G1646E-BYK0")
    with pytest.raises(ValueError):
        H.save_to_reference(cid)  # not analysed yet
    H.analyze(cid)
    kind, rid = H.save_to_reference(cid)
    assert kind == "memory"
    mem = ctx.db.query_one("SELECT * FROM memory_chips WHERE id=?", (rid,))
    assert mem["memory_type"] == "DDR3 SDRAM" and mem["datasheet_url"] == "https://vendor.example/ds.pdf"
    assert mem["capacity_bytes"] == 512 * 1024 ** 2   # datasheet states 4Gb -> stored
    assert H.facts(rid, "memory")
    # a second TV with the same part reuses reference facts with provenance chain
    p2 = ctx.projects.create(TVProject(name="second"))
    a = H.analyze(H.add_component(p2.id, "ram", "K4B4G1646E-BYK0"))
    assert any(f.source_reference.startswith(f"reference DB memory #{rid}") for f in a.facts)
    assert H.reference_entries()[0]["part_number"] == "K4B4G1646E-BYK0"


def test_reference_capacity_not_set_from_decoder_only(ctx, project):
    H = ctx.hardware
    cid = H.add_component(project.id, "flash", "W25Q64JVSIQ")
    H.analyze(cid)
    kind, rid = H.save_to_reference(cid)
    assert ctx.db.scalar("SELECT capacity_bytes FROM memory_chips WHERE id=?", (rid,)) is None


# ---- reports ------------------------------------------------------------------------------------
def test_hardware_reports_all_formats(ctx, project, tmp_path, sample_image):
    from openpyxl import load_workbook
    from pypdf import PdfReader
    ctx.datasheets.import_pdf(ddr3_datasheet(tmp_path / "d.pdf"))
    ev = ctx.evidence.add_image(project.id, sample_image, "chip")
    H = ctx.hardware
    H.add_component(project.id, "ram", "K4B4G1646E-BYK0", quantity=2, evidence_id=ev.id)
    H.add_component(project.id, "flash", "W25Q64)V")
    H.analyze_project(project.id)
    R = ctx.hardware_reports
    pdf = R.generate_pdf(project.id)
    text = " ".join(p.extract_text() for p in PdfReader(pdf).pages)
    assert "Hardware Report" in text and "K4B4G1646E-BYK0" in text and "1 GB total" in text
    assert "OCR misread" in text and "not identified (no evidence)" in text
    js = json.loads(R.export_json(project.id).read_text(encoding="utf-8"))
    assert js["board_summary"]["ram"]["total"] == 1024 ** 3
    assert {c["part_number"] for c in js["components"]} == {"K4B4G1646E-BYK0", "W25Q64)V"}
    with open(R.export_csv(project.id), encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    assert any(r["fact_attribute"] == "density_bits" and r["fact_value"] == "4 Gbit" for r in rows)
    assert all(r["fact_source_type"] or r["part_number"] == "W25Q64)V" for r in rows)
    wb = load_workbook(R.export_xlsx(project.id))
    assert wb.sheetnames == ["Components", "Specifications", "Board summary"]
    types = {r["format"] for r in ctx.db.query("SELECT format FROM technical_reports WHERE report_type='hardware'")}
    assert types == {"pdf", "json", "csv", "xlsx"}


def test_proven_capacity_rules():
    from app.modules.hardware_analyzer.service import proven_capacity_bytes

    def f(attr, val, st, ref="x"):
        return {"attribute": attr, "value": str(val), "source_type": st, "source_reference": ref}
    assert proven_capacity_bytes([f("density_bits", 4 * GBIT, "decoder")]) is None
    assert proven_capacity_bytes([f("density_bits", 4 * GBIT, "decoder", "d (corroborated by datasheet)")]) == 512 * MBIT
    # datasheet covering 2Gb and 4Gb variants is ambiguous
    assert proven_capacity_bytes([f("density_bits", 2 * GBIT, "datasheet"), f("density_bits", 4 * GBIT, "datasheet")]) is None
    assert proven_capacity_bytes([f("capacity_bytes", 8 * 1024 ** 3, "datasheet")]) == 8 * 1024 ** 3
    assert proven_capacity_bytes([f("density_bits", 4 * GBIT, "datasheet"),
                                  f("capacity_bytes", 1024, "user")]) == 1024
