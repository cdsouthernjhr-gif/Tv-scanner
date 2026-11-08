import pytest

from app.modules.identification.parsers import extract_from_text
from app.modules.visual_scanner import markings as mk
from app.modules.visual_scanner.ocr import OcrResult, OcrToken


def _fields(text, conf=1.0):
    return {(c.field, c.value): c for c in extract_from_text(text, conf)}


def test_label_keys():
    f = _fields("Model Code: UA55AU7000KXXM\nSerial No: 0B4K3NAR600123\nCHASSIS: XYZ-9\n"
                "Product Code: AB12CD\nMain Board: TP.MS338.PB801  PCB REV: 1.0\nPanel ID: LC550DGJ")
    for k in [("model_number", "UA55AU7000KXXM"), ("serial_number", "0B4K3NAR600123"),
              ("chassis", "XYZ-9"), ("product_code", "AB12CD"), ("mainboard", "TP.MS338.PB801"),
              ("pcb_revision", "1.0"), ("panel_model", "LC550DGJ")]:
        assert k in f, k
        assert f[k].method == "label_key" and f[k].confidence == 0.95


def test_generic_keys_have_low_weight():
    f = _fields("Version: AU01\nSoftware Version: T-ABC-1500.5\nREV 2.1")
    assert f[("firmware_version", "T-ABC-1500.5")].method == "label_key"
    assert f[("firmware_version", "AU01")].method == "generic_key"
    assert f[("firmware_version", "AU01")].confidence < 0.6
    assert f[("pcb_revision", "2.1")].method == "generic_key"


def test_confidence_scales_with_ocr_confidence():
    f = _fields("MODEL: ABC123", conf=0.5)
    assert f[("model_number", "ABC123")].confidence == pytest.approx(0.475)


def test_key_fragments_are_not_values():
    f = _fields("MODEL NA ME\nSOFTWARE VER SION\nModel: AB")
    assert not any(k[0] in ("model_number", "firmware_version") for k in f)


def test_split_code_fragment_dropped():
    f = _fields("Model: UA55\nModel: UA55AU7000KXXM")
    assert ("model_number", "UA55AU7000KXXM") in f
    assert ("model_number", "UA55") not in f


def test_brand_whole_word_only():
    assert ("manufacturer", "LG") in _fields("LG Electronics Inc.")
    assert not any(k[0] == "manufacturer" for k in _fields("MADE IN BULGARIA"))
    assert ("manufacturer", "Samsung") in _fields("SAMSUNG")


def test_size_only_from_explicit_text():
    assert ("screen_size_inches", "55") in _fields('LED TV 55" Class')
    assert ("screen_size_inches", "43") in _fields("Screen Size: 43")
    # digits inside a model number are NOT treated as a size
    assert not any(k[0] == "screen_size_inches" for k in _fields("Model: 55UQ7500PSF"))
    assert not any(k[0] == "screen_size_inches" for k in _fields('5" speaker'))


def test_platform_keywords():
    f = _fields("Platform Android TV")
    assert ("platform", "Android TV") in f
    assert f[("platform", "Android TV")].confidence < 0.7


# ---- markings ----------------------------------------------------------------------
@pytest.mark.parametrize("text,rule,norm,corrected", [
    ("MSD6A648", "mstar_soc", "MSD6A648", False),
    ("M5D6A648", "mstar_soc", "MSD6A648", True),
    ("MT5889", "mediatek_tv_soc", "MT5889", False),
    ("MT58B9", "mediatek_tv_soc", "MT5889", True),
    ("MT41K256M16", "micron_dram", "MT41K256M16", False),
    ("MT7668", "mediatek_wifi", "MT7668", False),
    ("BN41-02635A", "samsung_bn41", "BN41-02635A", False),
    ("8N41-02635A", "samsung_bn41", "BN41-02635A", True),
    ("TP.MS338.PB801", "oem_tp_board", "TP.MS338.PB801", False),
    ("17MB211", "vestel_17mb", "17MB211", False),
    ("W25Q64JV", "winbond_spi", "W25Q64JV", False),
    ("5905X", "amlogic_soc", "S905X", True),
    ("NT5CC256M16", "nanya_dram", "NT5CC256M16", False),
    ("NT72671", "novatek", "NT72671", False),
])
def test_marking_rules(text, rule, norm, corrected):
    m = mk.match(text)
    assert m is not None
    assert (m[0].id, m[1], m[2]) == (rule, norm, corrected)


@pytest.mark.parametrize("text", ["RANDOM12", "TAIWAN", "2219B", "HELLO"])
def test_marking_no_false_rule(text):
    assert mk.match(text) is None


def test_rules_file_is_consistent():
    rules = mk.load_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert all(0 < r.strength <= 1 for r in rules)


def _ocr(tokens):
    return OcrResult("fake", "", [OcrToken(t, c, (i * 100, line * 40, 90, 30), line)
                                  for i, (t, c, line) in enumerate(tokens)])


def test_detect_joins_split_tokens_and_filters_noise():
    r = _ocr([("BN41-", 0.9, 0), ("02635A", 0.9, 0), ("MSD6A648", 0.95, 1), ("2219B", 0.9, 2),
              ("XQ77ZZ12", 0.8, 3), ("12V", 0.9, 4)])
    dets = {d.normalized: d for d in mk.detect(r, include_unrecognised=True)}
    assert dets["BN41-02635A"].rule_id == "samsung_bn41"
    assert dets["BN41-02635A"].bbox[2] > 90  # union of two tokens
    assert dets["MSD6A648"].vendor.startswith("MStar")
    assert "2219B" not in dets and "12V" not in dets            # date code / voltage
    assert dets["XQ77ZZ12"].rule_id is None                      # kept for manual lookup
    assert dets["XQ77ZZ12"].confidence < 0.3


def test_detect_correction_penalised():
    clean = mk.detect(_ocr([("MT5889", 0.9, 0)]))[0]
    fixed = mk.detect(_ocr([("MT58B9", 0.9, 0)]))[0]
    assert fixed.normalized == "MT5889"
    assert fixed.confidence < clean.confidence
    assert "OCR correction" in fixed.note
