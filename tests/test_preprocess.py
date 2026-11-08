import numpy as np
import pytest

from app.modules.visual_scanner import preprocess as pp
from synthetic_images import font, rear_label


def _text_img(dark_bg=False):
    img = np.full((200, 400, 3), 30 if dark_bg else 230, np.uint8)
    import cv2
    cv2.putText(img, "MT5889 ABC", (20, 110), cv2.FONT_HERSHEY_SIMPLEX, 1.5,
                (200, 200, 200) if dark_bg else (20, 20, 20), 3)
    return img


def test_crop_and_bounds():
    img = _text_img()
    assert pp.crop(img, 10, 20, 100, 50).shape[:2] == (50, 100)
    assert pp.crop(img, 350, 150, 500, 500).shape[:2] == (50, 50)  # clipped to image
    with pytest.raises(ValueError):
        pp.crop(img, 399, 199, 10, 10)


def test_rotate_shapes():
    img = _text_img()
    assert pp.rotate(img, 90).shape[:2] == (400, 200)
    assert pp.rotate(img, 180).shape[:2] == (200, 400)
    assert pp.rotate(img, 5).shape[:2] == (200, 400)


@pytest.mark.skipif(font(20) is None, reason="no TrueType font available")
@pytest.mark.parametrize("angle", [4, -4, 8])
def test_deskew_corrects_rotation(tmp_path, angle):
    p = rear_label(tmp_path / "l.png", ["MODEL: ABC123456", "SERIAL NO: 99887766", "MADE IN XYZ"], angle=angle)
    img = pp.load_image(p)
    assert abs(pp.estimate_skew(img) + angle) < 1.0
    assert abs(pp.estimate_skew(pp.deskew(img))) < 0.6


def test_auto_polarity_makes_dark_text_on_light():
    dark = pp.auto_polarity(_text_img(dark_bg=True))
    light = pp.auto_polarity(_text_img(dark_bg=False))
    assert dark.mean() > 127 and light.mean() > 127


@pytest.mark.parametrize("preset", list(pp.PRESETS))
def test_all_presets_run(preset):
    res = pp.run_pipeline(_text_img(), preset, crop_rect=(0, 0, 300, 200))
    assert res.image.size > 0
    assert res.steps[0]["op"] == "crop"
    assert len(res.steps) == len(pp.PRESETS[preset]) + 1


def test_unknown_preset_or_op():
    with pytest.raises(ValueError):
        pp.run_pipeline(_text_img(), "magic")
    with pytest.raises(ValueError):
        pp.run_pipeline(_text_img(), [("explode", {})])


def test_unicode_path_roundtrip(tmp_path):
    p = tmp_path / "gambar_ﾃｽﾄ_ç.png"
    pp.save_image(_text_img(), p)
    assert pp.load_image(p).shape == (200, 400, 3)


def test_quality_report_flags_blur_and_resolution():
    import cv2
    sharp = _text_img()
    blurred = cv2.GaussianBlur(sharp, (31, 31), 10)
    q_sharp, q_blur = pp.quality_report(sharp), pp.quality_report(blurred)
    assert q_sharp["sharpness"] > q_blur["sharpness"]
    assert any("blurred" in w for w in q_blur["warnings"])
    assert any("resolution" in w.lower() for w in q_blur["warnings"])


def test_load_rejects_non_image(tmp_path):
    p = tmp_path / "x.png"
    p.write_bytes(b"nope")
    with pytest.raises(ValueError):
        pp.load_image(p)
