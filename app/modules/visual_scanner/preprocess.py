"""Image preprocessing for OCR (OpenCV).

All operations are pure functions on numpy arrays; nothing touches the stored
evidence file. ``run_pipeline`` records every step so the processing applied to
a derived image is reproducible and is stored with it (``processing_json``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import cv2
import numpy as np


# ---- I/O (unicode-safe on Windows: cv2.imread fails on non-ASCII paths) ------
def load_image(path: str | Path) -> np.ndarray:
    data = np.fromfile(str(path), dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Cannot decode image: {path}")
    return img


def save_image(img: np.ndarray, path: str | Path) -> None:
    ext = Path(path).suffix or ".png"
    ok, buf = cv2.imencode(ext, img)
    if not ok:
        raise IOError(f"Cannot encode image as {ext}")
    buf.tofile(str(path))


# ---- primitive operations ---------------------------------------------------------
def to_gray(img: np.ndarray) -> np.ndarray:
    return img if img.ndim == 2 else cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)


def crop(img: np.ndarray, x: int, y: int, w: int, h: int) -> np.ndarray:
    H, W = img.shape[:2]
    x0, y0 = max(0, int(x)), max(0, int(y))
    x1, y1 = min(W, int(x + w)), min(H, int(y + h))
    if x1 - x0 < 4 or y1 - y0 < 4:
        raise ValueError("Crop region is empty or too small")
    return img[y0:y1, x0:x1].copy()


def rotate(img: np.ndarray, degrees: float) -> np.ndarray:
    """Rotate clockwise by ``degrees`` (as seen on screen)."""
    d = degrees % 360
    if d == 90:
        return cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
    if d == 180:
        return cv2.rotate(img, cv2.ROTATE_180)
    if d == 270:
        return cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)
    h, w = img.shape[:2]
    m = cv2.getRotationMatrix2D((w / 2, h / 2), -degrees, 1.0)
    return cv2.warpAffine(img, m, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)


def estimate_skew(img: np.ndarray, max_angle: float = 20.0) -> float:
    """Estimate text-line angle in degrees via Hough lines (image coords, y down:
    positive = lines slope down to the right, i.e. text is rotated clockwise)."""
    gray = to_gray(img)
    edges = cv2.Canny(gray, 50, 150, apertureSize=3)
    lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=80,
                            minLineLength=max(30, gray.shape[1] // 8), maxLineGap=10)
    if lines is None:
        return 0.0
    angles = []
    for x1, y1, x2, y2 in np.asarray(lines).reshape(-1, 4):  # shape differs across OpenCV versions
        if x2 == x1:
            continue
        a = np.degrees(np.arctan2(y2 - y1, x2 - x1))
        if abs(a) <= max_angle:
            angles.append(a)
    return float(np.median(angles)) if angles else 0.0


def deskew(img: np.ndarray) -> np.ndarray:
    angle = estimate_skew(img)
    # rotate() turns clockwise for positive degrees, so undo the measured angle
    return img if abs(angle) < 0.3 else rotate(img, -angle)


def upscale(img: np.ndarray, factor: float = 2.0) -> np.ndarray:
    return cv2.resize(img, None, fx=factor, fy=factor, interpolation=cv2.INTER_CUBIC)


def ensure_min_height(img: np.ndarray, min_h: int = 600) -> np.ndarray:
    h = img.shape[0]
    return upscale(img, min_h / h) if h < min_h else img


def clahe(img: np.ndarray, clip: float = 2.5, grid: int = 8) -> np.ndarray:
    c = cv2.createCLAHE(clipLimit=clip, tileGridSize=(grid, grid))
    if img.ndim == 2:
        return c.apply(img)
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    lab[:, :, 0] = c.apply(lab[:, :, 0])
    return cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)


def denoise(img: np.ndarray, strength: int = 7) -> np.ndarray:
    if img.ndim == 2:
        return cv2.fastNlMeansDenoising(img, None, strength, 7, 21)
    return cv2.fastNlMeansDenoisingColored(img, None, strength, strength, 7, 21)


def sharpen(img: np.ndarray, amount: float = 1.0) -> np.ndarray:
    blur = cv2.GaussianBlur(img, (0, 0), 2.0)
    return cv2.addWeighted(img, 1 + amount, blur, -amount, 0)


def adaptive_threshold(img: np.ndarray, block: int = 31, c: int = 10) -> np.ndarray:
    return cv2.adaptiveThreshold(to_gray(img), 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                 cv2.THRESH_BINARY, block | 1, c)


def otsu(img: np.ndarray) -> np.ndarray:
    _, out = cv2.threshold(to_gray(img), 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return out


def invert(img: np.ndarray) -> np.ndarray:
    return cv2.bitwise_not(img)


def auto_polarity(img: np.ndarray) -> np.ndarray:
    """Make text dark-on-light (Tesseract works best that way).

    Chip markings are usually light text on a dark package; menus may be either.
    Decided on the binarised image: if most pixels are dark, invert.
    """
    g = to_gray(img)
    return invert(g) if np.mean(otsu(g)) < 127 else g


def sharpness_score(img: np.ndarray) -> float:
    """Variance of Laplacian — low values mean the photo is blurred."""
    return float(cv2.Laplacian(to_gray(img), cv2.CV_64F).var())


def quality_report(img: np.ndarray) -> dict:
    g = to_gray(img)
    sharp = sharpness_score(g)
    mean = float(np.mean(g))
    warnings = []
    if sharp < 60:
        warnings.append("Image appears blurred — retake with steady focus if OCR fails.")
    contrast = float(np.std(g))
    if mean < 50 and contrast < 30:
        warnings.append("Image is dark with low contrast — add light or use a flash at an angle.")
    elif mean > 225:
        warnings.append("Image is overexposed / glare.")
    if min(g.shape) < 300:
        warnings.append("Low resolution — move closer or use a higher resolution.")
    return {"width": int(g.shape[1]), "height": int(g.shape[0]), "sharpness": round(sharp, 1),
            "brightness": round(mean, 1), "contrast": round(contrast, 1),
            "warnings": warnings}


# ---- pipelines ------------------------------------------------------------------
OPS: dict[str, Callable[..., np.ndarray]] = {
    "gray": to_gray, "deskew": deskew, "rotate": rotate, "upscale": upscale,
    "min_height": ensure_min_height, "clahe": clahe, "denoise": denoise, "sharpen": sharpen,
    "adaptive_threshold": adaptive_threshold, "otsu": otsu, "invert": invert,
    "auto_polarity": auto_polarity,
}

PRESETS: dict[str, list[tuple[str, dict]]] = {
    "none": [],
    # Printed product / rear labels: black text on white/silver sticker.
    "label": [("min_height", {"min_h": 900}), ("gray", {}), ("deskew", {}),
              ("clahe", {"clip": 2.0}), ("sharpen", {"amount": 0.6})],
    # Laser-etched or printed chip markings: low contrast, often light-on-dark.
    "chip_marking": [("upscale", {"factor": 3.0}), ("gray", {}), ("denoise", {"strength": 9}),
                     ("clahe", {"clip": 4.0, "grid": 4}), ("sharpen", {"amount": 1.0}),
                     ("auto_polarity", {})],
    # Silkscreen text on PCBs (white on green/blue).
    "pcb_silkscreen": [("min_height", {"min_h": 900}), ("gray", {}), ("clahe", {"clip": 3.0}),
                       ("sharpen", {"amount": 0.8}), ("auto_polarity", {})],
    # Photos of on-screen System Information menus (moire, glare).
    "screen_menu": [("min_height", {"min_h": 1000}), ("gray", {}), ("denoise", {"strength": 5}),
                    ("clahe", {"clip": 2.0}), ("auto_polarity", {})],
    "binarize": [("min_height", {"min_h": 900}), ("gray", {}), ("adaptive_threshold", {})],
}

PRESET_FOR_EVIDENCE = {
    "tv_back_label": "label", "product_label": "label", "panel_label": "label",
    "system_info_menu": "screen_menu", "chip": "chip_marking", "mainboard": "pcb_silkscreen",
    "power_supply": "pcb_silkscreen", "tcon": "pcb_silkscreen", "other": "label",
}


@dataclass
class PipelineResult:
    image: np.ndarray
    steps: list[dict] = field(default_factory=list)


def run_pipeline(img: np.ndarray, steps: list[tuple[str, dict]] | str,
                 crop_rect: tuple[int, int, int, int] | None = None) -> PipelineResult:
    if isinstance(steps, str):
        if steps not in PRESETS:
            raise ValueError(f"Unknown preset {steps!r}")
        steps = PRESETS[steps]
    applied: list[dict] = []
    out = img
    if crop_rect:
        out = crop(out, *crop_rect)
        applied.append({"op": "crop", "args": list(crop_rect)})
    for name, kwargs in steps:
        if name not in OPS:
            raise ValueError(f"Unknown operation {name!r}")
        out = OPS[name](out, **kwargs)
        applied.append({"op": name, "args": kwargs})
    return PipelineResult(out, applied)
