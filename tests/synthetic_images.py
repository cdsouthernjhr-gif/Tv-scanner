"""Generate realistic synthetic test images (labels, chip markings, menus, PCB silkscreen).

No real product photos are bundled; these images reproduce the difficulties OCR
faces on real photos: rotation, noise, blur, low contrast, light-on-dark text.
All model/part numbers below are illustrative strings, not claims about real products.
"""
from __future__ import annotations

import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
]


def font(size: int):
    for f in _FONT_CANDIDATES:
        if Path(f).exists():
            return ImageFont.truetype(f, size)
    return None  # callers skip when no TrueType font exists


def _noise(im: Image.Image, amount: int = 12, seed: int = 1) -> Image.Image:
    rnd = random.Random(seed)
    px = im.load()
    w, h = im.size
    for _ in range(w * h // 8):
        x, y = rnd.randrange(w), rnd.randrange(h)
        v = px[x, y]
        d = rnd.randint(-amount, amount)
        px[x, y] = tuple(max(0, min(255, c + d)) for c in v) if isinstance(v, tuple) else max(0, min(255, v + d))
    return im


def rear_label(path: Path, lines: list[str], angle: float = 3.0) -> Path:
    f = font(34)
    im = Image.new("RGB", (1100, 90 + 58 * len(lines)), (236, 236, 230))
    d = ImageDraw.Draw(im)
    d.rectangle([10, 10, im.width - 10, im.height - 10], outline=(30, 30, 30), width=3)
    for i, ln in enumerate(lines):
        d.text((40, 40 + i * 58), ln, fill=(20, 20, 20), font=f)
    im = im.rotate(angle, expand=True, fillcolor=(90, 90, 95), resample=Image.BICUBIC)
    im = _noise(im).filter(ImageFilter.GaussianBlur(0.8))
    im.save(path, quality=88)
    return path


def chip_marking(path: Path, lines: list[str]) -> Path:
    """Light grey laser-etched text on a dark package, low contrast, small."""
    f = font(30)
    im = Image.new("RGB", (520, 90 + 48 * len(lines)), (38, 38, 42))
    d = ImageDraw.Draw(im)
    d.ellipse([20, 20, 40, 40], fill=(70, 70, 75))  # pin-1 dot
    for i, ln in enumerate(lines):
        d.text((60, 45 + i * 48), ln, fill=(150, 150, 150), font=f)
    im = _noise(im, 10, seed=2).filter(ImageFilter.GaussianBlur(0.6))
    im.save(path)
    return path


def system_menu(path: Path, rows: list[tuple[str, str]]) -> Path:
    """Photo of an on-screen 'System Information' menu: white text on dark blue."""
    f = font(32)
    im = Image.new("RGB", (1280, 120 + 60 * len(rows)), (18, 30, 60))
    d = ImageDraw.Draw(im)
    d.text((40, 30), "System Information", fill=(240, 240, 240), font=font(40))
    for i, (k, v) in enumerate(rows):
        d.text((60, 110 + i * 60), k, fill=(200, 210, 230), font=f)
        d.text((560, 110 + i * 60), v, fill=(255, 255, 255), font=f)
    im = _noise(im, 8, seed=3).filter(ImageFilter.GaussianBlur(0.7))
    im.save(path, quality=85)
    return path


def pcb_silkscreen(path: Path, lines: list[str]) -> Path:
    """White silkscreen on green solder mask."""
    f = font(34)
    im = Image.new("RGB", (900, 100 + 56 * len(lines)), (20, 95, 50))
    d = ImageDraw.Draw(im)
    for x in range(0, 900, 45):
        d.line([(x, 0), (x + 30, im.height)], fill=(30, 110, 60), width=3)  # traces
    for i, ln in enumerate(lines):
        d.text((50, 40 + i * 56), ln, fill=(235, 235, 225), font=f)
    im = _noise(im, 10, seed=4).filter(ImageFilter.GaussianBlur(0.6))
    im.save(path)
    return path
