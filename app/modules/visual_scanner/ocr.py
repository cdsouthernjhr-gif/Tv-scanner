"""OCR engine abstraction.

* ``TesseractEngine`` — uses the Tesseract 4/5 binary through ``pytesseract``.
  Word-level confidences and bounding boxes come from ``image_to_data``.
* ``PaddleOcrEngine`` — optional; enabled only if the ``paddleocr`` package is
  installed. (Not bundled: it pulls in PaddlePaddle, ~1 GB.)

Engines never guess: if the binary/package is missing, ``available()`` is False
and callers report that OCR is unavailable.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field

import numpy as np

log = logging.getLogger(__name__)


@dataclass
class OcrToken:
    text: str
    conf: float                      # 0..1
    bbox: tuple[int, int, int, int]  # x, y, w, h in the *processed* image
    line: int                        # line index in reading order


@dataclass
class OcrResult:
    engine: str
    text: str
    tokens: list[OcrToken] = field(default_factory=list)
    duration_ms: int = 0
    language: str = "eng"

    @property
    def mean_confidence(self) -> float:
        toks = [t for t in self.tokens if t.text.strip()]
        if not toks:
            return 0.0
        # weight by token length: long part numbers matter more than stray marks
        total = sum(len(t.text) for t in toks)
        return round(sum(t.conf * len(t.text) for t in toks) / total, 3)

    def lines(self) -> list[tuple[str, float]]:
        """Reading-order lines with mean confidence per line."""
        out: dict[int, list[OcrToken]] = {}
        for t in self.tokens:
            out.setdefault(t.line, []).append(t)
        res = []
        for _, toks in sorted(out.items()):
            text = " ".join(t.text for t in toks).strip()
            if text:
                res.append((text, round(sum(t.conf for t in toks) / len(toks), 3)))
        return res

    def tokens_as_dicts(self) -> list[dict]:
        return [asdict(t) for t in self.tokens]


class OcrEngine(ABC):
    name = "base"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def recognize(self, image: np.ndarray, language: str = "eng", psm: int = 11) -> OcrResult: ...


WINDOWS_TESSERACT = (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                     r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe")


def default_tesseract() -> str | None:
    """Tesseract on PATH, else the standard Windows install folders (the UB-Mannheim/Chocolatey
    installers do not always add Tesseract to PATH)."""
    import os
    import shutil
    found = shutil.which("tesseract")
    if found:
        return found
    if os.name == "nt":
        for c in WINDOWS_TESSERACT:
            if os.path.isfile(c):
                return c
    return None


class TesseractEngine(OcrEngine):
    name = "tesseract"

    def __init__(self, binary: str | None = None):
        binary = binary or default_tesseract()
        self.binary = binary
        self._version: str | None = None
        try:
            import pytesseract  # noqa: F401
            self._pyt = pytesseract
            if binary:
                pytesseract.pytesseract.tesseract_cmd = binary
        except ImportError:
            self._pyt = None

    def available(self) -> bool:
        if self._pyt is None:
            return False
        try:
            self._version = str(self._pyt.get_tesseract_version())
            return True
        except Exception:
            return False

    def version(self) -> str:
        if self._version is None and not self.available():
            return "not installed"
        return f"tesseract {self._version}"

    def languages(self) -> list[str]:
        try:
            return sorted(self._pyt.get_languages(config=""))
        except Exception:
            return []

    def recognize(self, image: np.ndarray, language: str = "eng", psm: int = 11) -> OcrResult:
        """psm 11 = sparse text (labels, PCBs); psm 6 = uniform block (menus)."""
        if not self.available():
            raise RuntimeError("Tesseract OCR is not installed or not found")
        t0 = time.perf_counter()
        data = self._pyt.image_to_data(image, lang=language, config=f"--oem 1 --psm {psm}",
                                       output_type=self._pyt.Output.DICT)
        tokens: list[OcrToken] = []
        line_ids: dict[tuple, int] = {}
        for i, word in enumerate(data["text"]):
            word = (word or "").strip()
            conf = float(data["conf"][i])
            if not word or conf < 0:
                continue
            key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
            line = line_ids.setdefault(key, len(line_ids))
            tokens.append(OcrToken(word, round(conf / 100.0, 3),
                                   (int(data["left"][i]), int(data["top"][i]),
                                    int(data["width"][i]), int(data["height"][i])), line))
        res = OcrResult(self.name, "", tokens, int((time.perf_counter() - t0) * 1000), language)
        res.text = "\n".join(t for t, _ in res.lines())
        return res


class PaddleOcrEngine(OcrEngine):
    name = "paddleocr"

    def __init__(self):
        self._ocr = None
        try:
            import paddleocr  # noqa: F401
            self._mod = paddleocr
        except ImportError:
            self._mod = None

    def available(self) -> bool:
        return self._mod is not None

    def version(self) -> str:
        return f"paddleocr {getattr(self._mod, '__version__', '?')}" if self._mod else "not installed"

    def recognize(self, image: np.ndarray, language: str = "en", psm: int = 11) -> OcrResult:
        if not self.available():
            raise RuntimeError("PaddleOCR is not installed (pip install paddleocr paddlepaddle)")
        t0 = time.perf_counter()
        if self._ocr is None:
            self._ocr = self._mod.PaddleOCR(lang="en" if language == "eng" else language)
        raw = self._ocr.ocr(image)
        tokens: list[OcrToken] = []
        # PaddleOCR 2.x returns [[ [box, (text, conf)], ... ]]; boxes are 4 points.
        for line_no, item in enumerate((raw or [[]])[0] or []):
            box, (text, conf) = item[0], item[1]
            xs, ys = [p[0] for p in box], [p[1] for p in box]
            tokens.append(OcrToken(text, round(float(conf), 3),
                                   (int(min(xs)), int(min(ys)), int(max(xs) - min(xs)),
                                    int(max(ys) - min(ys))), line_no))
        res = OcrResult(self.name, "", tokens, int((time.perf_counter() - t0) * 1000), language)
        res.text = "\n".join(t for t, _ in res.lines())
        return res


def available_engines(tesseract_path: str | None = None) -> list[OcrEngine]:
    return [e for e in (TesseractEngine(tesseract_path), PaddleOcrEngine()) if e.available()]
