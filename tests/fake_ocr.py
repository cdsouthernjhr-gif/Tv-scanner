"""Deterministic OCR engine for service tests (no Tesseract needed)."""
from app.modules.visual_scanner.ocr import OcrEngine, OcrResult, OcrToken


class FakeEngine(OcrEngine):
    name = "fake"

    def __init__(self, lines):
        self.lines = lines
        self.calls = 0

    def available(self):
        return True

    def version(self):
        return "fake 1.0"

    def recognize(self, image, language="eng", psm=11):
        self.calls += 1
        toks = []
        for li, (text, conf) in enumerate(self.lines):
            for wi, w in enumerate(text.split()):
                toks.append(OcrToken(w, conf, (wi * 80, li * 40, 70, 30), li))
        r = OcrResult("fake", "", toks, 1)
        r.text = "\n".join(t for t, _ in r.lines())
        return r


def install_fake_ocr(ctx, lines):
    eng = FakeEngine(lines)
    ctx.identification._engines = {"fake": eng}
    return eng
