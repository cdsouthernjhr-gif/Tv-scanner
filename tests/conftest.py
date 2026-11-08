import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.context import AppContext  # noqa: E402


@pytest.fixture
def ctx(tmp_path):
    from keyring.backends import fail
    from app.security.secrets import SecretStore
    c = AppContext.create(tmp_path / "data")
    # never touch the developer's real credential store (e.g. Windows Credential Manager) from tests
    c.secrets = SecretStore(backend=fail.Keyring())
    c.finder.secrets = c.secrets
    c.finder._providers = None
    yield c
    c.close()


@pytest.fixture
def sample_image(tmp_path):
    from PIL import Image, ImageDraw
    p = tmp_path / "label.png"
    im = Image.new("RGB", (400, 200), "white")
    d = ImageDraw.Draw(im)
    d.text((10, 80), "MODEL: TEST-55X SN: 123456", fill="black")
    im.save(p)
    return p


@pytest.fixture
def firmware_file(tmp_path):
    import io
    import zipfile
    p = tmp_path / "upgrade_test.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("version.txt", "V1.2.3")
    p.write_bytes(buf.getvalue())
    return p
