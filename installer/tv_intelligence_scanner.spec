# PyInstaller spec — build with:  pyinstaller installer\tv_intelligence_scanner.spec --noconfirm
# Run from the repository root.
import os
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    datas=[
        (os.path.join(ROOT, "config", "default_config.json"), "config"),
        (os.path.join(ROOT, "app", "database", "migrations"), os.path.join("app", "database", "migrations")),
        (os.path.join(ROOT, "resources", "data"), os.path.join("resources", "data")),
        (os.path.join(ROOT, "app", "integrations", "ghidra", "scripts"), os.path.join("app", "integrations", "ghidra", "scripts")),
    ],
    hiddenimports=["pytesseract", "pypdf", "keyring.backends.Windows", "keyring.backends.fail", "reportlab.graphics.barcode.common", "reportlab.graphics.barcode.code128"],
    # matplotlib/binwalk may be present system-wide (e.g. from a binwalk package) but are not used by the app
    excludes=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore", "matplotlib", "binwalk"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="TVIntelligenceScanner",
          console=False, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="TVIntelligenceScanner", upx=False)
