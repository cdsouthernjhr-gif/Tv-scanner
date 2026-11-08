"""TV Intelligence Scanner — application entry point.

Usage:
    python main.py                 # start the desktop application
    python main.py --data-dir DIR  # use a custom (e.g. portable) data directory
    python main.py --self-check    # initialise storage/database and exit (no GUI)
    python main.py --smoke-test    # open the main window, visit every page, exit 0 (used by CI on Windows)
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="TV Intelligence Scanner")
    ap.add_argument("--data-dir", type=Path, help="data directory (default: %%LOCALAPPDATA%%)")
    ap.add_argument("--self-check", action="store_true", help="initialise storage and exit")
    ap.add_argument("--smoke-test", action="store_true",
                    help="open the main window, visit every page and exit (exit code 0 = OK)")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    from app.core.context import AppContext
    from app.core.logging_setup import setup_logging

    ctx = AppContext.create(args.data_dir)
    setup_logging(ctx.config.logs_dir)
    log = logging.getLogger("main")
    log.info("Data directory: %s (schema v%s)", ctx.config.data_dir, ctx.db.schema_version)

    if args.self_check:
        from app.services.external_tools import detect_tools
        print(f"Data directory : {ctx.config.data_dir}")
        print(f"Database       : {ctx.config.database_path} (schema v{ctx.db.schema_version})")
        print(f"Firmware lib   : {ctx.config.firmware_library_dir}")
        for t in detect_tools(ctx.config):
            print(f"  {t.label:20} {'OK  ' + t.path if t.available else 'not found'}")
        engines = ctx.identification.available_engines()
        print(f"OCR engines    : {', '.join(ctx.identification.engine(e).version() for e in engines) or 'none'}")
        from app.modules.identification.parsers import _brand_data
        from app.modules.visual_scanner.markings import load_rules
        from app.modules.hardware_analyzer.decoders import load_decoders
        print(f"Rule data      : {len(load_rules())} marking rules, {len(_brand_data()['brands'])} brands, "
              f"{len(load_decoders())} part-number decoders")
        fw_tools = ctx.firmware.tools()
        print("Firmware tools : " + ", ".join(f"{k}={'yes' if fw_tools.get(k) else 'no'}" for k in
                                              ("binwalk_cmd", "seven_zip", "unsquashfs", "jefferson", "ubireader", "ghidra")))
        ctx.close()
        return 0

    from PySide6.QtWidgets import QApplication
    from app.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("TV Intelligence Scanner")
    window = MainWindow(ctx)
    window.show()
    if args.smoke_test:
        return _smoke(app, window, ctx)
    try:
        return app.exec()
    finally:
        ctx.close()


def _smoke(app, window, ctx) -> int:
    """Visit every sidebar page with the real window; report and exit."""
    from app.ui.main_window import SIDEBAR
    errors = []
    try:
        for name in SIDEBAR:
            try:
                window.navigate(name)
                app.processEvents()
                if window.stack.currentWidget() is not window.pages[name]:
                    errors.append(f"{name}: page not shown")
            except Exception as exc:          # pragma: no cover - reported to CI
                errors.append(f"{name}: {exc!r}")
        print(f"Qt platform    : {app.platformName()}")
        print(f"Pages visited  : {len(SIDEBAR)}; window {window.width()}x{window.height()}")
        for e in errors:
            print("ERROR", e)
        print("SMOKE TEST " + ("FAILED" if errors else "OK"))
        return 1 if errors else 0
    finally:
        window.close()
        ctx.close()


if __name__ == "__main__":
    sys.exit(main())
