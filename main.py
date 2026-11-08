"""TV Intelligence Scanner — application entry point.

Usage:
    python main.py                 # start the desktop application
    python main.py --data-dir DIR  # use a custom (e.g. portable) data directory
    python main.py --self-check    # initialise storage/database and exit (no GUI)
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
        ctx.close()
        return 0

    from PySide6.QtWidgets import QApplication
    from app.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("TV Intelligence Scanner")
    window = MainWindow(ctx)
    window.show()
    try:
        return app.exec()
    finally:
        ctx.close()


if __name__ == "__main__":
    sys.exit(main())
