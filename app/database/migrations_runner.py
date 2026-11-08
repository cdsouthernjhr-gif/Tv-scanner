"""Versioned SQL migration runner.

Migrations are files named ``NNNN_description.sql`` in ``app/database/migrations``.
Each is applied once, inside a transaction, and recorded in ``schema_migrations``.
``PRAGMA user_version`` mirrors the latest applied version.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

from app.core.config import application_root

log = logging.getLogger(__name__)
_NAME = re.compile(r"^(\d{4})_[\w-]+\.sql$")


def migrations_dir() -> Path:
    return application_root() / "app" / "database" / "migrations"


def discover(directory: Path | None = None) -> list[tuple[int, Path]]:
    directory = directory or migrations_dir()
    found = []
    for p in sorted(directory.glob("*.sql")):
        m = _NAME.match(p.name)
        if m:
            found.append((int(m.group(1)), p))
    versions = [v for v, _ in found]
    if len(versions) != len(set(versions)):
        raise RuntimeError("Duplicate migration version numbers")
    return found


def apply_migrations(conn: sqlite3.Connection, directory: Path | None = None) -> int:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL,"
        " applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')))"
    )
    conn.commit()
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    current = max(applied, default=0)
    for version, path in discover(directory):
        if version in applied:
            continue
        log.info("Applying migration %s", path.name)
        sql = path.read_text(encoding="utf-8")
        # executescript() issues its own COMMIT, so wrap explicitly for atomicity.
        try:
            conn.executescript("BEGIN;\n" + sql + "\nINSERT INTO schema_migrations(version, name) "
                               f"VALUES ({version}, '{path.name}');\nCOMMIT;")
        except sqlite3.Error:
            conn.rollback()
            log.exception("Migration %s failed", path.name)
            raise
        current = version
    conn.execute(f"PRAGMA user_version = {int(current)}")
    return current
