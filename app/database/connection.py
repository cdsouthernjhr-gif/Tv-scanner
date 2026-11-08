"""SQLite connection management."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.database.migrations_runner import apply_migrations


class Database:
    """Thin wrapper around a single SQLite connection (UI thread usage).

    Foreign keys are enforced; WAL journaling keeps the file consistent if the
    application is closed unexpectedly.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.schema_version = apply_migrations(self.conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self.conn.execute("BEGIN")
                yield self.conn
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: tuple | dict = ()) -> Any:
        row = self.query_one(sql, params)
        return None if row is None else row[0]

    def execute(self, sql: str, params: tuple | dict = ()) -> int:
        """Execute a single write statement in its own transaction, returning lastrowid."""
        with self.transaction() as c:
            return c.execute(sql, params).lastrowid

    def close(self) -> None:
        with self._lock:
            self.conn.close()
