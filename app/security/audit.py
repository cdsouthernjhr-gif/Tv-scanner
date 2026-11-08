"""Append-only audit log stored in SQLite (and mirrored to the app log)."""
from __future__ import annotations

import getpass
import json
import logging
from typing import Any

from app.database.connection import Database

log = logging.getLogger("audit")


def current_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - platform specific
        return "unknown"


class AuditLogger:
    def __init__(self, db: Database):
        self.db = db

    def record(self, action: str, entity_type: str | None = None,
               entity_id: int | None = None, **details: Any) -> int:
        payload = json.dumps(details, default=str, sort_keys=True) if details else None
        log.info("%s %s#%s %s", action, entity_type, entity_id, payload or "")
        return self.db.execute(
            "INSERT INTO audit_log(actor, action, entity_type, entity_id, details_json)"
            " VALUES (?,?,?,?,?)",
            (current_actor(), action, entity_type, entity_id, payload),
        )

    def entries(self, entity_type: str | None = None, entity_id: int | None = None,
                limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM audit_log"
        params: list = []
        clauses = []
        if entity_type:
            clauses.append("entity_type = ?")
            params.append(entity_type)
        if entity_id is not None:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.query(sql, tuple(params))]
