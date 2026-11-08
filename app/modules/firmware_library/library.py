"""Firmware Library: immutable, deduplicated, provenance-tracked storage.

Layout::

    TV_Firmware_Library/<Manufacturer>/<Model>/{Original,Official,Community,Analyzed,Reports}/

* The user's source file is only *read*.
* The library copy is verified by SHA-256 after copying and marked read-only.
* Duplicate content (same SHA-256) is never stored twice.
"""
from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, fields
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.firmware_analyzer.signatures import detect_format
from app.security.audit import AuditLogger
from app.security.file_protection import ensure_within, make_read_only, safe_component
from app.security.hashing import sha256_file

log = logging.getLogger(__name__)

CATEGORIES = ("Original", "Official", "Community")
SUBFOLDERS = ("Original", "Official", "Community", "Analyzed", "Reports")


@dataclass
class FirmwareRecord:
    id: int
    project_id: int | None
    original_filename: str
    stored_path: str
    sha256: str
    file_size: int
    detected_format: str | None
    manufacturer: str | None
    model_number: str | None
    mainboard: str | None
    version: str | None
    category: str
    download_url: str | None
    imported_at: str
    verification_status: str
    last_integrity_check: str | None
    notes: str | None

    @classmethod
    def from_row(cls, row) -> "FirmwareRecord":
        return cls(**{f.name: row[f.name] for f in fields(cls)})


class DuplicateFirmware(Exception):
    def __init__(self, record: FirmwareRecord):
        super().__init__(f"Firmware already in library (id={record.id}, sha256={record.sha256})")
        self.record = record


class FirmwareLibrary:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger):
        self.config = config
        self.db = db
        self.audit = audit

    @property
    def root(self) -> Path:
        return self.config.firmware_library_dir

    def model_dir(self, manufacturer: str | None, model: str | None) -> Path:
        d = self.root / safe_component(manufacturer) / safe_component(model)
        for sub in SUBFOLDERS:
            (d / sub).mkdir(parents=True, exist_ok=True)
        return d

    def import_file(self, source: str | Path, *, category: str = "Original",
                    manufacturer: str | None = None, model_number: str | None = None,
                    mainboard: str | None = None, version: str | None = None,
                    project_id: int | None = None, download_url: str | None = None,
                    source_type: str = "local_import", notes: str | None = None) -> FirmwareRecord:
        source = Path(source)
        if category not in CATEGORIES:
            raise ValueError(f"Category must be one of {CATEGORIES}")
        if not source.is_file():
            raise FileNotFoundError(source)

        digest = sha256_file(source)
        existing = self.db.query_one("SELECT * FROM firmware_files WHERE sha256=?", (digest,))
        if existing:
            raise DuplicateFirmware(FirmwareRecord.from_row(existing))

        fmt = detect_format(source)
        target_dir = self.model_dir(manufacturer, model_number) / category
        name = safe_component(source.name, fallback="firmware.bin")
        dest = target_dir / name
        if dest.exists():  # same name, different content -> disambiguate by hash prefix
            dest = target_dir / f"{dest.stem}__{digest[:12]}{dest.suffix}"
        ensure_within(self.root, dest)

        shutil.copy2(source, dest)
        if sha256_file(dest) != digest:
            dest.unlink(missing_ok=True)
            raise IOError("Library copy verification failed (hash mismatch)")
        make_read_only(dest)

        with self.db.transaction() as c:
            src_id = c.execute(
                "INSERT INTO firmware_sources(source_type, name, url, reliability) VALUES (?,?,?,?)",
                (source_type, str(source), download_url,
                 "user_supplied" if source_type == "local_import" else "unknown")).lastrowid
            fid = c.execute(
                "INSERT INTO firmware_files(project_id, original_filename, stored_path, sha256,"
                " file_size, detected_format, manufacturer, model_number, mainboard, version,"
                " category, source_id, download_url, verification_status, last_integrity_check, notes)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'hash_ok', strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?)",
                (project_id, source.name, str(dest), digest, dest.stat().st_size, fmt.format,
                 manufacturer, model_number, mainboard, version, category, src_id, download_url,
                 notes)).lastrowid
            if version:
                c.execute("INSERT INTO firmware_versions(firmware_id, version) VALUES (?,?)",
                          (fid, version))
        self.audit.record("firmware.import", "firmware_file", fid, sha256=digest,
                          source=str(source), stored=str(dest), category=category)
        return self.get(fid)

    def verify_integrity(self, firmware_id: int) -> FirmwareRecord:
        rec = self.get(firmware_id)
        path = Path(rec.stored_path)
        status = "hash_ok" if path.is_file() and sha256_file(path) == rec.sha256 else "hash_mismatch"
        # A previously 'verified' record keeps that status only if the hash still matches.
        if status == "hash_ok" and rec.verification_status == "verified":
            status = "verified"
        self.db.execute("UPDATE firmware_files SET verification_status=?,"
                        " last_integrity_check=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                        (status, firmware_id))
        self.audit.record("firmware.integrity_check", "firmware_file", firmware_id, result=status)
        if status == "hash_mismatch":
            log.warning("Integrity failure for firmware %s at %s", firmware_id, path)
        return self.get(firmware_id)

    def get(self, firmware_id: int) -> FirmwareRecord:
        row = self.db.query_one("SELECT * FROM firmware_files WHERE id=?", (firmware_id,))
        if row is None:
            raise KeyError(firmware_id)
        return FirmwareRecord.from_row(row)

    def list(self, project_id: int | None = None, mainboard: str | None = None) -> list[FirmwareRecord]:
        sql, params = "SELECT * FROM firmware_files WHERE 1=1", []
        if project_id is not None:
            sql += " AND project_id=?"
            params.append(project_id)
        if mainboard:
            sql += " AND mainboard LIKE ?"
            params.append(f"%{mainboard}%")
        sql += " ORDER BY id DESC"
        return [FirmwareRecord.from_row(r) for r in self.db.query(sql, tuple(params))]

    def make_working_copy(self, firmware_id: int) -> Path:
        """Copy into the isolated workspace for analysis; originals are never touched."""
        rec = self.get(firmware_id)
        ws = self.config.workspace_dir / f"fw_{firmware_id}"
        ws.mkdir(parents=True, exist_ok=True)
        dest = ws / Path(rec.stored_path).name
        if not dest.exists():
            shutil.copyfile(rec.stored_path, dest)  # copyfile: do not carry read-only bit
        return dest
