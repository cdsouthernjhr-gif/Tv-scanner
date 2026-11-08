"""Evidence image storage (labels, menus, boards, chips ...).

Images are copied into ``storage/projects/<id>/evidence/<sha256>.<ext>``;
the user's source file is only read. Copies are made read-only.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.core.config import AppConfig
from app.database.connection import Database
from app.security.audit import AuditLogger
from app.security.file_protection import make_read_only
from app.security.hashing import sha256_file

EVIDENCE_TYPES = {
    "tv_back_label": "TV rear label",
    "product_label": "Product label",
    "system_info_menu": "System information menu",
    "mainboard": "Mainboard",
    "chip": "Electronic chip",
    "power_supply": "Power supply board",
    "tcon": "T-Con board",
    "panel_label": "Panel label",
    "other": "Other component",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
MAX_IMAGE_BYTES = 200 * 1024 * 1024


@dataclass
class Evidence:
    id: int
    project_id: int
    evidence_type: str
    original_filename: str
    stored_path: str
    sha256: str
    file_size: int
    width: int | None
    height: int | None
    description: str | None
    ocr_text: str | None
    created_at: str
    parent_evidence_id: int | None = None
    processing_json: str | None = None


class EvidenceService:
    def __init__(self, config: AppConfig, db: Database, audit: AuditLogger):
        self.config = config
        self.db = db
        self.audit = audit

    def project_evidence_dir(self, project_id: int) -> Path:
        return self.config.projects_dir / str(int(project_id)) / "evidence"

    def add_image(self, project_id: int, source: str | Path, evidence_type: str,
                  description: str | None = None) -> Evidence:
        source = Path(source)
        if evidence_type not in EVIDENCE_TYPES:
            raise ValueError(f"Unknown evidence type {evidence_type!r}")
        if not source.is_file():
            raise FileNotFoundError(source)
        if source.suffix.lower() not in IMAGE_EXTENSIONS:
            raise ValueError(f"Unsupported image type {source.suffix}")
        size = source.stat().st_size
        if size > MAX_IMAGE_BYTES:
            raise ValueError("Image exceeds 200 MB limit")
        if self.db.query_one("SELECT id FROM tv_projects WHERE id=?", (project_id,)) is None:
            raise KeyError(f"Project {project_id} not found")
        try:
            with Image.open(source) as im:
                im.verify()
            with Image.open(source) as im:
                width, height = im.size
        except (UnidentifiedImageError, OSError) as exc:
            raise ValueError(f"File is not a valid image: {exc}") from exc

        digest = sha256_file(source)
        existing = self.db.query_one(
            "SELECT * FROM scan_evidence WHERE project_id=? AND sha256=?", (project_id, digest))
        if existing:
            return Evidence(**{k: existing[k] for k in Evidence.__dataclass_fields__})

        dest_dir = self.project_evidence_dir(project_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{digest}{source.suffix.lower()}"
        if not dest.exists():
            shutil.copy2(source, dest)
            if sha256_file(dest) != digest:
                dest.unlink(missing_ok=True)
                raise IOError("Copy verification failed (hash mismatch)")
            make_read_only(dest)
        eid = self.db.execute(
            "INSERT INTO scan_evidence(project_id, evidence_type, original_filename, stored_path,"
            " sha256, file_size, width, height, description) VALUES (?,?,?,?,?,?,?,?,?)",
            (project_id, evidence_type, source.name, str(dest), digest, size, width, height,
             description))
        self.audit.record("evidence.add", "scan_evidence", eid, project_id=project_id,
                          sha256=digest, type=evidence_type)
        return self.get(eid)

    def add_derived(self, parent_id: int, png_bytes: bytes, processing: list[dict],
                    width: int, height: int, description: str | None = None) -> Evidence:
        """Store a processed (cropped/enhanced) copy as new evidence linked to its parent.

        The parent image is never modified. Identical results are deduplicated.
        """
        import hashlib
        import json
        parent = self.get(parent_id)
        digest = hashlib.sha256(png_bytes).hexdigest()
        existing = self.db.query_one("SELECT id FROM scan_evidence WHERE project_id=? AND sha256=?",
                                     (parent.project_id, digest))
        if existing:
            return self.get(existing[0])
        dest_dir = self.project_evidence_dir(parent.project_id) / "processed"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{digest}.png"
        if not dest.exists():
            dest.write_bytes(png_bytes)
            make_read_only(dest)
        eid = self.db.execute(
            "INSERT INTO scan_evidence(project_id, evidence_type, original_filename, stored_path, sha256,"
            " file_size, width, height, description, parent_evidence_id, processing_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (parent.project_id, parent.evidence_type, f"processed_from_{parent.id}.png", str(dest),
             digest, len(png_bytes), width, height,
             description or f"Processed copy of evidence #{parent.id}", parent.id,
             json.dumps(processing)))
        self.audit.record("evidence.derive", "scan_evidence", eid, parent=parent.id, sha256=digest)
        return self.get(eid)

    def get(self, evidence_id: int) -> Evidence:
        row = self.db.query_one("SELECT * FROM scan_evidence WHERE id=?", (evidence_id,))
        if row is None:
            raise KeyError(evidence_id)
        return Evidence(**{k: row[k] for k in Evidence.__dataclass_fields__})

    def list_for_project(self, project_id: int) -> list[Evidence]:
        rows = self.db.query("SELECT * FROM scan_evidence WHERE project_id=? ORDER BY id", (project_id,))
        return [Evidence(**{k: r[k] for k in Evidence.__dataclass_fields__}) for r in rows]
