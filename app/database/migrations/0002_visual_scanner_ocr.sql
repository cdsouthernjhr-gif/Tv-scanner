-- 0002: Phase 2 — TV identification & visual scanner (OCR, markings, candidates).

-- Processed images (crop/enhance) are stored as new evidence rows that point to
-- the original evidence; the original image is never overwritten.
ALTER TABLE scan_evidence ADD COLUMN parent_evidence_id INTEGER REFERENCES scan_evidence(id) ON DELETE SET NULL;
ALTER TABLE scan_evidence ADD COLUMN processing_json TEXT;

-- Raw OCR output for one evidence image (one row per OCR run).
CREATE TABLE ocr_results (
    id              INTEGER PRIMARY KEY,
    evidence_id     INTEGER NOT NULL REFERENCES scan_evidence(id) ON DELETE CASCADE,
    engine          TEXT NOT NULL,              -- tesseract 5.x / paddleocr ...
    preset          TEXT NOT NULL,              -- preprocessing preset used
    language        TEXT,
    text            TEXT NOT NULL,
    mean_confidence REAL NOT NULL,              -- 0..1
    tokens_json     TEXT NOT NULL,              -- [{text, conf, bbox:[x,y,w,h], line}]
    duration_ms     INTEGER,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX idx_ocr_evidence ON ocr_results(evidence_id);

-- Values proposed for a project field, each tied to the evidence that produced it.
-- Nothing is written into tv_projects until the operator accepts a candidate.
CREATE TABLE identification_candidates (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    field           TEXT NOT NULL,
    value           TEXT NOT NULL,
    confidence      REAL NOT NULL,              -- 0..1
    method          TEXT NOT NULL,              -- label_key, keyword, brand_dictionary, pattern ...
    evidence_id     INTEGER REFERENCES scan_evidence(id) ON DELETE SET NULL,
    ocr_result_id   INTEGER REFERENCES ocr_results(id) ON DELETE SET NULL,
    source_line     TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','accepted','rejected')),
    decided_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (project_id, field, value, evidence_id)
);
CREATE INDEX idx_candidates_project ON identification_candidates(project_id, status);

-- Chip markings and PCB/board numbers recognised in images.
CREATE TABLE marking_detections (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    evidence_id     INTEGER NOT NULL REFERENCES scan_evidence(id) ON DELETE CASCADE,
    ocr_result_id   INTEGER REFERENCES ocr_results(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('chip','pcb')),
    raw_text        TEXT NOT NULL,
    normalized      TEXT NOT NULL,
    rule_id         TEXT,
    candidate_vendor TEXT,
    candidate_type  TEXT,
    note            TEXT,
    confidence      REAL NOT NULL,
    bbox_json       TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','confirmed','rejected')),
    hardware_component_id INTEGER REFERENCES hardware_components(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (evidence_id, kind, normalized)
);
CREATE INDEX idx_markings_project ON marking_detections(project_id);

-- Panel identification is needed for later compatibility checks.
ALTER TABLE tv_projects ADD COLUMN panel_model TEXT;
