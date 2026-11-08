-- 0004: Phase 4 — Firmware Analyzer.

-- One row per analysis run (several analyzers write into firmware_analysis per run).
CREATE TABLE firmware_analysis_runs (
    id              INTEGER PRIMARY KEY,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    options_json    TEXT,
    original_sha256_before TEXT NOT NULL,
    original_sha256_after  TEXT,
    original_unchanged INTEGER,
    working_copy    TEXT,
    error           TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at     TEXT
);
ALTER TABLE firmware_analysis ADD COLUMN run_id INTEGER REFERENCES firmware_analysis_runs(id) ON DELETE CASCADE;

-- Embedded components found inside a firmware image (structure map).
CREATE TABLE firmware_components (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES firmware_analysis_runs(id) ON DELETE CASCADE,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    offset          INTEGER NOT NULL,
    size            INTEGER,                      -- NULL when the format does not state its size
    type            TEXT NOT NULL,                -- squashfs, uimage, gzip, elf, ext4, ...
    category        TEXT NOT NULL,                -- filesystem, kernel, bootloader, archive, compressed, executable, partition_table ...
    description     TEXT NOT NULL,
    details_json    TEXT,
    source          TEXT NOT NULL,                -- native | binwalk
    validated       INTEGER NOT NULL DEFAULT 0    -- header fields checked for consistency
);
CREATE INDEX idx_fwcomp_fw ON firmware_components(firmware_id, run_id);

-- Metadata facts with provenance (kernel version, architecture, firmware version, OS, ...).
CREATE TABLE firmware_metadata (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES firmware_analysis_runs(id) ON DELETE CASCADE,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    attribute       TEXT NOT NULL,
    value           TEXT NOT NULL,
    source          TEXT NOT NULL,                -- e.g. 'uImage header @0x0', 'string @0x1a2b', '/etc/os-release'
    confidence      REAL NOT NULL
);
CREATE INDEX idx_fwmeta_fw ON firmware_metadata(firmware_id, run_id);

-- Files produced by safe extraction (workspace only), with hashes for comparison.
CREATE TABLE firmware_extracted_files (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES firmware_analysis_runs(id) ON DELETE CASCADE,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    rel_path        TEXT NOT NULL,
    size            INTEGER NOT NULL,
    sha256          TEXT,
    kind            TEXT,                         -- file | symlink (not followed) | config | sensitive
    note            TEXT
);
CREATE INDEX idx_fwfiles_fw ON firmware_extracted_files(firmware_id, run_id);
