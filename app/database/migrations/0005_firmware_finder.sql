-- 0005: Phase 5 — Universal Firmware Finder.

-- One row per search the operator runs (search history).
CREATE TABLE search_sessions (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE SET NULL,
    criteria_json   TEXT NOT NULL,
    providers       TEXT NOT NULL,
    queries_json    TEXT,
    status          TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    result_count    INTEGER NOT NULL DEFAULT 0,
    errors_json     TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at     TEXT
);

ALTER TABLE firmware_search_results ADD COLUMN session_id INTEGER REFERENCES search_sessions(id) ON DELETE CASCADE;
ALTER TABLE firmware_search_results ADD COLUMN source_type TEXT;            -- official | github | gitlab | sourceforge | archive | community | documentation | open_source
ALTER TABLE firmware_search_results ADD COLUMN source_site TEXT;            -- host name of the result
ALTER TABLE firmware_search_results ADD COLUMN description TEXT;
ALTER TABLE firmware_search_results ADD COLUMN file_name TEXT;
ALTER TABLE firmware_search_results ADD COLUMN file_format TEXT;
ALTER TABLE firmware_search_results ADD COLUMN download_url TEXT;           -- only a URL returned by the source itself
ALTER TABLE firmware_search_results ADD COLUMN manufacturer TEXT;
ALTER TABLE firmware_search_results ADD COLUMN supported_models TEXT;
ALTER TABLE firmware_search_results ADD COLUMN supported_mainboards TEXT;
ALTER TABLE firmware_search_results ADD COLUMN sha256_source TEXT;          -- where the published hash came from
ALTER TABLE firmware_search_results ADD COLUMN signature_status TEXT NOT NULL DEFAULT 'not verifiable';
ALTER TABLE firmware_search_results ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'search result only (not verified)';
ALTER TABLE firmware_search_results ADD COLUMN distribution_status TEXT;    -- e.g. licensed | unknown
ALTER TABLE firmware_search_results ADD COLUMN match_details_json TEXT;
ALTER TABLE firmware_search_results ADD COLUMN firmware_id INTEGER REFERENCES firmware_files(id) ON DELETE SET NULL;
ALTER TABLE firmware_search_results ADD COLUMN downloaded_at TEXT;
ALTER TABLE firmware_search_results ADD COLUMN url_key TEXT;                -- normalised URL for de-duplication
CREATE INDEX idx_fsr_session ON firmware_search_results(session_id);
CREATE INDEX idx_fsr_urlkey ON firmware_search_results(url_key);

-- Downloads (attempts and outcomes), including malware-scan result.
CREATE TABLE firmware_downloads (
    id              INTEGER PRIMARY KEY,
    result_id       INTEGER REFERENCES firmware_search_results(id) ON DELETE SET NULL,
    url             TEXT NOT NULL,
    status          TEXT NOT NULL,              -- completed | failed | refused | hash_mismatch | quarantined
    bytes           INTEGER,
    sha256          TEXT,
    expected_sha256 TEXT,
    malware_scan    TEXT,
    firmware_id     INTEGER REFERENCES firmware_files(id) ON DELETE SET NULL,
    message         TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at     TEXT
);
