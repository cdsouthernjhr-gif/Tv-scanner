-- 0001: Initial schema for TV Intelligence Scanner.
-- All tables listed in the specification are created now so later phases
-- only add columns/indices through new numbered migrations.

CREATE TABLE manufacturers (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    website         TEXT,
    support_url     TEXT,
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE operating_systems (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,              -- Android TV, Tizen, webOS, VIDAA, Linux, proprietary ...
    vendor          TEXT,
    version         TEXT,
    kernel          TEXT,
    notes           TEXT,
    UNIQUE (name, version)
);

CREATE TABLE tv_chassis (
    id              INTEGER PRIMARY KEY,
    manufacturer_id INTEGER REFERENCES manufacturers(id) ON DELETE SET NULL,
    chassis_code    TEXT NOT NULL,
    notes           TEXT,
    UNIQUE (manufacturer_id, chassis_code)
);

CREATE TABLE chipsets (
    id              INTEGER PRIMARY KEY,
    vendor          TEXT,                       -- MediaTek, Realtek, Amlogic, Novatek ...
    part_number     TEXT NOT NULL,
    chip_type       TEXT NOT NULL DEFAULT 'soc',-- soc, wifi, bluetooth, audio, tcon, pmic ...
    architecture    TEXT,
    specification   TEXT,
    datasheet_url   TEXT,
    source_reference TEXT,
    UNIQUE (vendor, part_number)
);

CREATE TABLE memory_chips (
    id              INTEGER PRIMARY KEY,
    vendor          TEXT,
    part_number     TEXT NOT NULL,
    memory_type     TEXT,                       -- DDR3, DDR4, eMMC, SPI NOR, NAND ...
    capacity_bytes  INTEGER,                    -- NULL when not proven by evidence
    datasheet_url   TEXT,
    source_reference TEXT,
    UNIQUE (vendor, part_number)
);

CREATE TABLE display_panels (
    id              INTEGER PRIMARY KEY,
    vendor          TEXT,
    panel_model     TEXT NOT NULL,
    panel_id        TEXT,
    size_inches     REAL,
    resolution      TEXT,
    interface       TEXT,                       -- LVDS, V-by-One, eDP ...
    source_reference TEXT,
    UNIQUE (vendor, panel_model)
);

CREATE TABLE mainboards (
    id              INTEGER PRIMARY KEY,
    manufacturer_id INTEGER REFERENCES manufacturers(id) ON DELETE SET NULL,
    board_number    TEXT NOT NULL,
    pcb_revision    TEXT,
    soc_chipset_id  INTEGER REFERENCES chipsets(id) ON DELETE SET NULL,
    notes           TEXT,
    UNIQUE (board_number, pcb_revision)
);

CREATE TABLE tv_models (
    id              INTEGER PRIMARY KEY,
    manufacturer_id INTEGER REFERENCES manufacturers(id) ON DELETE SET NULL,
    model_number    TEXT NOT NULL,
    product_code    TEXT,
    chassis_id      INTEGER REFERENCES tv_chassis(id) ON DELETE SET NULL,
    mainboard_id    INTEGER REFERENCES mainboards(id) ON DELETE SET NULL,
    panel_id        INTEGER REFERENCES display_panels(id) ON DELETE SET NULL,
    os_id           INTEGER REFERENCES operating_systems(id) ON DELETE SET NULL,
    screen_size_inches REAL,
    tv_type         TEXT,
    notes           TEXT,
    UNIQUE (manufacturer_id, model_number)
);

-- A TV project is one physical TV under investigation (known or unknown).
CREATE TABLE tv_projects (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL,
    manufacturer        TEXT,
    model_number        TEXT,
    serial_number       TEXT,
    product_code        TEXT,
    chassis             TEXT,
    mainboard           TEXT,
    pcb_revision        TEXT,
    screen_size_inches  REAL,
    tv_type             TEXT,
    platform            TEXT,
    firmware_version    TEXT,
    identification_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (identification_status IN ('unknown','partial','identified','verified')),
    identification_confidence REAL NOT NULL DEFAULT 0.0,
    identification_source TEXT NOT NULL DEFAULT 'manual',
    tv_model_id         INTEGER REFERENCES tv_models(id) ON DELETE SET NULL,
    notes               TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE hardware_components (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE CASCADE,
    component_type  TEXT NOT NULL,
    component_name  TEXT,
    manufacturer    TEXT,
    part_number     TEXT,
    specification   TEXT,
    evidence_id     INTEGER REFERENCES scan_evidence(id) ON DELETE SET NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    verified_by_user INTEGER NOT NULL DEFAULT 0,
    source_reference TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE scan_sessions (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    session_type    TEXT NOT NULL,              -- registration, identification, visual, firmware ...
    summary         TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at     TEXT
);

CREATE TABLE scan_evidence (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    session_id      INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    evidence_type   TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_path     TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    file_size       INTEGER NOT NULL,
    width           INTEGER,
    height          INTEGER,
    description     TEXT,
    ocr_text        TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (project_id, sha256)
);

CREATE TABLE firmware_sources (
    id              INTEGER PRIMARY KEY,
    source_type     TEXT NOT NULL,              -- local_import, official, github, gitlab, community, archive ...
    name            TEXT,
    url             TEXT,
    reliability     TEXT NOT NULL DEFAULT 'unknown',
    accessed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    notes           TEXT
);

CREATE TABLE firmware_files (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE SET NULL,
    original_filename TEXT NOT NULL,
    stored_path     TEXT NOT NULL,
    sha256          TEXT NOT NULL UNIQUE,
    file_size       INTEGER NOT NULL,
    detected_format TEXT,
    manufacturer    TEXT,
    model_number    TEXT,
    mainboard       TEXT,
    version         TEXT,
    category        TEXT NOT NULL DEFAULT 'Original'
        CHECK (category IN ('Original','Official','Community')),
    source_id       INTEGER REFERENCES firmware_sources(id) ON DELETE SET NULL,
    download_url    TEXT,
    downloaded_at   TEXT,
    imported_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    verification_status TEXT NOT NULL DEFAULT 'unverified'
        CHECK (verification_status IN ('unverified','hash_ok','hash_mismatch','verified')),
    last_integrity_check TEXT,
    changelog       TEXT,
    notes           TEXT
);

CREATE TABLE firmware_versions (
    id              INTEGER PRIMARY KEY,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    version         TEXT NOT NULL,
    build           TEXT,
    release_date    TEXT,
    supported_models TEXT,
    supported_mainboards TEXT,
    changelog       TEXT
);

CREATE TABLE firmware_analysis (
    id              INTEGER PRIMARY KEY,
    firmware_id     INTEGER NOT NULL REFERENCES firmware_files(id) ON DELETE CASCADE,
    analyzer        TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE firmware_search_results (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE SET NULL,
    query           TEXT NOT NULL,
    provider        TEXT NOT NULL,
    title           TEXT,
    url             TEXT NOT NULL,
    version         TEXT,
    file_size       INTEGER,
    published_at    TEXT,
    sha256          TEXT,
    compatibility_score REAL,
    match_status    TEXT NOT NULL DEFAULT 'INSUFFICIENT INFORMATION',
    risk_assessment TEXT,
    raw_json        TEXT,
    searched_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE firmware_compatibility (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE CASCADE,
    firmware_id     INTEGER REFERENCES firmware_files(id) ON DELETE CASCADE,
    verdict         TEXT NOT NULL
        CHECK (verdict IN ('VERIFIED COMPATIBLE','LIKELY COMPATIBLE','POSSIBLE MATCH',
                           'INCOMPATIBLE','INSUFFICIENT EVIDENCE')),
    score           REAL,
    reasons_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE firmware_upgrade_profiles (
    id              INTEGER PRIMARY KEY,
    manufacturer    TEXT NOT NULL,
    model_pattern   TEXT NOT NULL,
    method          TEXT NOT NULL
        CHECK (method IN ('official_usb','official_network','service_tool',
                          'authorized_uart','authorized_usb_device','vendor_recovery')),
    instructions    TEXT,
    documentation_url TEXT,
    verified        INTEGER NOT NULL DEFAULT 0,
    risk_level      TEXT NOT NULL DEFAULT 'high',
    notes           TEXT
);

CREATE TABLE firmware_upgrade_sessions (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    profile_id      INTEGER REFERENCES firmware_upgrade_profiles(id) ON DELETE SET NULL,
    source_firmware_version TEXT,
    target_firmware_id INTEGER REFERENCES firmware_files(id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'planned',
    log             TEXT,
    started_at      TEXT,
    finished_at     TEXT
);

CREATE TABLE service_menus (
    id              INTEGER PRIMARY KEY,
    manufacturer    TEXT NOT NULL,
    model_pattern   TEXT,
    chassis         TEXT,
    platform        TEXT,
    firmware_version TEXT,
    menu_category   TEXT NOT NULL,
    access_procedure TEXT,
    function_description TEXT,
    official_documentation TEXT,
    access_availability TEXT,
    configuration_risk TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE diagnostic_profiles (
    id              INTEGER PRIMARY KEY,
    manufacturer    TEXT,
    platform        TEXT,
    interface       TEXT NOT NULL,              -- menu, official_api, adb (only if supported) ...
    description     TEXT,
    documentation_url TEXT
);

CREATE TABLE technical_reports (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE SET NULL,
    report_type     TEXT NOT NULL,
    format          TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    entity_type     TEXT,
    entity_id       INTEGER,
    details_json    TEXT
);

CREATE INDEX idx_evidence_project ON scan_evidence(project_id);
CREATE INDEX idx_fw_project ON firmware_files(project_id);
CREATE INDEX idx_fw_mainboard ON firmware_files(mainboard);
CREATE INDEX idx_sessions_project ON scan_sessions(project_id);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
