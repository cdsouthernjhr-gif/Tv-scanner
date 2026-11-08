-- 0006: Phase 6 — Software & OS Analyzer, Factory & Service Menu database.

-- Software/OS facts per project, each with its own source.
CREATE TABLE software_facts (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    category        TEXT NOT NULL,      -- os, os_version, kernel, build, firmware_version, bootloader, application,
                                        -- library, driver, network_interface, display, audio, device_info, other
    name            TEXT NOT NULL,
    value           TEXT,
    source_type     TEXT NOT NULL CHECK (source_type IN ('firmware_analysis','system_menu_ocr','operator',
                                                         'upnp','adb','fingerprint')),
    source_ref      TEXT NOT NULL,
    confidence      REAL NOT NULL,
    firmware_id     INTEGER REFERENCES firmware_files(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX idx_swfacts_project ON software_facts(project_id, category);

-- Authorised device communication sessions (read-only queries).
CREATE TABLE device_sessions (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER REFERENCES tv_projects(id) ON DELETE SET NULL,
    connector       TEXT NOT NULL,      -- upnp | adb
    target          TEXT,
    authorization_note TEXT NOT NULL,   -- operator's statement of authorisation
    status          TEXT NOT NULL,
    commands_json   TEXT,
    output_json     TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at     TEXT
);

-- Service menu records must cite official documentation.
ALTER TABLE service_menus ADD COLUMN source_type TEXT NOT NULL DEFAULT 'official_document';
    -- official_document | official_web | manufacturer_training
ALTER TABLE service_menus ADD COLUMN document_id INTEGER REFERENCES datasheets(id) ON DELETE SET NULL;
ALTER TABLE service_menus ADD COLUMN document_page INTEGER;
ALTER TABLE service_menus ADD COLUMN region TEXT;
ALTER TABLE service_menus ADD COLUMN backup_mechanism TEXT;     -- documented way to back up settings, if any
ALTER TABLE service_menus ADD COLUMN notes TEXT;
ALTER TABLE service_menus ADD COLUMN created_by TEXT;
ALTER TABLE service_menus ADD COLUMN created_at TEXT;
ALTER TABLE service_menus ADD COLUMN updated_at TEXT;

-- Planned / performed changes of factory settings (documentation + safety workflow).
CREATE TABLE service_actions (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES tv_projects(id) ON DELETE CASCADE,
    service_menu_id INTEGER NOT NULL REFERENCES service_menus(id) ON DELETE RESTRICT,
    setting         TEXT NOT NULL,
    old_value       TEXT,
    new_value       TEXT NOT NULL,
    reason          TEXT NOT NULL,
    backup_required INTEGER NOT NULL,
    backup_evidence TEXT,               -- description / location of the backup
    backup_evidence_id INTEGER REFERENCES scan_evidence(id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned','backed_up','confirmed','performed','cancelled')),
    confirmed_by    TEXT,
    confirmed_at    TEXT,
    performed_at    TEXT,
    result          TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
