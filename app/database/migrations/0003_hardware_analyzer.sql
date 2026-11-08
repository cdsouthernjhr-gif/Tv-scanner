-- 0003: Phase 3 — Hardware Analyzer (component reference DB, datasheets, specification facts).

-- Extra detail for components found on a TV.
ALTER TABLE hardware_components ADD COLUMN board TEXT;            -- mainboard, power_supply, tcon, panel, other
ALTER TABLE hardware_components ADD COLUMN position TEXT;         -- reference designator, e.g. U12
ALTER TABLE hardware_components ADD COLUMN quantity INTEGER NOT NULL DEFAULT 1;
ALTER TABLE hardware_components ADD COLUMN catalog_kind TEXT;     -- chipset | memory | panel
ALTER TABLE hardware_components ADD COLUMN catalog_id INTEGER;
ALTER TABLE hardware_components ADD COLUMN datasheet_id INTEGER REFERENCES datasheets(id) ON DELETE SET NULL;
ALTER TABLE hardware_components ADD COLUMN match_status TEXT NOT NULL DEFAULT 'not_analyzed';
    -- not_analyzed | unidentified | vendor_only | decoded | datasheet_family | datasheet_exact
ALTER TABLE hardware_components ADD COLUMN analyzed_at TEXT;
ALTER TABLE hardware_components ADD COLUMN notes TEXT;
ALTER TABLE hardware_components ADD COLUMN analysis_warnings TEXT;   -- JSON list from the last analysis

-- Local datasheet library (PDF copies are read-only and hashed).
CREATE TABLE datasheets (
    id              INTEGER PRIMARY KEY,
    vendor          TEXT,
    title           TEXT,
    original_filename TEXT NOT NULL,
    stored_path     TEXT NOT NULL,
    sha256          TEXT NOT NULL UNIQUE,
    file_size       INTEGER NOT NULL,
    page_count      INTEGER,
    source_url      TEXT,                        -- where the operator obtained it (never invented)
    text_extracted  INTEGER NOT NULL DEFAULT 0,
    imported_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Extracted text per page, used for part-number search and fact extraction.
CREATE TABLE datasheet_pages (
    datasheet_id    INTEGER NOT NULL REFERENCES datasheets(id) ON DELETE CASCADE,
    page            INTEGER NOT NULL,
    text            TEXT NOT NULL,
    PRIMARY KEY (datasheet_id, page)
);

-- Part numbers mentioned in each datasheet (canonical form for matching).
CREATE TABLE datasheet_parts (
    datasheet_id    INTEGER NOT NULL REFERENCES datasheets(id) ON DELETE CASCADE,
    part_number     TEXT NOT NULL,
    canonical       TEXT NOT NULL,
    first_page      INTEGER,
    PRIMARY KEY (datasheet_id, canonical)
);
CREATE INDEX idx_dsparts_canonical ON datasheet_parts(canonical);

-- One row per specification fact, each with its own provenance.
-- owner_kind: 'component' (a hardware_components row on a TV) or 'chipset' / 'memory' / 'panel'
-- (reference database rows).
CREATE TABLE component_specs (
    id              INTEGER PRIMARY KEY,
    owner_kind      TEXT NOT NULL,
    owner_id        INTEGER NOT NULL,
    attribute       TEXT NOT NULL,              -- memory_type, density_bits, organization, interface, voltage ...
    value           TEXT NOT NULL,
    unit            TEXT,
    source_type     TEXT NOT NULL CHECK (source_type IN ('datasheet','decoder','marking_rule','user')),
    source_reference TEXT NOT NULL,             -- e.g. 'datasheet #3 p.1', 'decoder samsung_ddr', 'operator'
    confidence      REAL NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (owner_kind, owner_id, attribute, value, source_type, source_reference)
);
CREATE INDEX idx_specs_owner ON component_specs(owner_kind, owner_id);
