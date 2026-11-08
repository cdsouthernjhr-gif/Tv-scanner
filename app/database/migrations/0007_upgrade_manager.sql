-- 0007: Phase 7 — Compatibility Analyzer and Firmware Upgrade Manager.

ALTER TABLE firmware_compatibility ADD COLUMN baseline_firmware_id INTEGER REFERENCES firmware_files(id) ON DELETE SET NULL;
ALTER TABLE firmware_compatibility ADD COLUMN criteria_json TEXT;

-- Upgrade profiles: one per manufacturer/model(/chassis/board) and method, citing documentation.
ALTER TABLE firmware_upgrade_profiles ADD COLUMN chassis TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN mainboard_pattern TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN documentation_ref TEXT;      -- mandatory (enforced in code)
ALTER TABLE firmware_upgrade_profiles ADD COLUMN package_pattern TEXT;        -- documented file name pattern, e.g. upgrade_*.bin
ALTER TABLE firmware_upgrade_profiles ADD COLUMN usb_filesystems TEXT;        -- e.g. FAT32
ALTER TABLE firmware_upgrade_profiles ADD COLUMN usb_target_path TEXT;        -- path on the USB stick, e.g. / or /upgrade
ALTER TABLE firmware_upgrade_profiles ADD COLUMN usb_target_name TEXT;        -- required file name on the stick ('' = keep)
ALTER TABLE firmware_upgrade_profiles ADD COLUMN power_requirements TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN verification_steps TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN recovery_procedure TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN rollback_documented INTEGER NOT NULL DEFAULT 0;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN verified_by TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN verified_at TEXT;
ALTER TABLE firmware_upgrade_profiles ADD COLUMN created_at TEXT;

ALTER TABLE firmware_upgrade_sessions ADD COLUMN method TEXT;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN compatibility_id INTEGER REFERENCES firmware_compatibility(id) ON DELETE SET NULL;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN steps_json TEXT;             -- per-step status/results
ALTER TABLE firmware_upgrade_sessions ADD COLUMN backup_json TEXT;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN preparation_json TEXT;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN execution_json TEXT;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN verification_json TEXT;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN executable INTEGER NOT NULL DEFAULT 0;
ALTER TABLE firmware_upgrade_sessions ADD COLUMN created_at TEXT;
