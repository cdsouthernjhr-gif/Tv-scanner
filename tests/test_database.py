import sqlite3

import pytest

from app.database.connection import Database
from app.database.migrations_runner import apply_migrations, discover

SPEC_TABLES = """manufacturers tv_models tv_chassis mainboards chipsets memory_chips display_panels
hardware_components firmware_files firmware_sources firmware_search_results firmware_analysis
firmware_versions firmware_compatibility firmware_upgrade_profiles firmware_upgrade_sessions
operating_systems service_menus diagnostic_profiles scan_sessions scan_evidence technical_reports""".split()


def test_all_spec_tables_exist(tmp_path):
    db = Database(tmp_path / "t.db")
    names = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in SPEC_TABLES + ["tv_projects", "audit_log", "schema_migrations"]:
        assert t in names, t
    assert db.schema_version == len(discover())
    assert db.scalar("PRAGMA user_version") == db.schema_version
    assert db.scalar("PRAGMA foreign_keys") == 1
    db.close()


def test_migrations_idempotent_and_reopen(tmp_path):
    path = tmp_path / "t.db"
    db = Database(path)
    db.execute("INSERT INTO tv_projects(name) VALUES ('x')")
    db.close()
    db2 = Database(path)
    assert db2.scalar("SELECT COUNT(*) FROM schema_migrations") == len(discover())
    assert db2.scalar("SELECT name FROM tv_projects") == "x"
    db2.close()


def test_new_migration_applied_once(tmp_path):
    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "0001_a.sql").write_text("CREATE TABLE a(x INTEGER);")
    conn = sqlite3.connect(tmp_path / "x.db")
    assert apply_migrations(conn, mdir) == 1
    (mdir / "0002_b.sql").write_text("ALTER TABLE a ADD COLUMN y TEXT;")
    assert apply_migrations(conn, mdir) == 2
    assert apply_migrations(conn, mdir) == 2
    cols = [r[1] for r in conn.execute("PRAGMA table_info(a)")]
    assert cols == ["x", "y"]


def test_failed_migration_rolls_back(tmp_path):
    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "0001_bad.sql").write_text("CREATE TABLE ok(x); THIS IS NOT SQL;")
    conn = sqlite3.connect(tmp_path / "x.db")
    with pytest.raises(sqlite3.Error):
        apply_migrations(conn, mdir)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "ok" not in names
    assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0


def test_transaction_rollback(tmp_path):
    db = Database(tmp_path / "t.db")
    with pytest.raises(RuntimeError):
        with db.transaction() as c:
            c.execute("INSERT INTO tv_projects(name) VALUES ('y')")
            raise RuntimeError("boom")
    assert db.scalar("SELECT COUNT(*) FROM tv_projects") == 0
    db.close()


def test_check_constraints(tmp_path):
    db = Database(tmp_path / "t.db")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO tv_projects(name, identification_status) VALUES ('z','bogus')")
    db.close()
