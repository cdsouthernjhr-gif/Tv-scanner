"""Aggregated statistics for the main dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.database.connection import Database


@dataclass
class DashboardStats:
    total_projects: int = 0
    identified: int = 0
    unknown: int = 0
    firmware_in_library: int = 0
    firmware_analyzed: int = 0
    firmware_found: int = 0
    verified_firmware: int = 0
    upgrade_sessions: int = 0
    recent_scans: list[dict] = field(default_factory=list)


def collect_stats(db: Database, recent_limit: int = 15) -> DashboardStats:
    s = DashboardStats()
    s.total_projects = db.scalar("SELECT COUNT(*) FROM tv_projects")
    s.identified = db.scalar(
        "SELECT COUNT(*) FROM tv_projects WHERE identification_status IN ('identified','verified')")
    s.unknown = db.scalar(
        "SELECT COUNT(*) FROM tv_projects WHERE identification_status IN ('unknown','partial')")
    s.firmware_in_library = db.scalar("SELECT COUNT(*) FROM firmware_files")
    s.firmware_analyzed = db.scalar("SELECT COUNT(DISTINCT firmware_id) FROM firmware_analysis")
    s.firmware_found = db.scalar("SELECT COUNT(*) FROM firmware_search_results")
    s.verified_firmware = db.scalar(
        "SELECT COUNT(*) FROM firmware_files WHERE verification_status='verified'")
    s.upgrade_sessions = db.scalar("SELECT COUNT(*) FROM firmware_upgrade_sessions")
    s.recent_scans = [dict(r) for r in db.query(
        "SELECT s.id, s.session_type, s.summary, s.started_at, p.name AS project_name,"
        " p.identification_status FROM scan_sessions s JOIN tv_projects p ON p.id=s.project_id"
        " ORDER BY s.id DESC LIMIT ?", (recent_limit,))]
    return s
