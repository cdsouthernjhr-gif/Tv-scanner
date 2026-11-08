"""Application context: wires configuration, database and services together."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.firmware_analyzer.service import FirmwareAnalyzer
from app.modules.firmware_finder.engine import FirmwareFinder
from app.modules.firmware_library.library import FirmwareLibrary
from app.modules.service_menu.service import ServiceMenuDB
from app.modules.software_analyzer.service import SoftwareAnalyzer
from app.modules.hardware_analyzer.datasheets import DatasheetLibrary
from app.modules.hardware_analyzer.service import HardwareAnalyzer
from app.modules.identification.catalog import CatalogService
from app.modules.identification.service import IdentificationService
from app.modules.reports.firmware_report import FirmwareReportGenerator
from app.modules.reports.hardware_report import HardwareReportGenerator
from app.modules.reports.search_report import SearchReportGenerator
from app.modules.reports.software_report import SoftwareReportGenerator
from app.modules.reports.pdf_report import PdfReportGenerator
from app.security.audit import AuditLogger
from app.security.secrets import SecretStore
from app.services.evidence_service import EvidenceService
from app.services.project_service import ProjectService


@dataclass
class AppContext:
    config: AppConfig
    db: Database
    audit: AuditLogger
    projects: ProjectService
    evidence: EvidenceService
    library: FirmwareLibrary
    reports: PdfReportGenerator
    catalog: CatalogService
    identification: IdentificationService
    datasheets: DatasheetLibrary
    hardware: HardwareAnalyzer
    hardware_reports: HardwareReportGenerator
    firmware: FirmwareAnalyzer
    firmware_reports: FirmwareReportGenerator
    secrets: SecretStore
    finder: FirmwareFinder
    search_reports: SearchReportGenerator
    software: SoftwareAnalyzer
    service_menus: ServiceMenuDB
    software_reports: SoftwareReportGenerator
    compatibility: object = None      # CompatibilityAnalyzer (needs the full context)
    upgrades: object = None           # UpgradeManager
    upgrade_reports: object = None    # UpgradeReportGenerator
    report_center: object = None      # ReportCenter (all reports, all formats)

    @classmethod
    def create(cls, data_dir: Path | None = None) -> "AppContext":
        config = AppConfig.load(data_dir)
        db = Database(config.database_path)
        audit = AuditLogger(db)
        projects = ProjectService(db, audit)
        evidence = EvidenceService(config, db, audit)
        library = FirmwareLibrary(config, db, audit)
        reports = PdfReportGenerator(config, db, audit, projects, evidence, library)
        catalog = CatalogService(db, audit)
        identification = IdentificationService(config, db, audit, projects, evidence, catalog)
        datasheets = DatasheetLibrary(config, db, audit)
        hardware = HardwareAnalyzer(db, audit, projects, datasheets)
        hardware_reports = HardwareReportGenerator(config, db, audit, projects, evidence, hardware)
        firmware = FirmwareAnalyzer(config, db, audit, library)
        firmware_reports = FirmwareReportGenerator(config, db, audit, library, firmware)
        secrets = SecretStore()
        finder = FirmwareFinder(config, db, audit, library, firmware, secrets)
        search_reports = SearchReportGenerator(config, db, audit, finder)
        software = SoftwareAnalyzer(db, audit, projects, library, firmware)
        service_menus = ServiceMenuDB(db, audit, datasheets)
        software_reports = SoftwareReportGenerator(config, db, audit, projects, software, service_menus)
        audit.record("app.start", details_dir=str(config.data_dir))
        ctx = cls(config, db, audit, projects, evidence, library, reports, catalog, identification,
                  datasheets, hardware, hardware_reports, firmware, firmware_reports, secrets, finder,
                  search_reports, software, service_menus, software_reports)
        from app.modules.compatibility.analyzer import CompatibilityAnalyzer
        from app.modules.reports.upgrade_report import UpgradeReportGenerator
        from app.modules.upgrade_manager.service import UpgradeManager
        ctx.compatibility = CompatibilityAnalyzer(ctx)
        ctx.upgrades = UpgradeManager(ctx)
        ctx.upgrade_reports = UpgradeReportGenerator(ctx)
        from app.modules.reports.report_center import ReportCenter
        ctx.report_center = ReportCenter(ctx)
        return ctx

    def close(self) -> None:
        self.db.close()
