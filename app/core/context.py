"""Application context: wires configuration, database and services together."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.firmware_analyzer.service import FirmwareAnalyzer
from app.modules.firmware_finder.engine import FirmwareFinder
from app.modules.firmware_library.library import FirmwareLibrary
from app.modules.hardware_analyzer.datasheets import DatasheetLibrary
from app.modules.hardware_analyzer.service import HardwareAnalyzer
from app.modules.identification.catalog import CatalogService
from app.modules.identification.service import IdentificationService
from app.modules.reports.firmware_report import FirmwareReportGenerator
from app.modules.reports.hardware_report import HardwareReportGenerator
from app.modules.reports.search_report import SearchReportGenerator
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
        audit.record("app.start", details_dir=str(config.data_dir))
        return cls(config, db, audit, projects, evidence, library, reports, catalog, identification,
                   datasheets, hardware, hardware_reports, firmware, firmware_reports, secrets, finder,
                   search_reports)

    def close(self) -> None:
        self.db.close()
