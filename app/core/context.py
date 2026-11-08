"""Application context: wires configuration, database and services together."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig
from app.database.connection import Database
from app.modules.firmware_library.library import FirmwareLibrary
from app.modules.hardware_analyzer.datasheets import DatasheetLibrary
from app.modules.hardware_analyzer.service import HardwareAnalyzer
from app.modules.identification.catalog import CatalogService
from app.modules.identification.service import IdentificationService
from app.modules.reports.hardware_report import HardwareReportGenerator
from app.modules.reports.pdf_report import PdfReportGenerator
from app.security.audit import AuditLogger
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
        audit.record("app.start", details_dir=str(config.data_dir))
        return cls(config, db, audit, projects, evidence, library, reports, catalog, identification,
                   datasheets, hardware, hardware_reports)

    def close(self) -> None:
        self.db.close()
