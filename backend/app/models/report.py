"""Generated report model."""
 
from __future__ import annotations
 
import enum
 
from sqlalchemy import Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
 
from app.db.base import Base, TimestampMixin
 
 
class ReportFormat(str, enum.Enum):
    """Export formats supported by the reporting engine."""
 
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
 
 
class ReportStatus(str, enum.Enum):
    """Lifecycle of a report generation job."""
 
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
 
 
class Report(Base, TimestampMixin):
    """Metadata of a generated report stored on disk."""
 
    __tablename__ = "reports"
 
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, name="report_format"), default=ReportFormat.PDF, nullable=False
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), default=ReportStatus.PENDING, nullable=False
    )
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scope: Mapped[str] = mapped_column(String(64), default="all", nullable=False)
    scope_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )