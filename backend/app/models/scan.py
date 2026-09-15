"""Scan job and scan log models."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

class ScannerType(str, enum.Enum):
    """Supported vulnerability/security scanners."""

    TRIVY = "TRIVY"
    WAZUH = "WAZUH"
    NESSUS = "NESSUS"


class ScanStatus(str, enum.Enum):
    """Lifecycle of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base, TimestampMixin):
    """A single scan job executed against an asset."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    scanner: Mapped[ScannerType] = mapped_column(
        SAEnum(
            ScannerType,
            name="scanner_type",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        default=ScannerType.TRIVY,
        nullable=False,
    )

    target: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(
            ScanStatus,
            name="scan_status",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
        ),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    packages_found: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    asset = relationship(
        "Asset",
        back_populates="scans",
    )

    logs = relationship(
        "ScanLog",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanLog.created_at",
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration of the scan, when it has started."""

        if not self.started_at:
            return None

        end = self.finished_at or datetime.now(
            tz=self.started_at.tzinfo
        )

        return (end - self.started_at).total_seconds()


class ScanLog(Base):
    """A timestamped log line emitted while a scan runs."""

    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    level: Mapped[str] = mapped_column(
        String(16),
        default="info",
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(),
    )

    scan = relationship(
        "Scan",
        back_populates="logs",
    )
    
    