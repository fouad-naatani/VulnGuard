"""Asset model: a scannable machine, container image or endpoint."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class AgentStatus(str, enum.Enum):
    """Reported state of the monitoring agent installed on the asset."""

    ONLINE = "online"
    OFFLINE = "offline"
    NEVER_CONNECTED = "never_connected"


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)

    wazuh_agent_id: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        unique=True,
        nullable=True,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
    )

    ip_address: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    tags: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    agent_status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status"),
        default=AgentStatus.NEVER_CONNECTED,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    last_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    scans = relationship(
        "Scan",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    @property
    def tag_list(self) -> list[str]:
        if not self.tags:
            return []

        return [
            tag.strip()
            for tag in self.tags.split(",")
            if tag.strip()
        ]