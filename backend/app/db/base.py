"""Declarative base and shared column mixins."""
 
from __future__ import annotations
 
from datetime import datetime, timezone
 
from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
 
 
def utcnow() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(tz=timezone.utc)
 
 
class Base(DeclarativeBase):
    """Base class for all ORM models."""
 
 
class TimestampMixin:
    """Adds ``created_at`` / ``updated_at`` bookkeeping columns."""
 
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )