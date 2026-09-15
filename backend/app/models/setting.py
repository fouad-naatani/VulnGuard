"""Key/value platform settings model."""
 
from __future__ import annotations
 
from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column
 
from app.db.base import Base, TimestampMixin
 
 
class Setting(Base, TimestampMixin):
    """A single configuration entry editable from the Settings page."""
 
    __tablename__ = "settings"
 
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="general", nullable=False)
    # Secret values are masked when returned by the API.
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)