"""User model and role enumeration."""
 
from __future__ import annotations
 
import enum
from datetime import datetime
 
from sqlalchemy import Boolean, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column
 
from app.db.base import Base, TimestampMixin
 
 
class UserRole(str, enum.Enum):
    """Roles available in the platform, ordered from most to least privileged."""
 
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"
    PENTESTER = "pentester"
    VIEWER = "viewer"
 
 
class User(Base, TimestampMixin):
    """An authenticated platform user."""
 
    __tablename__ = "users"
 
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), default=UserRole.VIEWER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)