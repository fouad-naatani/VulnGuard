"""User schemas."""
 
from __future__ import annotations
 
from datetime import datetime
 
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
 
from app.models.user import UserRole
from app.utils.validators import validate_password_strength
 
 
class UserBase(BaseModel):
    """Fields common to user creation and update."""
 
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    role: UserRole = UserRole.VIEWER
    is_active: bool = True
 
 
class UserCreate(UserBase):
    """Payload for creating a user."""
 
    password: str = Field(min_length=10, max_length=256)
 
    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        return validate_password_strength(value)
 
 
class UserUpdate(BaseModel):
    """Partial update of a user; every field is optional."""
 
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=10, max_length=256)
 
    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str | None) -> str | None:
        return validate_password_strength(value) if value else value
 
 
class UserRead(UserBase):
    """User representation returned by the API."""
 
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    last_login_at: datetime | None = None
    created_at: datetime