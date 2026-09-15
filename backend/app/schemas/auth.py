"""Authentication request/response schemas."""
 
from __future__ import annotations
 
from pydantic import BaseModel, EmailStr, Field
 
from app.schemas.user import UserRead
 
 
class LoginRequest(BaseModel):
    """Credentials submitted by the login form."""
 
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    remember_me: bool = False
 
 
class TokenPair(BaseModel):
    """Access/refresh token pair plus the authenticated user profile."""
 
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead
 
 
class RefreshRequest(BaseModel):
    """Payload used to exchange a refresh token for a new access token."""
 
    refresh_token: str
 
 
class AccessToken(BaseModel):
    """Freshly minted access token."""
 
    access_token: str
    token_type: str = "bearer"
    expires_in: int
 
 
class PasswordChangeRequest(BaseModel):
    """Self-service password change."""
 
    current_password: str
    new_password: str = Field(min_length=10, max_length=256)