"""Password hashing and JWT helpers."""
 
from __future__ import annotations
 
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
 
from jose import JWTError, jwt
from passlib.context import CryptContext
 
from app.core.config import settings
 
TokenType = Literal["access", "refresh"]
 
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
 
 
def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return _pwd_context.hash(password)
 
 
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time verification of a plaintext password against its hash."""
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        # Malformed hash stored in database: treat as failed authentication.
        return False
 
 
def _create_token(subject: str, token_type: TokenType, expires_minutes: int, **claims: Any) -> str:
    """Build a signed JWT for ``subject`` with the given type and lifetime."""
    now = datetime.now(tz=timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        **claims,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
 
 
def create_access_token(subject: str, role: str) -> str:
    """Create a short lived access token carrying the user role."""
    return _create_token(subject, "access", settings.ACCESS_TOKEN_EXPIRE_MINUTES, role=role)
 
 
def create_refresh_token(subject: str) -> str:
    """Create a long lived refresh token used to mint new access tokens."""
    return _create_token(subject, "refresh", settings.REFRESH_TOKEN_EXPIRE_MINUTES)
 
 
def decode_token(token: str, expected_type: TokenType) -> dict[str, Any] | None:
    """Decode and validate a JWT, returning ``None`` when it is not usable."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != expected_type:
        return None
    return payload