"""Authentication endpoints: login, refresh, logout, profile."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.base import utcnow
from app.db.session import get_session
from app.models.user import User
from app.schemas.auth import (
    AccessToken,
    LoginRequest,
    PasswordChangeRequest,
    RefreshRequest,
    TokenPair,
)
from app.schemas.common import Message
from app.schemas.user import UserRead
 
router = APIRouter(tags=["auth"])
 
INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid email or password",
)
 
 
@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_session)) -> TokenPair:
    """Authenticate a user and return an access/refresh token pair.
 
    The same generic error is returned for unknown emails, wrong passwords and
    deactivated accounts so the endpoint cannot be used to enumerate users.
    """
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise INVALID_CREDENTIALS
    if not user.is_active:
        raise INVALID_CREDENTIALS
 
    user.last_login_at = utcnow()
    await session.flush()
 
    return TokenPair(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id)),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserRead.model_validate(user),
    )
 
 
@router.post("/refresh", response_model=AccessToken)
async def refresh_token(
    payload: RefreshRequest, session: AsyncSession = Depends(get_session)
) -> AccessToken:
    """Exchange a valid refresh token for a new access token."""
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
 
    user = await session.scalar(select(User).where(User.id == int(claims["sub"])))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
 
    return AccessToken(
        access_token=create_access_token(str(user.id), user.role.value),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
 
 
@router.post("/logout", response_model=Message)
async def logout(_: User = Depends(get_current_user)) -> Message:
    """Log the current user out.
 
    Tokens are stateless, so the server simply acknowledges the call and the
    client discards its stored credentials.
    """
    return Message(detail="Logged out")
 
 
@router.get("/me", response_model=UserRead)
async def read_current_user(current_user: User = Depends(get_current_user)) -> UserRead:
    """Return the authenticated user profile."""
    return UserRead.model_validate(current_user)
 
 
@router.post("/me/password", response_model=Message)
async def change_password(
    payload: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Message:
    """Change the password of the authenticated user."""
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )
    current_user.hashed_password = hash_password(payload.new_password)
    session.add(current_user)
    return Message(detail="Password updated")