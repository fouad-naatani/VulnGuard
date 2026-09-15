"""Shared FastAPI dependencies: database session, current user, RBAC guards."""
 
from __future__ import annotations
 
from collections.abc import Awaitable, Callable
 
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.core.security import decode_token
from app.db.session import get_session
from app.models.user import User, UserRole
 
bearer_scheme = HTTPBearer(auto_error=False)
 
CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
 
 
async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the authenticated user from the ``Authorization`` header."""
    if credentials is None or not credentials.credentials:
        raise CREDENTIALS_ERROR
 
    payload = decode_token(credentials.credentials, expected_type="access")
    if payload is None:
        raise CREDENTIALS_ERROR
 
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CREDENTIALS_ERROR from exc
 
    user = await session.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active:
        raise CREDENTIALS_ERROR
    return user
 
 
def require_roles(*roles: UserRole) -> Callable[[User], Awaitable[User]]:
    """Build a dependency allowing only the given roles.
 
    Usage::
 
        @router.post("", dependencies=[Depends(require_roles(UserRole.ADMIN))])
    """
 
    async def _guard(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges for this operation",
            )
        return current_user
 
    return _guard
 
 
#: Roles allowed to mutate operational data (assets, scans, triage).
OPERATOR_ROLES = (UserRole.ADMIN, UserRole.SOC_ANALYST, UserRole.PENTESTER)
 
require_admin = require_roles(UserRole.ADMIN)
require_operator = require_roles(*OPERATOR_ROLES)