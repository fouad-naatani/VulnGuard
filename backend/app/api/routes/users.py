"""User management endpoints (admin only)."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.api.deps import get_current_user, require_admin
from app.core.security import hash_password
from app.db.session import get_session
from app.models.user import User, UserRole
from app.schemas.common import Message, Page
from app.schemas.user import UserCreate, UserRead, UserUpdate
 
router = APIRouter(prefix="/users", tags=["users"])
 
 
@router.get("", response_model=Page[UserRead])
async def list_users(
    search: str | None = None,
    role: UserRole | None = None,
    is_active: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_admin),
) -> Page[UserRead]:
    """List platform users."""
    query = select(User)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(User.email.ilike(pattern), User.full_name.ilike(pattern)))
    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)
 
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    query = query.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await session.scalars(query)).all()
    return Page[UserRead](
        items=[UserRead.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
 
 
@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_admin),
) -> UserRead:
    """Create a user account."""
    email = payload.email.lower()
    if await session.scalar(select(User).where(User.email == email)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists"
        )
    user = User(
        email=email,
        full_name=payload.full_name,
        role=payload.role,
        is_active=payload.is_active,
        hashed_password=hash_password(payload.password),
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return UserRead.model_validate(user)
 
 
@router.put("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_admin),
) -> UserRead:
    """Update a user, optionally resetting the password or deactivating it."""
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
 
    data = payload.model_dump(exclude_unset=True)
    if password := data.pop("password", None):
        user.hashed_password = hash_password(password)
    if "email" in data and data["email"]:
        data["email"] = data["email"].lower()
    if user.id == current_user.id and data.get("is_active") is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account"
        )
    for field, value in data.items():
        setattr(user, field, value)
 
    await session.flush()
    await session.refresh(user)
    return UserRead.model_validate(user)
 
 
@router.delete("/{user_id}", response_model=Message)
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_admin),
) -> Message:
    """Delete a user account."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account"
        )
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await session.delete(user)
    return Message(detail="User deleted")
 
 
@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> UserRead:
    """Return a single user profile."""
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user)