"""Platform settings endpoints."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.api.deps import get_current_user, require_admin
from app.db.session import get_session
from app.models.setting import Setting
from app.models.user import User
from app.schemas.setting import SettingRead, SettingUpdate
 
router = APIRouter(prefix="/settings", tags=["settings"])
 
MASKED_VALUE = "********"
 
 
def _serialize(setting: Setting) -> SettingRead:
    """Return a setting with secret values masked."""
    return SettingRead(
        key=setting.key,
        value=MASKED_VALUE if setting.is_secret and setting.value else setting.value,
        category=setting.category,
        is_secret=setting.is_secret,
    )
 
 
@router.get("", response_model=list[SettingRead])
async def list_settings(
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> list[SettingRead]:
    """List every configuration entry, masking secrets."""
    rows = (await session.scalars(select(Setting).order_by(Setting.category, Setting.key))).all()
    return [_serialize(row) for row in rows]
 
 
@router.put("", response_model=list[SettingRead])
async def upsert_settings(
    payload: list[SettingUpdate],
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_admin),
) -> list[SettingRead]:
    """Create or update the supplied configuration entries."""
    result: list[Setting] = []
    for item in payload:
        setting = await session.scalar(select(Setting).where(Setting.key == item.key))
        if setting is None:
            setting = Setting(key=item.key, category=item.category, is_secret=item.is_secret)
            session.add(setting)
        # A masked value means "leave the stored secret untouched".
        if not (setting.is_secret and item.value == MASKED_VALUE):
            setting.value = item.value
        setting.category = item.category
        setting.is_secret = item.is_secret
        result.append(setting)
    await session.flush()
    return [_serialize(setting) for setting in result]