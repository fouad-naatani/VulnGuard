"""Asset CRUD endpoints with search, filtering and pagination."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.api.deps import get_current_user, require_admin, require_operator
from app.api.serializers import serialize_asset
from app.db.session import get_session
from app.models.asset import AgentStatus, Asset
from app.models.user import User
from app.models.vulnerability import Severity, Vulnerability
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate
from app.schemas.common import Message, Page
 
router = APIRouter(prefix="/assets", tags=["assets"])
 
 
def _tags_to_column(tags: list[str] | None) -> str | None:
    """Serialise a tag list into the comma separated storage format."""
    if tags is None:
        return None
    return ",".join(tag.strip() for tag in tags if tag.strip()) or None
 
 
async def _counts_by_asset(
    session: AsyncSession, asset_ids: list[int]
) -> dict[int, tuple[int, int]]:
    """Return ``{asset_id: (total_vulns, critical_vulns)}`` for the given assets."""
    if not asset_ids:
        return {}
    critical_expr = func.sum(case((Vulnerability.severity == Severity.CRITICAL, 1), else_=0))
    rows = await session.execute(
        select(Vulnerability.asset_id, func.count(Vulnerability.id), critical_expr)
        .where(Vulnerability.asset_id.in_(asset_ids))
        .group_by(Vulnerability.asset_id)
    )
    return {row[0]: (int(row[1] or 0), int(row[2] or 0)) for row in rows}
 
 
@router.get("", response_model=Page[AssetRead])
async def list_assets(
    search: str | None = Query(default=None, description="Match hostname, IP, OS or owner"),
    agent_status: AgentStatus | None = None,
    tag: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    sort_by: str = Query(
        default="created_at", pattern="^(hostname|ip_address|created_at|last_scan_at)$"
    ),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> Page[AssetRead]:
    """List assets matching the supplied filters."""
    query = select(Asset)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
                Asset.operating_system.ilike(pattern),
                Asset.owner.ilike(pattern),
            )
        )
    if agent_status:
        query = query.where(Asset.agent_status == agent_status)
    if tag:
        query = query.where(Asset.tags.ilike(f"%{tag.strip()}%"))
 
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
 
    order_column = getattr(Asset, sort_by)
    query = query.order_by(order_column.desc() if sort_dir == "desc" else order_column.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)
 
    assets = list((await session.scalars(query)).all())
    counts = await _counts_by_asset(session, [asset.id for asset in assets])
    items = [serialize_asset(asset, *counts.get(asset.id, (0, 0))) for asset in assets]
    return Page[AssetRead](items=items, total=total, page=page, page_size=page_size)
 
 
@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(
    asset_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> AssetRead:
    """Return a single asset with its vulnerability counters."""
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    counts = await _counts_by_asset(session, [asset.id])
    return serialize_asset(asset, *counts.get(asset.id, (0, 0)))
 
 
@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> AssetRead:
    """Create a new asset."""
    asset = Asset(
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        operating_system=payload.operating_system,
        owner=payload.owner,
        tags=_tags_to_column(payload.tags),
        agent_status=payload.agent_status,
        description=payload.description,
    )
    session.add(asset)
    await session.flush()
    await session.refresh(asset)
    return serialize_asset(asset)
 
 
@router.put("/{asset_id}", response_model=AssetRead)
async def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> AssetRead:
    """Apply a partial update to an asset."""
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
 
    data = payload.model_dump(exclude_unset=True)
    if "tags" in data:
        data["tags"] = _tags_to_column(data["tags"])
    for field, value in data.items():
        setattr(asset, field, value)
 
    await session.flush()
    await session.refresh(asset)
    counts = await _counts_by_asset(session, [asset.id])
    return serialize_asset(asset, *counts.get(asset.id, (0, 0)))
 
 
@router.delete("/{asset_id}", response_model=Message)
async def delete_asset(
    asset_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_admin),
) -> Message:
    """Delete an asset together with its scans and findings."""
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    await session.delete(asset)
    return Message(detail="Asset deleted")