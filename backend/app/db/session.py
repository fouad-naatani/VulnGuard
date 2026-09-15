"""Async SQLAlchemy engine and session management."""
 
from __future__ import annotations
 
from collections.abc import AsyncIterator
 
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
 
from app.core.config import settings
 
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    future=True,
)
 
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)
 
 
async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise