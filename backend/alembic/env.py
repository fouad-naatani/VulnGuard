"""Alembic environment wired to the async SQLAlchemy engine."""
 
from __future__ import annotations
 
import asyncio
from logging.config import fileConfig
 
from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
 
from app.core.config import settings
from app.db.base import Base
from app import models  # noqa: F401  (imported for metadata registration)
 
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
 
target_metadata = Base.metadata
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
 
 
def run_migrations_offline() -> None:
    """Emit SQL statements without connecting to a database."""
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
 
 
def do_run_migrations(connection: Connection) -> None:
    """Run migrations on an established connection."""
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()
 
 
async def run_async_migrations() -> None:
    """Create an async engine and run the migrations through it."""
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()
 
 
def run_migrations_online() -> None:
    """Entrypoint used when Alembic runs against a live database."""
    asyncio.run(run_async_migrations())
 
 
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()