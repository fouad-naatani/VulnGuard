import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE_URL = "postgresql+asyncpg://vmp:vmp@localhost:5432/vmp"

engine = create_async_engine(DATABASE_URL, echo=True)

async def main():
    async with engine.connect() as conn:
        # Connection test
        version = await conn.execute(text("SELECT version();"))
        print("Connected to:", version.scalar())

        # List all tables
        tables = await conn.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public';
        """))

        print("\nTables:")
        rows = tables.fetchall()

        if not rows:
            print("No tables found.")
        else:
            for row in rows:
                print("-", row.table_name)

    await engine.dispose()

asyncio.run(main())