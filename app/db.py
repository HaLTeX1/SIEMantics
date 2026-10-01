import asyncio
import logging

from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger("siemantics.db")

# pool_recycle instead of pool_pre_ping: pre-ping is broken with aiomysql 0.3 on
# SQLAlchemy 2.0.35 (ping() missing "reconnect"); recycling keeps connections
# younger than MySQL's wait_timeout so they are not dropped server-side.
engine = create_async_engine(settings.database_url, echo=False, pool_recycle=3600)
async_session = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db(attempts: int = 30, delay: float = 2.0) -> None:
    # The database container may still be starting (MariaDB refuses connections
    # until it is initialized), so wait for it instead of crashing on boot.
    for attempt in range(1, attempts + 1):
        try:
            await _init_db()
            return
        except OperationalError as exc:
            if attempt == attempts:
                raise
            logger.warning("database not reachable (attempt %d/%d): %s", attempt, attempts, exc.orig)
            await asyncio.sleep(delay)


async def _init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)
        if conn.dialect.name == "mysql":
            await _sync_alert_status_enums(conn)


def _add_missing_columns(conn) -> None:
    """create_all() never alters an existing table, so a column added to a model
    later would be missing on an already-running database. This adds such
    columns (nullable only, without FK constraints) - a minimal stand-in for a
    migration tool that covers the "new optional column" case."""

    inspector = inspect(conn)
    preparer = conn.dialect.identifier_preparer
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {col["name"] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable:
                raise RuntimeError(f"cannot auto-add NOT NULL column {table.name}.{column.name}")
            col_type = column.type.compile(dialect=conn.dialect)
            conn.execute(
                text(f"ALTER TABLE {preparer.quote(table.name)} ADD COLUMN {preparer.quote(column.name)} {col_type} NULL")
            )


async def _sync_alert_status_enums(conn) -> None:
    """On MariaDB the AlertStatus columns are native ENUMs created with the
    members that existed at the time, so a newly added member would be rejected.
    Appending values to an ENUM is a cheap (instant) ALTER on MariaDB.
    SQLite stores the enum as plain VARCHAR, so it needs nothing."""

    from app.enums import AlertStatus

    values = ", ".join(f"'{m.name}'" for m in AlertStatus)
    for column, nullable in (("status", False), ("auto_status", True)):
        column_type = await conn.scalar(
            text(
                "SELECT COLUMN_TYPE FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'alert_records' AND COLUMN_NAME = :column"
            ),
            {"column": column},
        )
        if column_type is None or all(f"'{m.name}'" in column_type for m in AlertStatus):
            continue
        null_sql = "NULL" if nullable else "NOT NULL"
        await conn.execute(text(f"ALTER TABLE alert_records MODIFY COLUMN {column} ENUM({values}) {null_sql}"))


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
