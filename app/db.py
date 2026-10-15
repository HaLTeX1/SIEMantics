import asyncio
import logging

from sqlalchemy import inspect, select, text, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings
from app.enums import AlertStatus, UserRole

logger = logging.getLogger("siemantics.db")


engine = create_async_engine(settings.database_url, echo=False, pool_recycle=3600)
async_session = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db(attempts: int = 30, delay: float = 2.0) -> None:
    # Megvarjuk, mig elindul az adatbazis (pl. lassan indulo db kontener).
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
        await conn.run_sync(_backfill_rule_ids)
        if conn.dialect.name == "mysql":
            await _sync_alert_status_enums(conn)
            await _sync_enum_column(conn, "users", "role", UserRole, nullable=False)


def _add_missing_columns(conn) -> None:
    # Kesobb hozzaadott nullable oszlopok felvetele meglevo tablakba (create_all nem modosit).

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


def _backfill_rule_ids(conn) -> None:
    # A rule_id oszlop elotti rekordok kitoltese a raw_payload-bol.
    table = Base.metadata.tables["alert_records"]
    rows = conn.execute(
        select(table.c.id, table.c.raw_payload).where(table.c.rule_id.is_(None), table.c.raw_payload.is_not(None))
    ).all()
    for row_id, raw in rows:
        rule_id = ((raw or {}).get("rule") or {}).get("id")
        if rule_id:
            conn.execute(update(table).where(table.c.id == row_id).values(rule_id=str(rule_id)))


async def _sync_alert_status_enums(conn) -> None:
    # MariaDB-n az uj AlertStatus ertekek felvetele a nativ ENUM oszlopokba.
    for column, nullable in (("status", False), ("auto_status", True)):
        await _sync_enum_column(conn, "alert_records", column, AlertStatus, nullable)


async def _sync_enum_column(conn, table: str, column: str, enum_cls, nullable: bool) -> None:
    # Hianyzo enum ertekek felvetele egy nativ ENUM oszlopba (create_all nem modosit).
    column_type = await conn.scalar(
        text(
            "SELECT COLUMN_TYPE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table AND COLUMN_NAME = :column"
        ),
        {"table": table, "column": column},
    )
    if column_type is None or all(f"'{m.name}'" in column_type for m in enum_cls):
        return
    values = ", ".join(f"'{m.name}'" for m in enum_cls)
    null_sql = "NULL" if nullable else "NOT NULL"
    await conn.execute(text(f"ALTER TABLE {table} MODIFY COLUMN {column} ENUM({values}) {null_sql}"))


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
