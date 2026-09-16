from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import GroundTruth
from app.models import AlertRecord


async def create_alert_record(session: AsyncSession, **fields) -> AlertRecord:
    record = AlertRecord(**fields)
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


async def list_alert_records(session: AsyncSession, limit: int = 100, offset: int = 0) -> list[AlertRecord]:
    result = await session.execute(
        select(AlertRecord).order_by(AlertRecord.received_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


async def list_all_records(session: AsyncSession) -> list[AlertRecord]:
    result = await session.execute(select(AlertRecord))
    return list(result.scalars().all())


async def get_latest_alert_record(session: AsyncSession, alert_id: str) -> AlertRecord | None:
    result = await session.execute(
        select(AlertRecord).where(AlertRecord.alert_id == alert_id).order_by(AlertRecord.received_at.desc())
    )
    return result.scalars().first()


async def set_ground_truth(session: AsyncSession, alert_id: str, ground_truth: GroundTruth) -> AlertRecord | None:
    record = await get_latest_alert_record(session, alert_id)
    if record is None:
        return None
    record.ground_truth = ground_truth
    record.labeled_at = datetime.utcnow()
    await session.commit()
    await session.refresh(record)
    return record
