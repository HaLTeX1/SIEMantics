from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import AlertRecord


def correlation_ip(raw: dict | None) -> str | None:
    # Csak a valodi forras IP szamit, az agent IP nem.
    return ((raw or {}).get("data") or {}).get("srcip") or None


def _rule(raw: dict | None) -> dict:
    return (raw or {}).get("rule") or {}


def base_techniques(raw: dict | None) -> set[str]:
    # Az altechnikat a fo technikara vezetjuk vissza, pl. T1110.001 -> T1110.
    ids = (_rule(raw).get("mitre") or {}).get("id") or []
    if not isinstance(ids, list):
        ids = [ids]
    return {str(tid).split(".")[0] for tid in ids if tid}


def is_similar(raw_a: dict | None, raw_b: dict | None) -> bool:
    rule_a, rule_b = _rule(raw_a).get("id"), _rule(raw_b).get("id")
    if rule_a and rule_a == rule_b:
        return True
    return bool(base_techniques(raw_a) & base_techniques(raw_b))


async def find_correlated_record(session: AsyncSession, record: AlertRecord) -> AlertRecord | None:
    # A legutobbi, IRIS esettel rendelkezo hasonlo riasztas ugyanarrol a forras IP-rol az idoablakon belul.
    ip = correlation_ip(record.raw_payload)
    if not ip or settings.correlation_window_hours <= 0:
        return None

    since = datetime.utcnow() - timedelta(hours=settings.correlation_window_hours)
    result = await session.execute(
        select(AlertRecord)
        .where(
            AlertRecord.source_ip == ip,
            AlertRecord.iris_case_id.is_not(None),
            AlertRecord.received_at >= since,
            AlertRecord.id != record.id,
        )
        .order_by(AlertRecord.received_at.desc())
    )
    for candidate in result.scalars():
        if correlation_ip(candidate.raw_payload) == ip and is_similar(record.raw_payload, candidate.raw_payload):
            return candidate
    return None
