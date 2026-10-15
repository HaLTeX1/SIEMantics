from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.enums import AlertStatus
from app.models import AlertRecord


def join_group(record: AlertRecord, anchor: AlertRecord) -> None:
    # A rekord az anchor csoportjaba kerul; csoport nelkuli anchor sajat csoportot nyit.
    group_id = anchor.group_id or anchor.id
    anchor.group_id = group_id
    record.group_id = group_id


def _has_case():
    return AlertRecord.iris_case_id.is_not(None)


def _not_closed(exclude_cases):
    # Lezart eset riasztasa nem lehet korrelacios / csoport anchor: ott mar senki nem nezi.
    conditions = [AlertRecord.case_closed_at.is_(None)]
    if exclude_cases:
        conditions.append(or_(AlertRecord.iris_case_id.is_(None), AlertRecord.iris_case_id.notin_(exclude_cases)))
    return conditions


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


def correlation_host(raw: dict | None) -> str | None:
    # Az agent neve, a manager (000) kivetelevel: azon fut minden tuzfal/felho integracio.
    agent = (raw or {}).get("agent") or {}
    if agent.get("id") == "000":
        return None
    return agent.get("name") or None


async def find_correlated_record(
    session: AsyncSession, record: AlertRecord, *, require_case: bool = True, exclude_cases: set[int] = frozenset()
) -> AlertRecord | None:
    # IP-vel: hasonlo riasztas az ablakban; IP nelkul: a host rovid idon beluli riasztasa.
    # require_case=False: csoportositashoz, IRIS eset nelkuli riasztas is jo; lezart eset soha.
    ip = correlation_ip(record.raw_payload)
    if not ip:
        return await _find_same_host_record(session, record, require_case, exclude_cases)
    if settings.correlation_window_hours <= 0:
        return None

    since = datetime.utcnow() - timedelta(hours=settings.correlation_window_hours)
    result = await session.execute(
        select(AlertRecord)
        .where(
            AlertRecord.source_ip == ip,
            _has_case() if require_case else AlertRecord.status != AlertStatus.QUEUED,
            AlertRecord.received_at >= since,
            AlertRecord.id != record.id,
            *_not_closed(exclude_cases),
        )
        .order_by(AlertRecord.received_at.desc())
    )
    for candidate in result.scalars():
        if correlation_ip(candidate.raw_payload) == ip and is_similar(record.raw_payload, candidate.raw_payload):
            return candidate
    return None


async def _find_same_host_record(
    session: AsyncSession, record: AlertRecord, require_case: bool, exclude_cases: set[int]
) -> AlertRecord | None:
    # A legutobbi riasztas ugyanarrol a hostrol a +-ablakban (require_case eseten IRIS esettel).
    host = correlation_host(record.raw_payload)
    if not host or settings.correlation_host_window_minutes <= 0:
        return None
    window = timedelta(minutes=settings.correlation_host_window_minutes)
    received = record.received_at or datetime.utcnow()
    result = await session.execute(
        select(AlertRecord)
        .where(
            AlertRecord.agent_name == host,
            _has_case() if require_case else AlertRecord.status != AlertStatus.QUEUED,
            AlertRecord.received_at >= received - window,
            AlertRecord.received_at <= received + window,
            AlertRecord.id != record.id,
            *_not_closed(exclude_cases),
        )
        .order_by(AlertRecord.received_at.desc())
    )
    for candidate in result.scalars():
        if correlation_host(candidate.raw_payload) == host:
            return candidate
    return None
