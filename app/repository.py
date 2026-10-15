import re
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import GroundTruth
from app.db import Base
from app.models import AlertRecord, CaseAssignment, User, UserSession


async def create_alert_record(session: AsyncSession, **fields) -> AlertRecord:
    record = AlertRecord(**fields)
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


def closed_condition():
    # Lezart: az IRIS esete lezarult, vagy eset nelkul mar elemzoi itelete van (nyitott esetnel meg folyik a munka).
    return or_(
        AlertRecord.case_closed_at.is_not(None),
        and_(AlertRecord.iris_case_id.is_(None), AlertRecord.ground_truth.is_not(None)),
    )


async def list_alert_records(
    session: AsyncSession, limit: int = 100, offset: int = 0, include_closed: bool = True
) -> list[AlertRecord]:
    stmt = select(AlertRecord)
    if not include_closed:
        stmt = stmt.where(~closed_condition())
    result = await session.execute(stmt.order_by(AlertRecord.received_at.desc()).limit(limit).offset(offset))
    return list(result.scalars().all())


async def list_all_records(session: AsyncSession) -> list[AlertRecord]:
    result = await session.execute(select(AlertRecord))
    return list(result.scalars().all())


async def get_latest_alert_record(session: AsyncSession, alert_id: str) -> AlertRecord | None:
    result = await session.execute(
        select(AlertRecord).where(AlertRecord.alert_id == alert_id).order_by(AlertRecord.received_at.desc())
    )
    return result.scalars().first()


_DISPLAY_ID_RE = re.compile(r"#?ID-(\d+)", re.IGNORECASE)


async def get_alert_record_by_ref(session: AsyncSession, ref: str) -> AlertRecord | None:
    # ID-42 / #ID-42, vagy Wazuh alert_id (nem egyedi, ezert a legutobbi).
    match = _DISPLAY_ID_RE.fullmatch(ref.strip())
    if match:
        return await session.get(AlertRecord, int(match.group(1)))
    return await get_latest_alert_record(session, ref)


async def get_alert_records_by_refs(session: AsyncSession, refs: list[str]) -> tuple[list[AlertRecord], list[str]]:
    # (talalt rekordok egyszer, nem talalt hivatkozasok); ID-N egy IN lekerdezessel.
    ids: dict[int, str] = {}
    others: list[str] = []
    for ref in refs:
        match = _DISPLAY_ID_RE.fullmatch(ref.strip())
        if match:
            ids[int(match.group(1))] = ref
        else:
            others.append(ref)
    found: dict[int, AlertRecord] = {}
    for start in range(0, len(ids), 500):
        chunk = list(ids)[start:start + 500]
        result = await session.execute(select(AlertRecord).where(AlertRecord.id.in_(chunk)))
        found.update((r.id, r) for r in result.scalars())
    missing = [ref for record_id, ref in ids.items() if record_id not in found]
    for ref in others:
        record = await get_latest_alert_record(session, ref)
        if record is None:
            missing.append(ref)
        else:
            found[record.id] = record
    return sorted(found.values(), key=lambda r: r.received_at), missing


async def find_related_alerts(
    session: AsyncSession,
    *,
    agent_name: str | None,
    source_ip: str | None,
    around: datetime,
    before: timedelta,
    after: timedelta = timedelta(0),
    exclude_id: int | None = None,
    limit: int = 10,
) -> list[AlertRecord]:
    # Riasztasok ugyanarrol a hostrol vagy IP-rol az idoablakban, legujabb elol.
    conditions = []
    if agent_name:
        conditions.append(AlertRecord.agent_name == agent_name)
    if source_ip:
        conditions.append(AlertRecord.source_ip == source_ip)
    if not conditions:
        return []
    stmt = select(AlertRecord).where(
        or_(*conditions),
        AlertRecord.received_at >= around - before,
        AlertRecord.received_at <= around + after,
    )
    if exclude_id is not None:
        stmt = stmt.where(AlertRecord.id != exclude_id)
    result = await session.execute(stmt.order_by(AlertRecord.received_at.desc()).limit(limit))
    return list(result.scalars().all())


async def get_records_in_cases(session: AsyncSession, iris_case_ids: set[int]) -> list[AlertRecord]:
    if not iris_case_ids:
        return []
    result = await session.execute(
        select(AlertRecord).where(AlertRecord.iris_case_id.in_(iris_case_ids)).order_by(AlertRecord.received_at)
    )
    return list(result.scalars().all())


async def get_group_members(session: AsyncSession, group_ids: set[int]) -> list[AlertRecord]:
    if not group_ids:
        return []
    result = await session.execute(
        select(AlertRecord).where(AlertRecord.group_id.in_(group_ids)).order_by(AlertRecord.received_at)
    )
    return list(result.scalars().all())


async def count_group_members(session: AsyncSession, group_ids: set[int]) -> dict[int, int]:
    if not group_ids:
        return {}
    result = await session.execute(
        select(AlertRecord.group_id, func.count()).where(AlertRecord.group_id.in_(group_ids)).group_by(AlertRecord.group_id)
    )
    return dict(result.all())


async def save_alert_record(session: AsyncSession, record: AlertRecord) -> AlertRecord:
    await session.commit()
    await session.refresh(record)
    return record


async def set_ground_truth(session: AsyncSession, ref: str, ground_truth: GroundTruth) -> AlertRecord | None:
    record = await get_alert_record_by_ref(session, ref)
    if record is None:
        return None
    record.ground_truth = ground_truth
    record.labeled_at = datetime.utcnow()
    await session.commit()
    await session.refresh(record)
    return record


# --- Felhasznalok / munkamenetek ---

async def count_users(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(User))


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


async def get_user(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def get_users_by_ids(session: AsyncSession, user_ids: list[int]) -> dict[int, User]:
    if not user_ids:
        return {}
    result = await session.execute(select(User).where(User.id.in_(set(user_ids))))
    return {user.id: user for user in result.scalars().all()}


async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    return result.scalars().first()


async def create_user(session: AsyncSession, **fields) -> User:
    user = User(**fields)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def save_user(session: AsyncSession, user: User) -> User:
    await session.commit()
    await session.refresh(user)
    return user


async def delete_user(session: AsyncSession, user: User) -> list[int]:
    # Vegleges torles; az esetei felelos nelkuliek lesznek, a naplo-hivatkozasok NULL-ra allnak.
    released = list(await session.scalars(select(CaseAssignment.iris_case_id).where(CaseAssignment.user_id == user.id)))
    await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
    await session.execute(delete(CaseAssignment).where(CaseAssignment.user_id == user.id))
    # Minden users.id-re mutato, nullable hivatkozas NULL-ra, igy egy kesobbi uj tabla sem akasztja meg (MariaDB FK).
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if column.nullable and any(fk.column.table.name == "users" for fk in column.foreign_keys):
                await session.execute(update(table).where(column == user.id).values({column.name: None}))
    await session.delete(user)
    await session.commit()
    return sorted(released)


async def create_user_session(session: AsyncSession, user: User, token_hash: str, expires_at: datetime) -> None:
    user.last_login_at = datetime.utcnow()
    session.add(UserSession(user_id=user.id, token_hash=token_hash, expires_at=expires_at))
    # Lejart munkamenetek torlese, hogy ne gyuljenek fel.
    await session.execute(delete(UserSession).where(UserSession.expires_at < datetime.utcnow()))
    await session.commit()


async def get_user_by_session_token_hash(session: AsyncSession, token_hash: str) -> User | None:
    result = await session.execute(
        select(User)
        .join(UserSession, UserSession.user_id == User.id)
        .where(
            UserSession.token_hash == token_hash,
            UserSession.expires_at > datetime.utcnow(),
            User.is_active.is_(True),
        )
    )
    return result.scalars().first()


async def delete_user_session(session: AsyncSession, token_hash: str) -> None:
    await session.execute(delete(UserSession).where(UserSession.token_hash == token_hash))
    await session.commit()


async def delete_sessions_for_user(session: AsyncSession, user_id: int, keep_token_hash: str | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if keep_token_hash is not None:
        stmt = stmt.where(UserSession.token_hash != keep_token_hash)
    await session.execute(stmt)
    await session.commit()


# --- Eset felelosok (DFIR-IRIS) ---

async def case_exists(session: AsyncSession, iris_case_id: int) -> bool:
    result = await session.execute(select(AlertRecord.id).where(AlertRecord.iris_case_id == iris_case_id).limit(1))
    return result.first() is not None


async def list_active_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).where(User.is_active.is_(True)).order_by(User.username))
    return list(result.scalars().all())


async def get_case_assignment(session: AsyncSession, iris_case_id: int) -> CaseAssignment | None:
    result = await session.execute(select(CaseAssignment).where(CaseAssignment.iris_case_id == iris_case_id))
    return result.scalars().first()


async def get_case_assignments(
    session: AsyncSession, iris_case_ids: list[int]
) -> dict[int, tuple[CaseAssignment, User]]:
    # iris_case_id -> (hozzarendeles, felelos) a felelossel rendelkezo esetekre.
    if not iris_case_ids:
        return {}
    result = await session.execute(
        select(CaseAssignment, User)
        .join(User, User.id == CaseAssignment.user_id)
        .where(CaseAssignment.iris_case_id.in_(set(iris_case_ids)))
    )
    return {assignment.iris_case_id: (assignment, user) for assignment, user in result.all()}


async def set_case_assignee(
    session: AsyncSession, iris_case_id: int, user_id: int, assigned_by_id: int
) -> CaseAssignment:
    assignment = await get_case_assignment(session, iris_case_id)
    if assignment is None:
        assignment = CaseAssignment(iris_case_id=iris_case_id)
        session.add(assignment)
    assignment.user_id = user_id
    assignment.assigned_by_id = assigned_by_id
    assignment.assigned_at = datetime.utcnow()
    await session.commit()
    await session.refresh(assignment)
    return assignment


async def clear_case_assignee(session: AsyncSession, iris_case_id: int) -> None:
    await session.execute(delete(CaseAssignment).where(CaseAssignment.iris_case_id == iris_case_id))
    await session.commit()
