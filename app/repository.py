from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import GroundTruth
from app.models import AlertRecord, CaseAssignment, User, UserSession


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


# --- Users / sessions ---

async def count_users(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(User))


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


async def get_user(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


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


async def create_user_session(session: AsyncSession, user: User, token_hash: str, expires_at: datetime) -> None:
    user.last_login_at = datetime.utcnow()
    session.add(UserSession(user_id=user.id, token_hash=token_hash, expires_at=expires_at))
    # opportunistic cleanup so the table doesn't grow forever
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


# --- Case assignments ---

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
    """iris_case_id -> (assignment, assignee) for the given cases that have an assignee."""
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
