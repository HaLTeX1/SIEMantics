from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db import get_session
from app.models import IpBan, User
from app.repository import get_users_by_ids

router = APIRouter(prefix="/api/v1/security", tags=["security"])


def _out(ban: IpBan, users: dict, now: datetime) -> dict:
    lifted_by = users.get(ban.lifted_by_id)
    return {
        "id": ban.id, "ip": ban.ip, "reason": ban.reason, "failures": ban.failures, "usernames": ban.usernames or [],
        "created_at": ban.created_at, "until": ban.until, "lifted_at": ban.lifted_at,
        "lifted_by": lifted_by.username if lifted_by else None,
        "active": ban.lifted_at is None and ban.until > now,
    }


@router.get("/bans", dependencies=[Depends(require_admin)])
async def list_bans(active_only: bool = True, session: AsyncSession = Depends(get_session)):
    # Az automatikus belepesi tiltasok; active_only=false: az elmult 30 nap elozmenyei is.
    now = datetime.utcnow()
    stmt = select(IpBan).order_by(IpBan.created_at.desc())
    if active_only:
        stmt = stmt.where(IpBan.until > now, IpBan.lifted_at.is_(None))
    else:
        stmt = stmt.where(IpBan.created_at >= now - timedelta(days=30))
    bans = list((await session.execute(stmt.limit(500))).scalars())
    users = await get_users_by_ids(session, [b.lifted_by_id for b in bans if b.lifted_by_id])
    return [_out(b, users, now) for b in bans]


@router.delete("/bans/{ban_id}")
async def lift_ban(ban_id: int, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_session)):
    ban = await session.get(IpBan, ban_id)
    if ban is None:
        raise HTTPException(status_code=404, detail="ban not found")
    now = datetime.utcnow()
    if ban.lifted_at is None and ban.until > now:
        ban.lifted_at = now
        ban.lifted_by_id = admin.id
        await session.commit()
    return _out(ban, {admin.id: admin}, now)
