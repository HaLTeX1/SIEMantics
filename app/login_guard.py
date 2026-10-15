# Automatikus IP tiltas sikertelen belepesek utan; a valodi kliens IP csak megbizhato proxy fejlecebol.

import ipaddress
import logging
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import status
from app.config import settings
from app.models import IpBan, LoginFailure

logger = logging.getLogger("siemantics.login_guard")

_FORWARDED_HEADERS = ("cf-connecting-ip", "x-forwarded-for")


def _networks(setting: str) -> list:
    out = []
    for entry in setting.split(","):
        try:
            out.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            continue
    return out


def _in(ip: str, setting: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address.version == net.version and address in net for net in _networks(setting))


def is_trusted_proxy(ip: str) -> bool:
    return _in(ip, settings.trusted_proxy_ips)


def client_ip(request: Request) -> str:
    # A kozvetlen kapcsolat IP-je; megbizhato proxytol (pl. cloudflared) a fejlecben kuldott valodi IP.
    peer = request.client.host if request.client else "unknown"
    forwarded = next((request.headers[h] for h in _FORWARDED_HEADERS if request.headers.get(h)), None)
    if not forwarded:
        return peer
    candidate = forwarded.split(",")[0].strip()
    if not is_trusted_proxy(peer):
        # Hamisithato fejlec nem megbizhato forrastol: a kapcsolat IP-je szamit.
        status.record_failure("login_proxy", f"forwarded IP header from untrusted peer {peer}; set TRUSTED_PROXY_IPS")
        return peer
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


async def active_ban(session: AsyncSession, ip: str) -> IpBan | None:
    now = datetime.utcnow()
    result = await session.execute(
        select(IpBan).where(IpBan.ip == ip, IpBan.until > now, IpBan.lifted_at.is_(None)).order_by(IpBan.until.desc())
    )
    return result.scalars().first()


async def record_failure(session: AsyncSession, ip: str, username: str | None) -> IpBan | None:
    # Eltarolja a hibat; kuszob felett tiltas (visszaesonel duplazodo hosszal). A tiltast adja vissza.
    now = datetime.utcnow()
    session.add(LoginFailure(ip=ip, username=(username or "")[:128] or None, attempted_at=now))
    await session.execute(delete(LoginFailure).where(LoginFailure.attempted_at < now - timedelta(days=1)))
    await session.flush()
    if settings.login_max_failures <= 0 or _in(ip, settings.login_ban_exempt) or is_trusted_proxy(ip):
        await session.commit()
        return None

    since = now - timedelta(minutes=settings.login_failure_window_minutes)
    window = (await session.execute(
        select(LoginFailure.username).where(LoginFailure.ip == ip, LoginFailure.attempted_at >= since)
    )).scalars().all()
    if len(window) < settings.login_max_failures:
        await session.commit()
        return None

    previous = await session.scalar(
        select(func.count()).select_from(IpBan).where(IpBan.ip == ip, IpBan.created_at >= now - timedelta(days=1))
    )
    minutes = min(settings.login_ban_minutes * 2 ** previous, settings.login_ban_max_minutes)
    ban = IpBan(
        ip=ip,
        reason=f"{len(window)} failed logins within {settings.login_failure_window_minutes} min",
        failures=len(window),
        usernames=sorted({u for u in window if u})[:20] or None,
        created_at=now,
        until=now + timedelta(minutes=minutes),
    )
    session.add(ban)
    # A tiltas utan ujraindul a szamlalo.
    await session.execute(delete(LoginFailure).where(LoginFailure.ip == ip))
    await session.commit()
    logger.warning("login: %s banned for %d min after %d failed logins (users: %s)", ip, minutes, len(window),
                   ", ".join(ban.usernames or []))
    return ban


async def clear_failures(session: AsyncSession, ip: str) -> None:
    await session.execute(delete(LoginFailure).where(LoginFailure.ip == ip))
    await session.commit()


def retry_after_seconds(ban: IpBan) -> int:
    return max(int((ban.until - datetime.utcnow()).total_seconds()), 1)
