# Jelszo hash, cookie-s munkamenetek es a FastAPI auth dependency-k.

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import async_session, get_session
from app.enums import UserRole
from app.models import User
from app.repository import (
    count_users,
    create_user,
    create_user_session,
    delete_user_session,
    get_user_by_session_token_hash,
)

logger = logging.getLogger("siemantics.auth")

SESSION_COOKIE = "siemantics_session"

# scrypt parameterek (~16 MB memoria hash-enkent), csak stdlib.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


# Ismeretlen felhasznalonal is ugyanannyi ido, mint rossz jelszonal (timing ellen).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def check_credentials(user: User | None, password: str) -> bool:
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return False
    return user.is_active and verify_password(password, user.password_hash)


async def start_session(session: AsyncSession, response: Response, user: User) -> None:
    token = secrets.token_urlsafe(32)
    ttl = timedelta(hours=settings.session_ttl_hours)
    await create_user_session(session, user, token_hash=hash_token(token), expires_at=datetime.utcnow() + ttl)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


async def end_session(session: AsyncSession, request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await delete_user_session(session, hash_token(token))
    response.delete_cookie(SESSION_COOKIE, path="/")


async def get_current_user(request: Request, session: AsyncSession = Depends(get_session)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    user = await get_user_by_session_token_hash(session, hash_token(token)) if token else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return user


async def require_suppress(user: User = Depends(get_current_user)) -> User:
    if not user.can_suppress:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="L2 role required for suppression rules")
    return user


async def require_block_ip(user: User = Depends(get_current_user)) -> User:
    if not user.can_block_ip:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="L2 role or response permission required for response actions")
    return user


async def ensure_initial_admin() -> None:
    # Elso admin az ADMIN_USERNAME/ADMIN_PASSWORD alapjan, ha meg nincs felhasznalo.
    async with async_session() as session:
        if await count_users(session) > 0:
            return
        if not settings.admin_password:
            logger.warning(
                "no users exist and ADMIN_PASSWORD is not set - set it in .env and restart to create the first admin"
            )
            return
        await create_user(
            session,
            username=settings.admin_username,
            full_name="Administrator",
            password_hash=hash_password(settings.admin_password),
            role=UserRole.ADMIN,
        )
        logger.info("created initial admin user %r", settings.admin_username)
