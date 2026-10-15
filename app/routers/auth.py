from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    SESSION_COOKIE,
    check_credentials,
    end_session,
    get_current_user,
    hash_password,
    hash_token,
    start_session,
    verify_password,
)
from app.db import get_session
from app.login_guard import active_ban, clear_failures, client_ip, record_failure, retry_after_seconds
from app.models import User
from app.repository import delete_sessions_for_user, get_user_by_username, save_user
from app.schemas import LoginRequest, PasswordChangeRequest, UserOut

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _banned(ban) -> HTTPException:
    seconds = retry_after_seconds(ban)
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"too many failed logins from this address, try again in {max(seconds // 60, 1)} minute(s)",
        headers={"Retry-After": str(seconds)},
    )


@router.post("/login", response_model=UserOut)
async def login(
    body: LoginRequest, request: Request, response: Response, session: AsyncSession = Depends(get_session)
):
    # Kitiltott IP-rol a jelszot sem ellenorizzuk; tul sok hiba utan automatikus tiltas.
    ip = client_ip(request)
    ban = await active_ban(session, ip)
    if ban is not None:
        raise _banned(ban)
    user = await get_user_by_username(session, body.username.strip())
    if not check_credentials(user, body.password):
        ban = await record_failure(session, ip, body.username.strip())
        if ban is not None:
            raise _banned(ban)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password")
    await clear_failures(session, ip)
    await start_session(session, response, user)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, session: AsyncSession = Depends(get_session)):
    await end_session(session, request, response)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return user


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_own_password(
    body: PasswordChangeRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    await save_user(session, user)
    # A tobbi eszkozon kijelentkeztet, a mostani munkamenet marad.
    await delete_sessions_for_user(session, user.id, keep_token_hash=hash_token(request.cookies[SESSION_COOKIE]))
