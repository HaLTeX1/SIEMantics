from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, require_admin
from app.db import get_session
from app.enums import UserRole
from app.models import User
from app.repository import create_user, delete_sessions_for_user, get_user, get_user_by_username, list_users, save_user
from app.schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/api/v1/users", tags=["users"], dependencies=[Depends(require_admin)])


@router.get("", response_model=list[UserOut])
async def get_users(session: AsyncSession = Depends(get_session)):
    return await list_users(session)


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def add_user(body: UserCreate, session: AsyncSession = Depends(get_session)):
    if await get_user_by_username(session, body.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already exists")
    return await create_user(
        session,
        username=body.username,
        full_name=body.full_name,
        password_hash=hash_password(body.password),
        role=body.role,
    )


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    body: UserUpdate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    user = await get_user(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    # Az admin nem zarhatja ki magat az admin panelbol.
    if user.id == admin.id and (body.is_active is False or (body.role is not None and body.role != UserRole.ADMIN)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot deactivate or demote yourself")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    await save_user(session, user)

    if body.is_active is False or body.password is not None:
        await delete_sessions_for_user(session, user.id)
    return user
