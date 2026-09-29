from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.enums import UserRole
from app.models import User
from app.repository import (
    case_exists,
    clear_case_assignee,
    get_case_assignment,
    get_user,
    list_active_users,
    set_case_assignee,
)
from app.schemas import AssigneeOut, CaseAssignmentOut, CaseAssignRequest

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.get("/assignees", response_model=list[AssigneeOut], dependencies=[Depends(get_current_user)])
async def get_assignable_users(session: AsyncSession = Depends(get_session)):
    """Active users a case can be assigned to (for the assignee dropdown)."""
    return await list_active_users(session)


@router.put("/{iris_case_id}/assignee", response_model=CaseAssignmentOut)
async def assign_case(
    iris_case_id: int,
    body: CaseAssignRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not await case_exists(session, iris_case_id):
        raise HTTPException(status_code=404, detail="case not found")

    current = await get_case_assignment(session, iris_case_id)
    current_user_id = current.user_id if current else None

    # Analysts may only take an unowned case for themselves, or release their own.
    if user.role != UserRole.ADMIN:
        taking = body.user_id == user.id and current_user_id in (None, user.id)
        releasing = body.user_id is None and current_user_id == user.id
        if not (taking or releasing):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="analysts can only take unassigned cases or release their own",
            )

    if body.user_id is None:
        await clear_case_assignee(session, iris_case_id)
        return CaseAssignmentOut(iris_case_id=iris_case_id)

    assignee = await get_user(session, body.user_id)
    if assignee is None or not assignee.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="assignee must be an active user")

    assignment = await set_case_assignee(session, iris_case_id, assignee.id, assigned_by_id=user.id)
    return CaseAssignmentOut(
        iris_case_id=iris_case_id,
        assignee=assignee,
        assigned_by=user,
        assigned_at=assignment.assigned_at,
    )
