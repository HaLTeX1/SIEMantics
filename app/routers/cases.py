from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.case_actions import CaseActionError, close_as_false_positive, close_group_as_false_positive, merge_alerts
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
from app.iris_client import iris_client
from app.schemas import (
    AssigneeOut,
    CaseAssignmentOut,
    CaseAssignRequest,
    FalsePositiveRequest,
    FalsePositiveResult,
    GroupFalsePositiveResult,
    MergeRequest,
    MergeResult,
)

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.get("/assignees", response_model=list[AssigneeOut], dependencies=[Depends(get_current_user)])
async def get_assignable_users(session: AsyncSession = Depends(get_session)):
    # Aktiv felhasznalok, akikhez eset rendelheto.
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

    # Analyst csak gazdatlan esetet vehet magahoz, vagy a sajatjat adhatja le.
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


@router.post("/merge", response_model=MergeResult)
async def merge_cases(
    body: MergeRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # Kijelolt riasztasok egy SIEMantics csoportba; nyitott IRIS eset eseten az is osszevonva.
    try:
        outcome = await merge_alerts(session, body.alert_refs, user)
    except CaseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    case_id = outcome.iris_case_id
    return MergeResult(
        iris_case_id=case_id,
        case_url=iris_client.case_url(case_id) if case_id else None,
        target=outcome.target.display_id,
        group=outcome.target.display_id,
        merged=[r.display_id for r in outcome.merged],
        closed_cases=outcome.closed_cases,
        close_failed=outcome.close_failed,
    )


@router.post("/{iris_case_id}/false-positive", response_model=FalsePositiveResult)
async def mark_case_false_positive(
    iris_case_id: int,
    body: FalsePositiveRequest | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # Az eset FP-kent lezarva az IRIS-ben, minden riasztasa FP cimket kap.
    try:
        records, closed = await close_as_false_positive(session, iris_case_id, user, body.reason if body else None)
    except CaseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return FalsePositiveResult(iris_case_id=iris_case_id, labeled=[r.display_id for r in records], iris_closed=closed)


@router.post("/groups/{alert_ref}/false-positive", response_model=GroupFalsePositiveResult)
async def mark_group_false_positive(
    alert_ref: str,
    body: FalsePositiveRequest | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # A riasztas csoportjanak minden tagja FP, a nyitott IRIS eseteik FP-kent lezarva.
    try:
        group, records, closed = await close_group_as_false_positive(
            session, alert_ref, user, body.reason if body else None
        )
    except CaseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return GroupFalsePositiveResult(group=group, labeled=[r.display_id for r in records], closed_cases=closed)
