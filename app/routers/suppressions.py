from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_suppress
from app.case_actions import CaseActionError, resolve_many
from app.db import get_session
from app.models import SuppressionRule, User
from app.repository import get_users_by_ids
from app.schemas import AssigneeOut, SuppressionRuleOut, SuppressRequest, SuppressResult
from app.suppression import SuppressionError, create_rules, deactivate_rule, list_rules

router = APIRouter(prefix="/api/v1/suppressions", tags=["suppressions"])


async def _out(session: AsyncSession, rules: list[SuppressionRule]) -> list[SuppressionRuleOut]:
    creators = await get_users_by_ids(session, [r.created_by_id for r in rules if r.created_by_id is not None])
    out = []
    for rule in rules:
        item = SuppressionRuleOut.model_validate(rule)
        if rule.created_by_id in creators:
            item.created_by = AssigneeOut.model_validate(creators[rule.created_by_id])
        out.append(item)
    return out


@router.get("", response_model=list[SuppressionRuleOut], dependencies=[Depends(get_current_user)])
async def get_rules(include_inactive: bool = False, session: AsyncSession = Depends(get_session)):
    return await _out(session, await list_rules(session, include_inactive))


@router.post("", response_model=SuppressResult)
async def suppress_alerts(
    body: SuppressRequest,
    user: User = Depends(require_suppress),
    session: AsyncSession = Depends(get_session),
):
    # A kijelolt riasztasokbol suppression szabaly; az egyezo uj riasztasok LLM nelkul elnyomva.
    try:
        records = await resolve_many(session, body.alert_refs)
        rules, suppressed = await create_rules(
            session,
            records,
            body.scope,
            user,
            reason=body.reason,
            duration_hours=body.duration_hours,
            apply_existing=body.apply_existing,
        )
    except (CaseActionError, SuppressionError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return SuppressResult(rules=await _out(session, rules), suppressed=[r.display_id for r in suppressed])


@router.delete("/{rule_id}", response_model=SuppressionRuleOut)
async def remove_rule(
    rule_id: int,
    user: User = Depends(require_suppress),
    session: AsyncSession = Depends(get_session),
):
    try:
        rule = await deactivate_rule(session, rule_id, user)
    except SuppressionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return (await _out(session, [rule]))[0]
