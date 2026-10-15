import logging

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_admin, require_block_ip
from app.case_actions import CaseActionError, close_alerts_as_false_positive, delete_alerts
from app.config import settings
from app.db import get_session
from app.enums import AlertStatus
from app.fingerprint import alert_fingerprint
from app.normalize import normalize_wazuh_alert
from app.models import AlertRecord, User
from app.pipeline import alert_from_record, alert_queue, manual_escalate, process_record
from app.response import ResponseError, block_ip, list_actions
from app.surrounding import fetch_surrounding, indexer_client
from app.wazuh_client import wazuh_client
from app.repository import (
    count_group_members,
    create_alert_record,
    get_alert_record_by_ref,
    get_case_assignments,
    get_users_by_ids,
    list_alert_records,
    set_ground_truth,
)
from app.schemas import (
    AlertRecordOut,
    AssigneeOut,
    BlockIpRequest,
    BulkDeleteResult,
    BulkFalsePositiveResult,
    BulkRequest,
    LabelRequest,
    NormalizedAlert,
    ResponseActionOut,
    WazuhAlertPayload,
)

logger = logging.getLogger("siemantics.alerts")

router = APIRouter(prefix="/api/v1", tags=["alerts"])

# Ignoralt szabalycsoport miatt eldobott riasztasok szama indulas ota (/healthz).
ignored_counter = {"count": 0}

# Folyamatban levo kezi eszkalaciok, dupla kattintas ellen.
_escalations_in_progress: set[int] = set()


def _verify_token(x_webhook_token: str | None) -> None:
    if settings.wazuh_webhook_token and x_webhook_token != settings.wazuh_webhook_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")


def _matching_group(payload: WazuhAlertPayload, setting: str) -> str | None:
    groups = {g.strip().lower() for g in setting.split(",") if g.strip()}
    return next((g for g in payload.rule.groups if str(g).lower() in groups), None)


def _ignored_group(payload: WazuhAlertPayload) -> str | None:
    return _matching_group(payload, settings.ignored_rule_groups)


async def _with_assignees(session: AsyncSession, records: list[AlertRecord]) -> list[AlertRecordOut]:
    assignments = await get_case_assignments(session, [r.iris_case_id for r in records if r.iris_case_id is not None])
    escalators = await get_users_by_ids(session, [r.escalated_by_id for r in records if r.escalated_by_id is not None])
    group_sizes = await count_group_members(session, {r.group_id for r in records if r.group_id})
    out = []
    for record in records:
        item = AlertRecordOut.model_validate(record)
        if record.iris_case_id in assignments:
            assignment, assignee = assignments[record.iris_case_id]
            item.assignee = AssigneeOut.model_validate(assignee)
            item.assigned_at = assignment.assigned_at
        if record.escalated_by_id in escalators:
            item.escalated_by = AssigneeOut.model_validate(escalators[record.escalated_by_id])
        item.group_size = group_sizes.get(record.group_id)
        out.append(item)
    return out


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED)
async def receive_alert(
    payload: WazuhAlertPayload,
    wait: bool = False,
    x_webhook_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    # Eltarolja es sorba allitja a riasztast; ?wait=true eseten azonnal triazsol (teszteleshez).
    _verify_token(x_webhook_token)

    group = _ignored_group(payload)
    if group is not None:
        # Pl. SCA benchmark: nem tarolodik, nem megy LLM-hez, nem nyit esetet.
        ignored_counter["count"] += 1
        logger.debug("alert %s ignored (rule %s, group %s)", payload.id, payload.rule.id, group)
        return {"status": "ignored", "alert_id": payload.id, "reason": f"rule group '{group}' is ignored"}

    alert: NormalizedAlert = normalize_wazuh_alert(payload)
    context_group = _matching_group(payload, settings.context_rule_groups)
    record = await create_alert_record(
        session,
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        agent_name=alert.agent_name,
        rule_description=alert.rule_description,
        severity=alert.severity,
        raw_payload=payload.model_dump(mode="json"),
        fingerprint=alert_fingerprint(payload.model_dump(mode="json")),
        rule_id=payload.rule.id,
        status=AlertStatus.SUPPRESSED if context_group else AlertStatus.QUEUED,
        # Kontextus esemeny (pl. csomagtelepites): a tobbi riasztas triazsahoz kell, onmagaban nem.
        triage_engine="context" if context_group else None,
        review_reason=f"context event (rule group '{context_group}'), not triaged" if context_group else None,
        processing_time_ms=0.0,
    )
    if context_group:
        logger.info("alert %s stored as context (%s) as %s", alert.alert_id, context_group, record.display_id)
        return {"status": "context", "id": record.display_id, "alert_id": alert.alert_id, "record_id": record.id}
    if wait:
        return await _process_now(session, record)

    alert_queue.enqueue(record.id)
    logger.info("alert %s queued as %s", alert.alert_id, record.display_id)
    return {
        "status": AlertStatus.QUEUED.value,
        "id": record.display_id,
        "alert_id": alert.alert_id,
        "record_id": record.id,
    }


async def _process_now(session: AsyncSession, record: AlertRecord) -> dict:
    outcome = await process_record(session, record)
    if outcome.deferred:
        alert_queue.handle_outcome(record.id, outcome)
        raise HTTPException(status_code=503, detail="LLM unavailable, the alert stays queued and is retried later")
    if outcome.triage is None:
        raise HTTPException(status_code=502, detail="triage failed unexpectedly")
    if record.status == AlertStatus.ERROR:
        raise HTTPException(status_code=502, detail="incident management backend unavailable")
    return {
        "status": record.status.value,
        "id": record.display_id,
        "alert_id": record.alert_id,
        "record_id": record.id,
        "review_reason": record.review_reason,
        "triage": outcome.triage,
        "case": outcome.case,
        "correlated_with": outcome.correlated.display_id if outcome.correlated else None,
    }


@router.get("/alerts", response_model=list[AlertRecordOut], dependencies=[Depends(get_current_user)])
async def list_alerts(
    limit: int = 100, offset: int = 0, include_closed: bool = True, session: AsyncSession = Depends(get_session)
):
    # include_closed=false: lezartak es elnyomottak nelkul (a dashboard alapnezete).
    records = await list_alert_records(session, limit=limit, offset=offset, include_closed=include_closed)
    return await _with_assignees(session, records)


@router.get("/alerts/{alert_ref}", response_model=AlertRecordOut, dependencies=[Depends(get_current_user)])
async def get_alert(alert_ref: str, session: AsyncSession = Depends(get_session)):
    # alert_ref: ID-42, vagy Wazuh alert_id (a legutobbi rekord).
    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return (await _with_assignees(session, [record]))[0]


@router.get("/config", dependencies=[Depends(get_current_user)])
async def get_public_config():
    # Nem titkos beallitasok a frontendnek (pl. IRIS link).
    return {"iris_base_url": settings.iris_base_url.rstrip("/"), "response_enabled": wazuh_client.enabled}


@router.patch("/alerts/{alert_ref}/label", response_model=AlertRecordOut, dependencies=[Depends(get_current_user)])
async def label_alert(alert_ref: str, body: LabelRequest, session: AsyncSession = Depends(get_session)):
    record = await set_ground_truth(session, alert_ref, body.ground_truth)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return (await _with_assignees(session, [record]))[0]


@router.post("/alerts/{alert_ref}/escalate", response_model=AlertRecordOut)
async def escalate_alert(
    alert_ref: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # Kezi eszkalacio IRIS esette; az automatikus dontes az auto_status-ban marad.

    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    if record.iris_case_id is not None or record.status == AlertStatus.ESCALATED:
        raise HTTPException(status_code=409, detail="alert already escalated")
    if record.status == AlertStatus.QUEUED:
        raise HTTPException(status_code=409, detail="alert is still waiting for automatic triage")
    if record.id in _escalations_in_progress:
        raise HTTPException(status_code=409, detail="escalation already in progress")

    _escalations_in_progress.add(record.id)
    try:
        await manual_escalate(session, record, user)
    except Exception as exc:
        logger.exception("manual escalation of %s failed", record.display_id)
        raise HTTPException(status_code=502, detail="incident management backend unavailable") from exc
    finally:
        _escalations_in_progress.discard(record.id)

    return (await _with_assignees(session, [record]))[0]


@router.post("/alerts/bulk/false-positive", response_model=BulkFalsePositiveResult)
async def bulk_false_positive(
    body: BulkRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # Flood: a kijelolt riasztasok FP cimket kapnak, a nyitott IRIS eseteik FP-kent lezarva.
    try:
        records, closed = await close_alerts_as_false_positive(session, body.alert_refs, user, body.reason)
    except CaseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return BulkFalsePositiveResult(labeled=[r.display_id for r in records], closed_cases=closed)


@router.post("/alerts/bulk/delete", response_model=BulkDeleteResult)
async def bulk_delete(
    body: BulkRequest,
    user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    # Csak admin; vegleges torles a SIEMantics adatbazisbol, az IRIS esetek maradnak.
    try:
        deleted = await delete_alerts(session, body.alert_refs, user)
    except CaseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return BulkDeleteResult(deleted=deleted)


async def _actions_out(session: AsyncSession, actions) -> list[ResponseActionOut]:
    users = await get_users_by_ids(session, [a.requested_by_id for a in actions if a.requested_by_id is not None])
    out = []
    for action in actions:
        item = ResponseActionOut.model_validate(action)
        if action.requested_by_id in users:
            item.requested_by = AssigneeOut.model_validate(users[action.requested_by_id])
        out.append(item)
    return out


@router.post("/alerts/{alert_ref}/block-ip", response_model=ResponseActionOut)
async def block_alert_ip(
    alert_ref: str,
    body: BlockIpRequest,
    user: User = Depends(require_block_ip),
    session: AsyncSession = Depends(get_session),
):
    # L2 vagy kulon engedely: IP blokkolas Wazuh Active Response-szal, lejarattal; IRIS note az esetbe.
    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    try:
        action = await block_ip(session, record, body.ip, body.scope, body.duration_hours * 3600, user)
    except ResponseError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return (await _actions_out(session, [action]))[0]


@router.get("/alerts/{alert_ref}/responses", response_model=list[ResponseActionOut],
            dependencies=[Depends(get_current_user)])
async def get_alert_responses(alert_ref: str, session: AsyncSession = Depends(get_session)):
    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return await _actions_out(session, await list_actions(session, record))


@router.get("/alerts/{alert_ref}/surrounding", dependencies=[Depends(get_current_user)])
async def get_surrounding_events(alert_ref: str, minutes: int = 15, session: AsyncSession = Depends(get_session)):
    # A riasztas koruli esemenyek a Wazuh indexerbol idorendben, a riasztas sajat helyevel (this_alert).
    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    minutes = max(1, min(minutes, 120))
    if not indexer_client.enabled:
        return {"enabled": False, "window_minutes": minutes, "events": []}
    try:
        events = await fetch_surrounding(alert_from_record(record), minutes, 100, include_self=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {exc}") from exc
    return {"enabled": True, "window_minutes": minutes, "events": events}
