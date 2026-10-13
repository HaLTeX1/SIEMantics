import logging

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import settings
from app.db import get_session
from app.enums import AlertStatus
from app.normalize import normalize_wazuh_alert
from app.models import AlertRecord, User
from app.pipeline import alert_queue, manual_escalate, process_record
from app.repository import (
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
    LabelRequest,
    NormalizedAlert,
    WazuhAlertPayload,
)

logger = logging.getLogger("siemantics.alerts")

router = APIRouter(prefix="/api/v1", tags=["alerts"])

# Record IDs with a manual escalation in flight - guards against a double click opening two IRIS cases
_escalations_in_progress: set[int] = set()


def _verify_token(x_webhook_token: str | None) -> None:
    if settings.wazuh_webhook_token and x_webhook_token != settings.wazuh_webhook_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")


async def _with_assignees(session: AsyncSession, records: list[AlertRecord]) -> list[AlertRecordOut]:
    assignments = await get_case_assignments(session, [r.iris_case_id for r in records if r.iris_case_id is not None])
    escalators = await get_users_by_ids(session, [r.escalated_by_id for r in records if r.escalated_by_id is not None])
    out = []
    for record in records:
        item = AlertRecordOut.model_validate(record)
        if record.iris_case_id in assignments:
            assignment, assignee = assignments[record.iris_case_id]
            item.assignee = AssigneeOut.model_validate(assignee)
            item.assigned_at = assignment.assigned_at
        if record.escalated_by_id in escalators:
            item.escalated_by = AssigneeOut.model_validate(escalators[record.escalated_by_id])
        out.append(item)
    return out


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED)
async def receive_alert(
    payload: WazuhAlertPayload,
    wait: bool = False,
    x_webhook_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    """Store the alert and queue it for triage (app/pipeline.py). Answers right
    away, so Wazuh's integratord is never held up by the LLM or IRIS.
    `?wait=true` (test tools, Postman): triage in the request and answer with the
    full result instead - 502 if triage or IRIS failed, like before the queue."""
    _verify_token(x_webhook_token)

    alert: NormalizedAlert = normalize_wazuh_alert(payload)
    record = await create_alert_record(
        session,
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        agent_name=alert.agent_name,
        rule_description=alert.rule_description,
        severity=alert.severity,
        raw_payload=payload.model_dump(mode="json"),
        status=AlertStatus.QUEUED,
        processing_time_ms=0.0,
    )
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
async def list_alerts(limit: int = 100, offset: int = 0, session: AsyncSession = Depends(get_session)):
    return await _with_assignees(session, await list_alert_records(session, limit=limit, offset=offset))


@router.get("/alerts/{alert_ref}", response_model=AlertRecordOut, dependencies=[Depends(get_current_user)])
async def get_alert(alert_ref: str, session: AsyncSession = Depends(get_session)):
    """`alert_ref`: our display ID ("ID-42") or a Wazuh alert_id (-> latest record)."""
    record = await get_alert_record_by_ref(session, alert_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return (await _with_assignees(session, [record]))[0]


@router.get("/config", dependencies=[Depends(get_current_user)])
async def get_public_config():
    """Non-secret config the frontend needs (e.g. to link out to the IRIS case)."""
    return {"iris_base_url": settings.iris_base_url.rstrip("/")}


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
    """Analyst override: open an IRIS case for an alert the automatic triage did
    not escalate (needs_review / suppressed / error). The automatic decision is
    kept in auto_status, so the evaluation metrics are not affected."""

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
