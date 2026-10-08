import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import settings
from app.db import get_session
from app.enrichment import enrich_iocs
from app.enums import AlertStatus, GroundTruth
from app.iris_client import iris_client
from app.normalize import normalize_wazuh_alert
from app.models import AlertRecord, User
from app.pipeline import alert_from_record, alert_queue, related_alerts
from app.repository import (
    create_alert_record,
    get_alert_record_by_ref,
    get_case_assignments,
    get_users_by_ids,
    list_alert_records,
    save_alert_record,
    set_ground_truth,
)
from app.schemas import (
    AlertRecordOut,
    AssigneeOut,
    LabelRequest,
    NormalizedAlert,
    TriageResult,
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
    x_webhook_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    """Store the alert and queue it for triage (app/pipeline.py). Answers right
    away, so Wazuh's integratord is never held up by the LLM or IRIS."""
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
    alert_queue.enqueue(record.id)
    logger.info("alert %s queued as %s", alert.alert_id, record.display_id)
    return {
        "status": AlertStatus.QUEUED.value,
        "id": record.display_id,
        "alert_id": alert.alert_id,
        "record_id": record.id,
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


def _manual_triage(record: AlertRecord, user: User) -> TriageResult:
    if record.triage_engine:
        verdict = "true positive" if record.llm_is_true_positive else "false positive"
        original = (
            f"Original triage ({record.triage_engine}, model {record.triage_model or '-'}): "
            f"{verdict}, confidence {record.llm_confidence}."
        )
    else:
        original = "No automatic triage result (triage failed)."
    parts = [
        f"Manually escalated by {user.username} (automatic decision: {record.status.value}).",
        original,
    ]
    if record.review_reason:
        parts.append(f"Review reason: {record.review_reason}.")
    if record.llm_reasoning:
        parts.append(f"\nOriginal reasoning:\n{record.llm_reasoning}")
    return TriageResult(
        is_true_positive=True,
        confidence=record.llm_confidence or 0.0,
        reasoning="\n".join(parts),
        iocs=record.llm_iocs or [],
        engine="manual",
        model=record.triage_model,
        # Keep the original structured analysis (summary, actions, ...) for the ticket
        **(record.llm_analysis or {}),
    )


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
        alert = alert_from_record(record)
        triage = _manual_triage(record, user)
        related = await related_alerts(
            session, alert, record.received_at, include_later=True, exclude_id=record.id
        )
        enrichment = await enrich_iocs(triage.iocs)
        try:
            case = await iris_client.create_case_from_alert(
                alert,
                triage,
                enrichment,
                display_id=record.display_id,
                escalated_by=user.username,
                related_alerts=related,
            )
        except Exception as exc:
            logger.exception("manual escalation of %s failed", record.display_id)
            raise HTTPException(status_code=502, detail="incident management backend unavailable") from exc

        now = datetime.utcnow()
        if record.auto_status is None:
            record.auto_status = record.status
        record.status = AlertStatus.ESCALATED
        record.iris_case_id = case.case_id
        record.ioc_enrichment = enrichment or record.ioc_enrichment
        record.error_detail = None
        record.escalated_by_id = user.id
        record.escalated_at = now
        # Escalating is the analyst's verdict that this needs incident response
        record.ground_truth = GroundTruth.TRUE_POSITIVE
        record.labeled_at = now
        await save_alert_record(session, record)
    finally:
        _escalations_in_progress.discard(record.id)

    logger.info("%s manually escalated by %s to IRIS case %s", record.display_id, user.username, case.case_id)
    return (await _with_assignees(session, [record]))[0]
