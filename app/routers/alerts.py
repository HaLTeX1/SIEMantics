import logging
import time

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_session
from app.enums import AlertStatus
from app.iris_client import iris_client
from app.llm_engine import triage_alert
from app.normalize import normalize_wazuh_alert
from app.repository import create_alert_record, list_alert_records, set_ground_truth
from app.schemas import AlertRecordOut, LabelRequest, NormalizedAlert, WazuhAlertPayload

logger = logging.getLogger("siemantics.alerts")

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _verify_token(x_webhook_token: str | None) -> None:
    if settings.wazuh_webhook_token and x_webhook_token != settings.wazuh_webhook_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED)
async def receive_alert(
    payload: WazuhAlertPayload,
    x_webhook_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    _verify_token(x_webhook_token)

    alert: NormalizedAlert = normalize_wazuh_alert(payload)
    started = time.perf_counter()

    try:
        triage = await triage_alert(alert)
    except Exception as exc:
        await create_alert_record(
            session,
            alert_id=alert.alert_id,
            source_ip=alert.source_ip,
            rule_description=alert.rule_description,
            severity=alert.severity,
            status=AlertStatus.ERROR,
            processing_time_ms=_elapsed_ms(started),
            error_detail=f"triage failed: {exc}",
        )
        logger.exception("triage failed for alert %s", alert.alert_id)
        raise HTTPException(status_code=502, detail="triage failed unexpectedly") from exc

    if not triage.is_true_positive:
        record = await create_alert_record(
            session,
            alert_id=alert.alert_id,
            source_ip=alert.source_ip,
            rule_description=alert.rule_description,
            severity=alert.severity,
            status=AlertStatus.SUPPRESSED,
            llm_is_true_positive=False,
            llm_confidence=triage.confidence,
            llm_reasoning=triage.reasoning,
            llm_iocs=triage.iocs,
            triage_engine=triage.engine,
            processing_time_ms=_elapsed_ms(started),
        )
        logger.info("alert %s classified as false positive (confidence=%.2f)", alert.alert_id, triage.confidence)
        return {"status": "suppressed", "alert_id": alert.alert_id, "record_id": record.id, "triage": triage}

    try:
        case = await iris_client.create_case_from_alert(alert, triage)
    except Exception as exc:
        await create_alert_record(
            session,
            alert_id=alert.alert_id,
            source_ip=alert.source_ip,
            rule_description=alert.rule_description,
            severity=alert.severity,
            status=AlertStatus.ERROR,
            llm_is_true_positive=True,
            llm_confidence=triage.confidence,
            llm_reasoning=triage.reasoning,
            llm_iocs=triage.iocs,
            triage_engine=triage.engine,
            processing_time_ms=_elapsed_ms(started),
            error_detail=f"iris case creation failed: {exc}",
        )
        logger.exception("iris case creation failed for alert %s", alert.alert_id)
        raise HTTPException(status_code=502, detail="incident management backend unavailable") from exc

    record = await create_alert_record(
        session,
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        rule_description=alert.rule_description,
        severity=alert.severity,
        status=AlertStatus.ESCALATED,
        llm_is_true_positive=True,
        llm_confidence=triage.confidence,
        llm_reasoning=triage.reasoning,
        llm_iocs=triage.iocs,
        triage_engine=triage.engine,
        iris_case_id=case.case_id,
        processing_time_ms=_elapsed_ms(started),
    )
    logger.info("alert %s escalated to IRIS case %s", alert.alert_id, case.case_id)
    return {"status": "escalated", "alert_id": alert.alert_id, "record_id": record.id, "triage": triage, "case": case}


@router.get("/alerts", response_model=list[AlertRecordOut])
async def list_alerts(limit: int = 100, offset: int = 0, session: AsyncSession = Depends(get_session)):
    return await list_alert_records(session, limit=limit, offset=offset)


@router.patch("/alerts/{alert_id}/label", response_model=AlertRecordOut)
async def label_alert(alert_id: str, body: LabelRequest, session: AsyncSession = Depends(get_session)):
    record = await set_ground_truth(session, alert_id, body.ground_truth)
    if record is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return record
