# Hatter feldolgozas: a webhook csak sorba allit, a workerek triazsolnak.
# Ujrainditaskor a QUEUED rekordok ujra sorba kerulnek.

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.correlation import find_correlated_record
from app.db import async_session
from app.enrichment import enrich_iocs
from app.enums import AlertStatus, GroundTruth
from app.guardrails import decide_status
from app.iris_client import iris_client
from app.llm_engine import triage_alert
from app.models import AlertRecord, User
from app.normalize import normalize_wazuh_alert, related_log_excerpt
from app.repository import find_related_alerts, save_alert_record
from app.schemas import IrisCaseResult, NormalizedAlert, RelatedAlert, TriageResult, WazuhAlertPayload

logger = logging.getLogger("siemantics.pipeline")


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def alert_from_record(record: AlertRecord) -> NormalizedAlert:
    if record.raw_payload:
        alert = normalize_wazuh_alert(WazuhAlertPayload.model_validate(record.raw_payload))
        alert.received_at = record.received_at
        return alert
    # Records stored before raw_payload existed
    return NormalizedAlert(
        alert_id=record.alert_id,
        source_ip=record.source_ip,
        agent_name=record.agent_name,
        rule_description=record.rule_description,
        severity=record.severity,
        log_snippet="(original log not stored for this record)",
        received_at=record.received_at,
    )


async def related_alerts(
    session: AsyncSession,
    alert: NormalizedAlert,
    around: datetime,
    *,
    exclude_id: int | None = None,
) -> list[RelatedAlert]:
    # Korabbi riasztasok ugyanarrol a hostrol / IP-rol, kontextus az LLM-nek.
    if settings.correlation_window_hours <= 0 or settings.correlation_max_alerts <= 0:
        return []
    window = timedelta(hours=settings.correlation_window_hours)
    # Agent 000 is the Wazuh manager: every firewall/cloud integration alert carries
    # its name, so matching on it would link unrelated events - use the source IP only.
    agent_name = alert.agent_name if alert.agent_id != "000" else None
    records = await find_related_alerts(
        session,
        agent_name=agent_name,
        source_ip=alert.source_ip,
        around=around,
        before=window,
        exclude_id=exclude_id,
        limit=settings.correlation_max_alerts,
    )
    return [
        RelatedAlert(
            display_id=r.display_id,
            received_at=r.received_at,
            rule_id=((r.raw_payload or {}).get("rule") or {}).get("id"),
            rule_description=r.rule_description,
            severity=r.severity,
            status=r.status,
            agent_name=r.agent_name,
            source_ip=r.source_ip,
            iris_case_id=r.iris_case_id,
            log_excerpt=related_log_excerpt(r.raw_payload),
        )
        for r in records
    ]


async def send_to_iris(
    session: AsyncSession,
    record: AlertRecord,
    alert: NormalizedAlert,
    triage: TriageResult,
    enrichment: list[dict],
    escalated_by: str | None = None,
) -> tuple[IrisCaseResult, AlertRecord | None]:
    # Uj IRIS eset, vagy a korrelalt korabbi riasztas esete.
    correlated = await find_correlated_record(session, record)
    if correlated is not None:
        case = await iris_client.add_alert_to_case(
            correlated.iris_case_id,
            alert,
            triage,
            enrichment,
            display_id=record.display_id,
            correlated_with=correlated.display_id,
            escalated_by=escalated_by,
            raw_payload=record.raw_payload,
        )
        if case is not None:
            return case, correlated
    case = await iris_client.create_case_from_alert(
        alert, triage, enrichment, display_id=record.display_id, escalated_by=escalated_by, raw_payload=record.raw_payload
    )
    return case, None


def manual_triage(record: AlertRecord, username: str) -> TriageResult:
    if record.triage_engine:
        verdict = "true positive" if record.llm_is_true_positive else "false positive"
        original = (
            f"Original triage ({record.triage_engine}, model {record.triage_model or '-'}): "
            f"{verdict}, confidence {record.llm_confidence}."
        )
    else:
        original = "No automatic triage result (triage failed)."
    parts = [
        f"Manually escalated by {username} (automatic decision: {record.status.value}).",
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


async def manual_escalate(
    session: AsyncSession, record: AlertRecord, user: User, *, label_true_positive: bool = True
) -> IrisCaseResult:
    # Kezi eszkalacio; IRIS hibanal kivetel, a rekord csak siker eseten valtozik.
    alert = alert_from_record(record)
    triage = manual_triage(record, user.username)
    enrichment = await enrich_iocs(triage.iocs)
    case, correlated = await send_to_iris(session, record, alert, triage, enrichment, escalated_by=user.username)

    now = datetime.utcnow()
    if record.auto_status is None:
        record.auto_status = record.status
    record.status = AlertStatus.ESCALATED
    record.iris_case_id = case.case_id
    record.correlated_with_id = correlated.id if correlated else None
    record.ioc_enrichment = enrichment or record.ioc_enrichment
    record.error_detail = None
    record.escalated_by_id = user.id
    record.escalated_at = now
    if label_true_positive:
        # Az eszkalacio az analyst TP iteleteje.
        record.ground_truth = GroundTruth.TRUE_POSITIVE
        record.labeled_at = now
    await save_alert_record(session, record)
    logger.info("%s manually escalated by %s to IRIS case %s", record.display_id, user.username, case.case_id)
    return case


@dataclass
class ProcessOutcome:
    # A feldolgozas eredmenye a ?wait=true valaszhoz.

    triage: TriageResult | None = None
    case: IrisCaseResult | None = None
    correlated: AlertRecord | None = None


async def process_record(session: AsyncSession, record: AlertRecord) -> ProcessOutcome:
    # QUEUED rekord triazsa; triazs/IRIS hibat ERROR statuszkent tarol, nem dob.
    alert = alert_from_record(record)
    started = time.perf_counter()
    related = await related_alerts(session, alert, record.received_at, exclude_id=record.id)

    try:
        triage = await triage_alert(alert, related)
    except Exception as exc:
        logger.exception("triage failed for alert %s (%s)", alert.alert_id, record.display_id)
        record.status = AlertStatus.ERROR
        record.auto_status = AlertStatus.ERROR
        record.error_detail = f"triage failed: {exc}"
        record.processing_time_ms = _elapsed_ms(started)
        await save_alert_record(session, record)
        return ProcessOutcome()

    record.llm_is_true_positive = triage.is_true_positive
    record.llm_confidence = triage.confidence
    record.llm_reasoning = triage.reasoning
    record.llm_iocs = triage.iocs
    record.triage_engine = triage.engine
    record.triage_model = triage.model
    record.llm_analysis = triage.analysis() or None
    alert_status, review_reason = decide_status(alert, triage)
    record.auto_status = alert_status

    if alert_status != AlertStatus.ESCALATED:
        record.status = alert_status
        record.review_reason = review_reason
        record.processing_time_ms = _elapsed_ms(started)
        await save_alert_record(session, record)
        logger.info(
            "alert %s (%s) classified as false positive (confidence=%.2f) -> %s%s",
            alert.alert_id,
            record.display_id,
            triage.confidence,
            alert_status.value,
            f" ({review_reason})" if review_reason else "",
        )
        return ProcessOutcome(triage=triage)

    record.ioc_enrichment = await enrich_iocs(triage.iocs) or None
    try:
        case, correlated = await send_to_iris(session, record, alert, triage, record.ioc_enrichment or [])
    except Exception as exc:
        logger.exception("iris case creation failed for alert %s (%s)", alert.alert_id, record.display_id)
        # auto_status stays ESCALATED: the triage decision was right, only IRIS was unavailable
        record.status = AlertStatus.ERROR
        record.error_detail = f"iris case creation failed: {exc}"
        record.processing_time_ms = _elapsed_ms(started)
        await save_alert_record(session, record)
        return ProcessOutcome(triage=triage)

    record.status = AlertStatus.ESCALATED
    record.iris_case_id = case.case_id
    record.correlated_with_id = correlated.id if correlated else None
    record.processing_time_ms = _elapsed_ms(started)
    await save_alert_record(session, record)
    logger.info(
        "alert %s (%s) escalated to IRIS case %s%s",
        alert.alert_id,
        record.display_id,
        case.case_id,
        f" (correlated with {correlated.display_id})" if correlated else "",
    )
    return ProcessOutcome(triage=triage, case=case, correlated=correlated)


class AlertQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[int] | None = None
        self._workers: list[asyncio.Task] = []

    async def start(self, workers: int) -> None:
        self._queue = asyncio.Queue()
        self._workers = [asyncio.create_task(self._worker(i)) for i in range(max(workers, 1))]
        async with async_session() as session:
            pending = await session.scalars(
                select(AlertRecord.id).where(AlertRecord.status == AlertStatus.QUEUED).order_by(AlertRecord.id)
            )
            pending = list(pending)
        for record_id in pending:
            self._queue.put_nowait(record_id)
        if pending:
            logger.info("re-queued %d alert(s) left unprocessed by the previous run", len(pending))

    async def stop(self) -> None:
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        self._queue = None

    def enqueue(self, record_id: int) -> None:
        if self._queue is None:
            # Not started (should not happen in the app): the record stays QUEUED
            # in the database and is picked up on the next startup.
            logger.error("alert queue not running, record %s will be processed after restart", record_id)
            return
        self._queue.put_nowait(record_id)

    def size(self) -> int:
        return self._queue.qsize() if self._queue else 0

    async def join(self) -> None:
        # Megvarja a sor kiuruleset (tesztekhez).
        if self._queue is not None:
            await self._queue.join()

    async def _worker(self, index: int) -> None:
        assert self._queue is not None
        queue = self._queue
        while True:
            record_id = await queue.get()
            try:
                async with async_session() as session:
                    record = await session.get(AlertRecord, record_id)
                    if record is None or record.status != AlertStatus.QUEUED:
                        continue
                    await process_record(session, record)
            except Exception as exc:
                # Keep the worker alive, and do not leave the record QUEUED (it would be
                # retried - and probably fail again - on every restart)
                logger.exception("worker %d: unexpected error while processing record %s", index, record_id)
                await _mark_failed(record_id, exc)
            finally:
                queue.task_done()


async def _mark_failed(record_id: int, exc: Exception) -> None:
    try:
        async with async_session() as session:
            record = await session.get(AlertRecord, record_id)
            if record is not None and record.status == AlertStatus.QUEUED:
                record.status = AlertStatus.ERROR
                record.auto_status = AlertStatus.ERROR
                record.error_detail = f"processing failed: {exc}"
                await save_alert_record(session, record)
    except Exception:
        logger.exception("could not mark record %s as failed", record_id)


alert_queue = AlertQueue()
