"""Background alert processing.

The webhook only stores the alert (status QUEUED) and puts its record ID on an
in-process queue, so Wazuh gets an answer immediately. Worker tasks then run
triage -> guardrails -> enrichment -> IRIS case per alert. A slow free LLM or an
unreachable IRIS therefore never blocks Wazuh's integratord, and an alert burst
is worked off at the pace set by TRIAGE_WORKERS instead of hammering OpenRouter.

QUEUED records left over from a restart are re-queued on startup - the stored
raw payload is all that is needed to process them."""

import asyncio
import logging
import time
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import async_session
from app.enrichment import enrich_iocs
from app.enums import AlertStatus
from app.guardrails import decide_status
from app.iris_client import iris_client
from app.llm_engine import triage_alert
from app.models import AlertRecord
from app.normalize import normalize_wazuh_alert, related_log_excerpt
from app.repository import find_related_alerts, save_alert_record
from app.schemas import NormalizedAlert, RelatedAlert, WazuhAlertPayload

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
    include_later: bool = False,
    exclude_id: int | None = None,
) -> list[RelatedAlert]:
    """Other alerts from the same host or source IP within the correlation window.
    Live triage only sees the past; a later manual escalation also sees what came after."""
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
        after=window if include_later else timedelta(0),
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


async def process_record(session: AsyncSession, record: AlertRecord) -> None:
    """Triage a QUEUED record and store the outcome on it. Never raises for a
    triage or IRIS failure - those end up as status ERROR on the record."""
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
        return

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
        return

    record.ioc_enrichment = await enrich_iocs(triage.iocs) or None
    try:
        case = await iris_client.create_case_from_alert(
            alert, triage, record.ioc_enrichment or [], display_id=record.display_id, related_alerts=related
        )
    except Exception as exc:
        logger.exception("iris case creation failed for alert %s (%s)", alert.alert_id, record.display_id)
        # auto_status stays ESCALATED: the triage decision was right, only IRIS was unavailable
        record.status = AlertStatus.ERROR
        record.error_detail = f"iris case creation failed: {exc}"
        record.processing_time_ms = _elapsed_ms(started)
        await save_alert_record(session, record)
        return

    record.status = AlertStatus.ESCALATED
    record.iris_case_id = case.case_id
    record.processing_time_ms = _elapsed_ms(started)
    await save_alert_record(session, record)
    logger.info("alert %s (%s) escalated to IRIS case %s", alert.alert_id, record.display_id, case.case_id)


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
        """Wait until every queued alert is processed (used by the tests)."""
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
