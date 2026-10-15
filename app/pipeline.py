# Hatter triazs: a webhook sorba allit, a workerek dolgozzak fel, ujrainditaskor folytatva.

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.correlation import find_correlated_record, join_group
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
from app.suppression import apply_rule, find_suppression

logger = logging.getLogger("siemantics.pipeline")


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def alert_from_record(record: AlertRecord) -> NormalizedAlert:
    if record.raw_payload:
        alert = normalize_wazuh_alert(WazuhAlertPayload.model_validate(record.raw_payload))
        alert.received_at = record.received_at
        return alert
    # raw_payload elotti regi rekordok.
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
    # A manager (000) nevet minden tuzfal/felho integracio viseli, ott csak IP alapjan.
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


class CaseStateCache:
    # IRIS esetek nyitott/lezart allapota a szinkron elott is; nyitottnal rovid ideig gyorsitotarazva.

    OPEN_TTL_SECONDS = 60

    def __init__(self) -> None:
        self.closed: set[int] = set()
        self._open_at: dict[int, float] = {}

    def clear(self) -> None:
        self.closed.clear()
        self._open_at.clear()

    def mark_closed(self, case_id: int) -> None:
        self.closed.add(case_id)
        self._open_at.pop(case_id, None)

    async def is_open(self, record: AlertRecord) -> bool:
        case_id = record.iris_case_id
        if case_id is None or record.case_closed_at is not None or case_id in self.closed:
            return False
        if time.monotonic() - self._open_at.get(case_id, float("-inf")) < self.OPEN_TTL_SECONDS:
            return True
        try:
            case = await iris_client.get_case(case_id)
        except Exception:
            # IRIS nem elerheto: nyitottnak vesszuk, a hozzaadas ugyis ujra ellenorzi.
            logger.warning("IRIS case %s state unknown, treating it as open", case_id, exc_info=True)
            return True
        if case is None or case.get("close_date"):
            self.mark_closed(case_id)
            return False
        self._open_at[case_id] = time.monotonic()
        return True


case_state = CaseStateCache()


async def send_to_iris(
    session: AsyncSession,
    record: AlertRecord,
    alert: NormalizedAlert,
    triage: TriageResult,
    enrichment: list[dict],
    escalated_by: str | None = None,
) -> tuple[IrisCaseResult, AlertRecord | None]:
    # Uj IRIS eset, vagy a korrelalt korabbi riasztas nyitott esete; lezart esetbe soha.
    for _ in range(3):
        correlated = await find_correlated_record(session, record, exclude_cases=case_state.closed)
        if correlated is None:
            break
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
        # Az IRIS-ben lezarva (vagy nem olvashato): a kovetkezo jeloltet nezzuk.
        case_state.mark_closed(correlated.iris_case_id)
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
        # Az eredeti strukturalt elemzes megmarad a tickethez.
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
        # Az eszkalacio az analyst TP itelete.
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


async def _auto_group(session: AsyncSession, record: AlertRecord, correlated: AlertRecord | None) -> None:
    # Korrelalt vagy azonos burst-be tartozo riasztas automatikusan csoportba kerul.
    anchor = correlated or await find_correlated_record(
        session, record, require_case=False, exclude_cases=case_state.closed
    )
    if anchor is not None:
        join_group(record, anchor)


def _is_decided(record: AlertRecord) -> bool:
    auto = record.auto_status
    if auto in (None, AlertStatus.ERROR, AlertStatus.QUEUED) or record.status == AlertStatus.ERROR:
        return False
    # Eszkalalt csak IRIS esettel atveheto.
    return auto != AlertStatus.ESCALATED or record.iris_case_id is not None


async def _find_duplicate(session: AsyncSession, record: AlertRecord) -> tuple[AlertRecord, bool] | None:
    # Azonos ujjlenyomatu korabbi riasztas az ablakban; True, ha elemzo FP-nek jelolte.
    if settings.dedup_window_hours <= 0 or not record.fingerprint:
        return None
    window = timedelta(hours=settings.dedup_window_hours)
    result = await session.execute(
        select(AlertRecord)
        .where(
            AlertRecord.fingerprint == record.fingerprint,
            AlertRecord.id != record.id,
            AlertRecord.received_at >= record.received_at - window,
            AlertRecord.received_at <= record.received_at,
        )
        .order_by(AlertRecord.received_at.desc())
    )
    candidates = list(result.scalars())
    labels = {c.ground_truth for c in candidates}
    known_fp = GroundTruth.FALSE_POSITIVE in labels and GroundTruth.TRUE_POSITIVE not in labels
    decided = await _first_usable_anchor(candidates)
    if known_fp:
        return decided or candidates[0], True
    return (decided, False) if decided else None


async def _first_usable_anchor(candidates: list[AlertRecord]) -> AlertRecord | None:
    # Eldontott riasztas, aminek a dontese atveheto; lezart esetu eszkalacio nem: oda mar senki nem nez.
    for candidate in candidates:
        if not _is_decided(candidate):
            continue
        if candidate.auto_status == AlertStatus.ESCALATED and not await case_state.is_open(candidate):
            continue
        return candidate
    return None


async def _find_flood_anchor(session: AsyncSession, record: AlertRecord) -> AlertRecord | None:
    # Flood: a szabaly+host az ablakban elerte a kuszobot; a legutobbi dontes, ha nem enyhebb.
    if settings.flood_threshold <= 0 or settings.flood_window_minutes <= 0 or not record.rule_id:
        return None
    since = record.received_at - timedelta(minutes=settings.flood_window_minutes)
    same = [
        AlertRecord.rule_id == record.rule_id,
        AlertRecord.agent_name == record.agent_name if record.agent_name else AlertRecord.agent_name.is_(None),
        AlertRecord.received_at >= since,
        AlertRecord.received_at <= record.received_at,
    ]
    count = await session.scalar(select(func.count()).select_from(AlertRecord).where(*same))
    if count < settings.flood_threshold:
        return None
    result = await session.execute(
        select(AlertRecord)
        .where(*same, AlertRecord.id != record.id, AlertRecord.suppression_rule_id.is_(None))
        .order_by(AlertRecord.received_at.desc())
    )
    decided = await _first_usable_anchor(list(result.scalars()))
    # Magasabb szintu riasztas nem orokolheti egy enyhebb donteset.
    return decided if decided is not None and decided.severity >= record.severity else None


async def _apply_suppression(session: AsyncSession, record: AlertRecord, rule, started: float) -> ProcessOutcome:
    await apply_rule(session, rule, record)
    record.processing_time_ms = _elapsed_ms(started)
    await save_alert_record(session, record)
    logger.info("alert %s (%s) suppressed by rule #%s", record.alert_id, record.display_id, rule.id)
    triage = TriageResult(
        is_true_positive=False, confidence=1.0, reasoning=record.llm_reasoning, iocs=[], engine="suppression"
    )
    return ProcessOutcome(triage=triage)


async def _apply_duplicate(
    session: AsyncSession,
    record: AlertRecord,
    anchor: AlertRecord,
    known_fp: bool,
    started: float,
    engine: str = "dedup",
) -> ProcessOutcome:
    # LLM hivas nelkul: az ismert FP elnyomva, kulonben a korabbi dontes atveve.
    if engine == "flood":
        note = (f"Flood: rule {record.rule_id} fired at least {settings.flood_threshold} times on this host within "
                f"{settings.flood_window_minutes} min, latest decision taken from {anchor.display_id}")
    else:
        note = f"Duplicate of {anchor.display_id} (same host, rule and key fields within {settings.dedup_window_hours} h)"
    record.triage_engine = engine
    record.triage_model = anchor.triage_model
    record.llm_is_true_positive = anchor.llm_is_true_positive
    record.llm_confidence = anchor.llm_confidence
    record.llm_iocs = anchor.llm_iocs
    record.llm_analysis = anchor.llm_analysis
    record.correlated_with_id = anchor.id
    join_group(record, anchor)
    if known_fp:
        record.status = record.auto_status = AlertStatus.SUPPRESSED
        record.review_reason = f"duplicate of {anchor.display_id}, labeled false positive by an analyst"
        record.llm_reasoning = f"{note}; an analyst labeled it false positive, suppressed without triage."
    else:
        record.status = record.auto_status = anchor.auto_status
        record.review_reason = anchor.review_reason
        record.llm_reasoning = f"{note}; decision taken over.\n\n{anchor.llm_reasoning or ''}".rstrip()
        if anchor.auto_status == AlertStatus.ESCALATED:
            record.iris_case_id = anchor.iris_case_id
            record.ioc_enrichment = anchor.ioc_enrichment
    record.processing_time_ms = _elapsed_ms(started)
    await save_alert_record(session, record)
    logger.info("alert %s (%s) is a %s of %s -> %s", record.alert_id, record.display_id,
                "flood repeat" if engine == "flood" else "duplicate", anchor.display_id, record.status.value)
    triage = TriageResult(
        is_true_positive=bool(record.llm_is_true_positive) and not known_fp,
        confidence=record.llm_confidence or 0.0,
        reasoning=record.llm_reasoning,
        iocs=record.llm_iocs or [],
        engine=engine,
        model=record.triage_model,
    )
    case = None
    if record.iris_case_id:
        case = IrisCaseResult(case_id=record.iris_case_id, case_url=iris_client.case_url(record.iris_case_id))
    return ProcessOutcome(triage=triage, case=case, correlated=anchor)


async def process_record(session: AsyncSession, record: AlertRecord) -> ProcessOutcome:
    # QUEUED rekord triazsa; triazs/IRIS hibat ERROR statuszkent tarol, nem dob.
    alert = alert_from_record(record)
    started = time.perf_counter()
    rule = await find_suppression(session, record)
    if rule is not None:
        return await _apply_suppression(session, record, rule, started)
    duplicate = await _find_duplicate(session, record)
    if duplicate is not None:
        return await _apply_duplicate(session, record, *duplicate, started)
    flood_anchor = await _find_flood_anchor(session, record)
    if flood_anchor is not None:
        return await _apply_duplicate(session, record, flood_anchor, False, started, engine="flood")
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
        await _auto_group(session, record, None)
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
        # auto_status ESCALATED marad: a triazs jo volt, csak az IRIS nem volt elerheto.
        record.status = AlertStatus.ERROR
        record.error_detail = f"iris case creation failed: {exc}"
        record.processing_time_ms = _elapsed_ms(started)
        await save_alert_record(session, record)
        return ProcessOutcome(triage=triage)

    record.status = AlertStatus.ESCALATED
    record.iris_case_id = case.case_id
    record.correlated_with_id = correlated.id if correlated else None
    await _auto_group(session, record, correlated)
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
        # Ujjlenyomatonkenti zar: az azonos riasztasok sorban mennek, igy a dedup elkapja oket.
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock_users: dict[str, int] = {}

    async def _process_serialized(self, session: AsyncSession, record: AlertRecord) -> None:
        key = record.fingerprint or f"id:{record.id}"
        lock = self._locks.setdefault(key, asyncio.Lock())
        self._lock_users[key] = self._lock_users.get(key, 0) + 1
        try:
            async with lock:
                await session.refresh(record)
                if record.status == AlertStatus.QUEUED:
                    await process_record(session, record)
        finally:
            self._lock_users[key] -= 1
            if not self._lock_users[key]:
                del self._lock_users[key], self._locks[key]

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
            # Nem fut a sor: a rekord QUEUED marad, ujrainditaskor feldolgozodik.
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
                    await self._process_serialized(session, record)
            except Exception as exc:
                # A worker eletben marad, a rekord ne maradjon QUEUED (ujrainditaskor ujra elbukna).
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
