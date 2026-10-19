import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import AlertStatus, GroundTruth
from app import status
from app.iris_client import (
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_LEGITIMATE,
    OUTCOME_NAMES,
    OUTCOME_TRUE_POSITIVE,
    closure_annotation,
    iris_client,
)
from app.iris_report import MergedAlert, false_positive_note, merge_note, merged_away_note
from app.models import AlertRecord, User
from app.normalize import related_log_excerpt
from app.repository import get_alert_record_by_ref, get_alert_records_by_refs, get_group_members, get_records_in_cases

logger = logging.getLogger("siemantics.cases")

# Egyszerre egy eset-muvelet, dupla kattintas ellen.
_lock = asyncio.Lock()


class CaseActionError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class MergeOutcome:
    target: AlertRecord
    merged: list[AlertRecord]
    # None, ha nem volt nyitott IRIS eset: csak SIEMantics csoport.
    iris_case_id: int | None = None
    closed_cases: list[int] = field(default_factory=list)
    close_failed: list[int] = field(default_factory=list)


async def _expand(session: AsyncSession, selected: list[AlertRecord]) -> list[AlertRecord]:
    # A kijelolt riasztasok IRIS eseteinek es csoportjainak minden tagja is bekerul.
    members = {r.id: r for r in selected}
    while True:
        cases = {r.iris_case_id for r in members.values() if r.iris_case_id}
        groups = {r.group_id for r in members.values() if r.group_id}
        found = await get_records_in_cases(session, cases) + await get_group_members(session, groups)
        new = [r for r in found if r.id not in members]
        if not new:
            return sorted(members.values(), key=lambda r: r.received_at)
        members.update((r.id, r) for r in new)


async def resolve_many(session: AsyncSession, refs: list[str]) -> list[AlertRecord]:
    # Sok hivatkozas egy lekerdezessel; hianyzo ID-nel 404.
    records, missing = await get_alert_records_by_refs(session, refs)
    if missing:
        raise CaseActionError(404, f"alert not found: {', '.join(missing[:10])}")
    return records


async def _resolve(session: AsyncSession, refs: list[str]) -> list[AlertRecord]:
    records: dict[int, AlertRecord] = {}
    for ref in refs:
        record = await get_alert_record_by_ref(session, ref)
        if record is None:
            raise CaseActionError(404, f"alert not found: {ref}")
        records[record.id] = record
    return list(records.values())


async def _first_open_case(members: list[AlertRecord]) -> int | None:
    # A legkorabbi riasztas nyitott esete lesz a cel.
    checked: set[int] = set()
    for record in sorted(members, key=lambda r: r.received_at):
        case_id = record.iris_case_id
        if case_id is None or case_id in checked:
            continue
        checked.add(case_id)
        if await iris_client.is_open(case_id):
            return case_id
    return None


def _merged_row(record: AlertRecord, previous_status: str) -> MergedAlert:
    return MergedAlert(
        display_id=record.display_id,
        received_at=record.received_at,
        rule_description=record.rule_description,
        severity=record.severity,
        agent_name=record.agent_name,
        source_ip=record.source_ip,
        status=previous_status,
        previous_case_id=record.iris_case_id,
        log_excerpt=related_log_excerpt(record.raw_payload, limit=160),
    )


async def merge_alerts(session: AsyncSession, refs: list[str], user: User) -> MergeOutcome:
    async with _lock:
        selected = await _resolve(session, refs)
        if len(selected) < 2:
            raise CaseActionError(422, "select at least two different alerts")
        queued = [r.display_id for r in selected if r.status == AlertStatus.QUEUED]
        if queued:
            raise CaseActionError(409, f"alerts still waiting for triage: {', '.join(queued)}")

        members_list = await _expand(session, selected)
        try:
            target_case = await _first_open_case(members_list)
        except Exception as exc:
            logger.exception("merge: IRIS cases could not be checked")
            raise CaseActionError(502, "incident management backend unavailable") from exc

        # Nyitott eset nelkul (pl. csak FP-k) nincs IRIS muvelet, csak csoport.
        if target_case is None:
            target, moved = members_list[0], []
        else:
            target = next(r for r in members_list if r.iris_case_id == target_case)
            moved = [r for r in members_list if r.iris_case_id != target_case]
        regrouped = [r for r in members_list if r.group_id != target.id]
        if not moved and not regrouped:
            raise CaseActionError(409, "the selected alerts are already merged")

        outcome = MergeOutcome(
            target=target,
            merged=[r for r in members_list if r is not target and (r in moved or r in regrouped)],
            iris_case_id=target_case,
        )
        if moved:
            await _merge_into_case(target_case, target, moved, user, outcome)
        for record in members_list:
            record.group_id = target.id
        await session.commit()
        logger.info("%s merged %d alert(s) into group %s (IRIS case %s)",
                    user.username, len(outcome.merged), target.display_id, target_case)
        return outcome


async def _merge_into_case(
    target_case: int, target: AlertRecord, moved: list[AlertRecord], user: User, outcome: MergeOutcome
) -> None:
    # IRIS oldal: note a celesetbe, a regi esetek lezarva; a rekordok a celesetbe kerulnek.
    rows = [_merged_row(r, r.status.value) for r in moved]
    old_cases = sorted({r.iris_case_id for r in moved if r.iris_case_id is not None})
    label = f"merge {datetime.utcnow():%Y-%m-%d %H:%M} ({user.username})"
    try:
        await iris_client.add_case_notes(
            target_case, label, [("Merged alerts", merge_note(target.display_id, rows, user.username, old_cases))]
        )
    except Exception as exc:
        logger.exception("merge into IRIS case %s failed", target_case)
        raise CaseActionError(502, "incident management backend unavailable") from exc

    await _best_effort(iris_client.add_case_tags(target_case, ["merged"]), f"tagging case {target_case}")
    for case_id in old_cases:
        if await _close_merged(case_id, target_case, user.username):
            outcome.closed_cases.append(case_id)
        else:
            outcome.close_failed.append(case_id)

    now = datetime.utcnow()
    for record in moved:
        record.iris_case_id = target_case
        record.correlated_with_id = target.id
        if record.status != AlertStatus.ESCALATED:
            # Az automatikus dontes megmarad a metrikakhoz.
            if record.auto_status is None:
                record.auto_status = record.status
            record.status = AlertStatus.ESCALATED
            record.escalated_by_id = user.id
            record.escalated_at = now


async def _close_merged(case_id: int, target_case: int, username: str) -> bool:
    try:
        if not await iris_client.is_open(case_id):
            return True
        await iris_client.add_case_notes(case_id, f"merged into #{target_case}",
                                         [("Merged", merged_away_note(target_case, username))])
        # Lezarasi annotacio minden lezarasnal.
        await _best_effort(iris_client.set_closure_annotation(case_id, f"Merged into #{target_case} by {username} (SIEMantics)."),
                           f"setting closure annotation of case {case_id}")
        await iris_client.close_case(case_id)
        return True
    except Exception:
        logger.warning("merge: IRIS case %s could not be closed", case_id, exc_info=True)
        return False


async def _best_effort(coro, what: str) -> None:
    try:
        await coro
    except Exception:
        logger.warning("%s failed", what, exc_info=True)


async def _close_case_fp(case_id: int, username: str, reason: str | None, display_ids: list[str]) -> bool:
    # Nyitott esetnel note + tag + lezaras; True, ha nyitott volt.
    if not await iris_client.is_open(case_id):
        return False
    note = false_positive_note(username, reason, display_ids)
    await iris_client.add_case_notes(case_id, f"false positive ({username})", [("Closed as false positive", note)])
    await _best_effort(iris_client.add_case_tags(case_id, ["false-positive"]), f"tagging case {case_id}")
    await _best_effort(iris_client.set_case_outcome(case_id, OUTCOME_FALSE_POSITIVE), f"setting outcome of case {case_id}")
    await _best_effort(iris_client.set_closure_annotation(case_id, _fp_annotation(username, reason)),
                       f"setting closure annotation of case {case_id}")
    await iris_client.close_case(case_id)
    return True


def _fp_annotation(username: str, reason: str | None) -> str:
    return f"False positive ({username}, SIEMantics): {reason}" if reason else f"False positive ({username}, SIEMantics)"


def _mark_case_closed(
    records: list[AlertRecord], case_ids: set[int], now: datetime, note: str | None = None
) -> None:
    for record in records:
        if record.iris_case_id in case_ids and record.case_closed_at is None:
            record.case_closed_at = now
            record.case_closure_note = note


def _label_false_positive(records: list[AlertRecord]) -> None:
    # FP cimke, igy a metrikakba is bekerul.
    now = datetime.utcnow()
    for record in records:
        record.ground_truth = GroundTruth.FALSE_POSITIVE
        record.labeled_at = now
        record.label_source = None


async def close_as_false_positive(
    session: AsyncSession, case_id: int, user: User, reason: str | None
) -> tuple[list[AlertRecord], bool]:
    async with _lock:
        records = await get_records_in_cases(session, {case_id})
        if not records:
            raise CaseActionError(404, "case not found")
        try:
            was_open = await _close_case_fp(case_id, user.username, reason, [r.display_id for r in records])
        except Exception as exc:
            logger.exception("closing IRIS case %s as false positive failed", case_id)
            raise CaseActionError(502, "incident management backend unavailable") from exc

        _label_false_positive(records)
        _mark_case_closed(records, {case_id}, datetime.utcnow(), _fp_annotation(user.username, reason))
        await session.commit()
        logger.info("%s closed IRIS case %s as false positive (%d alert(s))", user.username, case_id, len(records))
        return records, was_open


async def _close_records_fp(
    session: AsyncSession, members: list[AlertRecord], user: User, reason: str | None
) -> tuple[list[AlertRecord], list[int]]:
    # A tagok IRIS eseteinek tobbi riasztasa is FP lesz, ahogy az eset FP lezarasanal.
    case_ids = sorted({r.iris_case_id for r in members if r.iris_case_id})
    records = {r.id: r for r in members}
    for other in await get_records_in_cases(session, set(case_ids)):
        records.setdefault(other.id, other)

    closed: list[int] = []
    try:
        for case_id in case_ids:
            ids = [r.display_id for r in records.values() if r.iris_case_id == case_id]
            if await _close_case_fp(case_id, user.username, reason, ids):
                closed.append(case_id)
    except Exception as exc:
        logger.exception("closing IRIS cases %s as false positive failed", case_ids)
        raise CaseActionError(502, "incident management backend unavailable") from exc

    labeled = sorted(records.values(), key=lambda r: r.received_at)
    _label_false_positive(labeled)
    _mark_case_closed(labeled, set(case_ids), datetime.utcnow(), _fp_annotation(user.username, reason))
    for record in labeled:
        if record.status == AlertStatus.QUEUED:
            # Triazs elott lezarva: nem kerul LLM ele, es nem rendszer-dontes.
            record.status = AlertStatus.SUPPRESSED
            record.triage_engine = "analyst"
            record.review_reason = f"closed as false positive by {user.username} before triage"
        elif record.iris_case_id is None and record.status in (AlertStatus.NEEDS_REVIEW, AlertStatus.ERROR):
            # Felulvizsgalat lezarva: lekerul a sorbol; az auto_status a metrikakhoz megmarad.
            if record.auto_status is None:
                record.auto_status = record.status
            record.status = AlertStatus.SUPPRESSED
            note = _fp_annotation(user.username, reason)
            record.review_reason = f"{record.review_reason}; {note}" if record.review_reason else note
    await session.commit()
    return labeled, closed


async def close_group_as_false_positive(
    session: AsyncSession, ref: str, user: User, reason: str | None
) -> tuple[str, list[AlertRecord], list[int]]:
    async with _lock:
        record = await get_alert_record_by_ref(session, ref)
        if record is None:
            raise CaseActionError(404, "alert not found")
        members = await get_group_members(session, {record.group_id}) if record.group_id else [record]
        labeled, closed = await _close_records_fp(session, members, user, reason)
        group = record.group or record.display_id
        logger.info("%s labeled group %s as false positive (%d alert(s), closed cases %s)",
                    user.username, group, len(labeled), closed)
        return group, labeled, closed


async def close_alerts_as_false_positive(
    session: AsyncSession, refs: list[str], user: User, reason: str | None
) -> tuple[list[AlertRecord], list[int]]:
    # Tomeges FP lezaras flood eseten; a varakozo riasztasok triazs nelkul lezarva.
    async with _lock:
        members = await resolve_many(session, refs)
        labeled, closed = await _close_records_fp(session, members, user, reason)
        logger.info("%s bulk-labeled %d alert(s) as false positive, closed cases %s", user.username, len(labeled), closed)
        return labeled, closed


async def delete_alerts(session: AsyncSession, refs: list[str], user: User) -> list[str]:
    # Vegleges torles csak a SIEMantics adatbazisbol; az IRIS esetek maradnak.
    async with _lock:
        records = await resolve_many(session, refs)
        deleted = [r.display_id for r in records]
        for record in records:
            await session.delete(record)
        await session.commit()
        logger.warning("%s deleted %d alert(s): %s", user.username, len(deleted), ", ".join(deleted[:50]))
        return deleted


# Az annotacio egyertelmu jelolesei, ha az Outcome mezo kitoltetlen (Unknown) maradt.
_NOTE_TP = re.compile(r"\b(tp|tpni|tpwi|true[\s-]+positive)\b", re.IGNORECASE)
_NOTE_FP = re.compile(r"\b(fp|false[\s-]+positive)\b", re.IGNORECASE)


def case_disposition(case: dict) -> GroundTruth | None:
    # IRIS kimenetelbol disposition; legitimate = nem fenyegetes, ezert FP.
    try:
        status_id = int(case.get("status_id") or 0)
    except (TypeError, ValueError):
        status_id = 0
    if status_id in OUTCOME_TRUE_POSITIVE:
        return GroundTruth.TRUE_POSITIVE
    if status_id in (OUTCOME_FALSE_POSITIVE, OUTCOME_LEGITIMATE):
        return GroundTruth.FALSE_POSITIVE
    tags = [t.strip().lower() for t in str(case.get("case_tags") or "").split(",")]
    if "false-positive" in tags:
        return GroundTruth.FALSE_POSITIVE
    # Tartalek: a lezarasi annotacio (pl. "IP blocked. TPNI"); ellentmondasnal nincs dontes.
    note = closure_annotation(case) or ""
    says_tp, says_fp = bool(_NOTE_TP.search(note)), bool(_NOTE_FP.search(note))
    if says_tp != says_fp:
        return GroundTruth.TRUE_POSITIVE if says_tp else GroundTruth.FALSE_POSITIVE
    return None


@dataclass
class SyncOutcome:
    checked: int = 0
    closed_cases: list[int] = field(default_factory=list)
    labeled: list[AlertRecord] = field(default_factory=list)
    unreadable: int = 0


async def sync_closed_cases(session: AsyncSession) -> SyncOutcome:
    # Az IRIS-ben lezart esetek kimenetele a riasztasok dispositionjebe; az eredmeny a Rendszerallapot fulre is.
    try:
        outcome = await _sync_closed_cases(session)
    except Exception as exc:
        status.record_failure("iris_sync", exc)
        raise
    info = {"checked": outcome.checked, "closed": len(outcome.closed_cases), "labeled": len(outcome.labeled),
            "unreadable": outcome.unreadable}
    if outcome.unreadable:
        status.record_failure("iris_sync", f"{outcome.unreadable} case(s) could not be read from IRIS")
    status.record_success("iris_sync", info)
    return outcome


# Lezart, de disposition nelkuli esetet eddig figyelunk: az Outcome utolag is kitoltheto.
_UNDECIDED_RECHECK_DAYS = 30


async def _sync_closed_cases(session: AsyncSession) -> SyncOutcome:
    # Nyitott esetek, es a lezart, de meg itelet nelkuli esetek; IRIS hibanal a tobbi eset megy tovabb.
    case_ids = await session.scalars(
        select(AlertRecord.iris_case_id)
        .where(
            AlertRecord.iris_case_id.is_not(None),
            or_(
                AlertRecord.case_closed_at.is_(None),
                and_(
                    AlertRecord.ground_truth.is_(None),
                    AlertRecord.case_closed_at >= datetime.utcnow() - timedelta(days=_UNDECIDED_RECHECK_DAYS),
                ),
            ),
        )
        .distinct()
    )
    outcome = SyncOutcome()
    for case_id in sorted(set(case_ids)):
        try:
            case = await iris_client.get_case(case_id)
        except Exception as exc:
            logger.warning("case sync: IRIS case %s could not be read: %s", case_id, exc)
            outcome.unreadable += 1
            continue
        outcome.checked += 1
        if case is None or not case.get("close_date"):
            continue
        outcome.labeled += await _apply_closed_case(session, case_id, case)
        outcome.closed_cases.append(case_id)
    return outcome


async def _apply_closed_case(session: AsyncSession, case_id: int, case: dict) -> list[AlertRecord]:
    # Lezart IRIS eset atvetele: lezaras ideje, annotacio, disposition; a frissen cimkezett rekordokat adja.
    labeled: list[AlertRecord] = []
    async with _lock:
        records = await get_records_in_cases(session, {case_id})
        disposition = case_disposition(case)
        note = closure_annotation(case)
        now = datetime.utcnow()
        for record in records:
            if record.case_closed_at is not None:
                # Mar lezartnak lattuk: csak a meg itelet nelkulieket potoljuk (az elemzoi cimke marad).
                if record.ground_truth is None and disposition is not None:
                    record.ground_truth = disposition
                    record.labeled_at = now
                    record.case_closure_note = note
                    labeled.append(record)
                continue
            record.case_closed_at = now
            record.case_closure_note = note
            if disposition is not None and record.ground_truth != disposition:
                # A lezaras az IRIS-ben a vegso itelet, felulirja a korabbi cimket.
                record.ground_truth = disposition
                record.labeled_at = now
                labeled.append(record)
        await session.commit()
    logger.info("case sync: IRIS case %s closed (outcome %s) -> %s", case_id, case.get("status_id"),
                disposition.value if disposition else "no disposition")
    return labeled


async def case_info(session: AsyncSession, case_id: int) -> dict:
    # Az IRIS eset aktualis allapota; lezart esetnel a tarolt annotacio is frissul.
    records = await get_records_in_cases(session, {case_id})
    if not records:
        raise CaseActionError(404, "case not found")
    try:
        case = await iris_client.get_case(case_id)
    except Exception as exc:
        logger.warning("IRIS case %s could not be read: %s", case_id, exc)
        raise CaseActionError(502, "incident management backend unavailable") from exc
    if case is None:
        raise CaseActionError(404, "case not found in IRIS")

    closed = bool(case.get("close_date"))
    note = closure_annotation(case)
    if closed:
        if any(r.case_closed_at is None or r.ground_truth is None for r in records):
            await _apply_closed_case(session, case_id, case)
        stale = [r for r in records if r.case_closure_note != note]
        if stale:
            # A lezaras utan irt vagy javitott annotacio is megjelenjen.
            for record in stale:
                record.case_closure_note = note
            await session.commit()
    try:
        status_id = int(case.get("status_id") or 0)
    except (TypeError, ValueError):
        status_id = 0
    return {
        "iris_case_id": case_id,
        "case_url": iris_client.case_url(case_id),
        "closed": closed,
        "close_date": str(case["close_date"]) if closed else None,
        "outcome": OUTCOME_NAMES.get(status_id),
        "closure_annotation": note,
    }
