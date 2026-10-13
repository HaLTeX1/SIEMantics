import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import AlertStatus, GroundTruth
from app.iris_client import iris_client
from app.iris_report import MergedAlert, false_positive_note, merge_note, merged_away_note
from app.models import AlertRecord, User
from app.normalize import related_log_excerpt
from app.pipeline import manual_escalate
from app.repository import get_alert_record_by_ref, get_records_in_cases

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
    closed_cases: list[int] = field(default_factory=list)
    close_failed: list[int] = field(default_factory=list)


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

        # A kijelolt riasztasok meglevo eseteinek minden riasztasa is atkerul.
        members = {r.id: r for r in selected}
        for record in await get_records_in_cases(session, {r.iris_case_id for r in selected if r.iris_case_id}):
            members.setdefault(record.id, record)
        members_list = sorted(members.values(), key=lambda r: r.received_at)

        try:
            target_case = await _first_open_case(members_list)
            if target_case is None:
                # Egyiknek sincs nyitott esete: a legkorabbibol nyitunk egyet, TP cimke nelkul.
                await manual_escalate(session, members_list[0], user, label_true_positive=False)
                target_case = members_list[0].iris_case_id
        except Exception as exc:
            logger.exception("merge: target case could not be prepared")
            raise CaseActionError(502, "incident management backend unavailable") from exc

        target = next(r for r in members_list if r.iris_case_id == target_case)
        moved = [r for r in members_list if r.iris_case_id != target_case]
        if not moved:
            raise CaseActionError(409, "the selected alerts are already in one case")

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

        outcome = MergeOutcome(target=target, merged=moved)
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
        await session.commit()
        logger.info("%s merged %d alert(s) into IRIS case %s", user.username, len(moved), target_case)
        return outcome


async def _close_merged(case_id: int, target_case: int, username: str) -> bool:
    try:
        if not await iris_client.is_open(case_id):
            return True
        await iris_client.add_case_notes(case_id, f"merged into #{target_case}",
                                         [("Merged", merged_away_note(target_case, username))])
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


async def close_as_false_positive(
    session: AsyncSession, case_id: int, user: User, reason: str | None
) -> tuple[list[AlertRecord], bool]:
    async with _lock:
        records = await get_records_in_cases(session, {case_id})
        if not records:
            raise CaseActionError(404, "case not found")

        try:
            was_open = await iris_client.is_open(case_id)
            if was_open:
                note = false_positive_note(user.username, reason, [r.display_id for r in records])
                await iris_client.add_case_notes(case_id, f"false positive ({user.username})",
                                                 [("Closed as false positive", note)])
                await _best_effort(iris_client.add_case_tags(case_id, ["false-positive"]), f"tagging case {case_id}")
                await iris_client.close_case(case_id)
        except Exception as exc:
            logger.exception("closing IRIS case %s as false positive failed", case_id)
            raise CaseActionError(502, "incident management backend unavailable") from exc

        # Az eset minden riasztasa FP cimket kap, igy a metrikakba is bekerul.
        now = datetime.utcnow()
        for record in records:
            record.ground_truth = GroundTruth.FALSE_POSITIVE
            record.labeled_at = now
        await session.commit()
        logger.info("%s closed IRIS case %s as false positive (%d alert(s))", user.username, case_id, len(records))
        return records, was_open
