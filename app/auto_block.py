# Automatikus IP blokkolas: eszkalalt brute force riasztas publikus, rossz hiru forras IP-jere (dry_run / enforce).

import asyncio
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import status
from app.config import settings
from app.enrichment import enrich_ip
from app.enums import AlertStatus, GroundTruth
from app.iris_client import OUTCOME_TP_NO_IMPACT, iris_client
from app.models import AlertRecord, ResponseAction
from app.db import async_session
from app.repository import get_case_assignments, get_records_in_cases
from app.response import ResponseError, block_ip, validate_ip
from app.surrounding import indexer_client
from app.wazuh_client import wazuh_client

logger = logging.getLogger("siemantics.auto_block")


def _groups(record: AlertRecord) -> set[str]:
    return {str(g).lower() for g in (((record.raw_payload or {}).get("rule") or {}).get("groups") or [])}


async def _abuse_score(record: AlertRecord, ip: str) -> int | None:
    # A dusitasbol, kulonben kozvetlen AbuseIPDB lekeres (ha van kulcs).
    for entry in record.ioc_enrichment or []:
        if entry.get("ioc") == ip and (entry.get("abuseipdb") or {}).get("abuse_confidence_score") is not None:
            return int(entry["abuseipdb"]["abuse_confidence_score"])
    if not settings.abuseipdb_api_key:
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        result = await enrich_ip(client, ip)
    score = (result.get("abuseipdb") or {}).get("abuse_confidence_score")
    return int(score) if score is not None else None


async def _skip_reason(session: AsyncSession, record: AlertRecord, ip: str | None) -> str | None:
    # None: mehet a blokkolas; kulonben az ok, amiert nem.
    wanted = {g.strip().lower() for g in settings.auto_block_rule_groups.split(",") if g.strip()}
    if not wanted & _groups(record):
        return "rule group not selected for automatic blocking"
    if not ip:
        return "no source IP"
    try:
        validate_ip(ip)
    except ResponseError as exc:
        return exc.detail
    agent_id = (((record.raw_payload or {}).get("agent") or {}).get("id") or "")
    if settings.auto_block_scope == "agent" and agent_id in ("", "000"):
        return "alert relayed by the Wazuh manager; set AUTO_BLOCK_SCOPE=all to block on all agents"
    now = datetime.utcnow()
    # Proba modban a korabbi proba is szamit, eles modban csak a valodi blokk.
    counted = ("sent", "partial", "dry_run") if settings.auto_block_mode == "dry_run" else ("sent", "partial")
    active = (await session.execute(select(ResponseAction).where(
        ResponseAction.action == "block_ip", ResponseAction.ip == ip, ResponseAction.expires_at > now,
        ResponseAction.status.in_(counted)))).scalars()
    # Mar blokkolt: minden agenten, vagy (agent hatokornel) ezen a hoston.
    if any(a.scope == "all" or (settings.auto_block_scope == "agent"
                                and any(t.get("id") == agent_id for t in a.targets or []))
           for a in active):
        return "already blocked"
    recent = await session.scalar(select(func.count()).select_from(ResponseAction).where(
        ResponseAction.automatic.is_(True), ResponseAction.created_at >= now - timedelta(hours=1)))
    if recent >= settings.auto_block_max_per_hour:
        return f"hourly limit reached ({settings.auto_block_max_per_hour})"
    if settings.auto_block_min_abuse_score > 0:
        score = await _abuse_score(record, ip)
        if score is None:
            return "no AbuseIPDB score available"
        if score < settings.auto_block_min_abuse_score:
            return f"AbuseIPDB score {score} < {settings.auto_block_min_abuse_score}"
    return None


async def _successful_login(ip: str, until: datetime, since: datetime | None = None) -> bool | None:
    # Volt-e sikeres belepes az IP-rol (a 3-as szintu esemenyek csak az indexerben vannak); None: nem ellenorizheto.
    if not indexer_client.enabled:
        return None
    since = since or until - timedelta(hours=settings.auto_close_success_lookback_hours)
    body = {
        "size": 1,
        "_source": ["timestamp", "rule.id"],
        "query": {"bool": {"filter": [
            {"term": {"data.srcip": ip}},
            {"term": {"rule.groups": "authentication_success"}},
            {"range": {"timestamp": {"gte": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                     "lte": until.strftime("%Y-%m-%dT%H:%M:%S.000Z")}}},
        ]}},
    }
    try:
        return bool(await indexer_client.search(body))
    except Exception as exc:
        logger.warning("auto close: login history of %s could not be checked: %s", ip, exc)
        return None


async def _close_skip_reason(session: AsyncSession, record: AlertRecord, ip: str) -> str | None:
    # None: az eset lezarhato "True positive without impact"-tel.
    if not settings.auto_close_after_block:
        return "automatic closing is off"
    if not record.iris_case_id:
        return "no IRIS case"
    wanted = {g.strip().lower() for g in settings.auto_block_rule_groups.split(",") if g.strip()}
    members = await get_records_in_cases(session, {record.iris_case_id})
    if any(not (wanted & _groups(m)) for m in members):
        return "the case has other than brute force alerts"
    success = await _successful_login(ip, datetime.utcnow())
    if success is None:
        return "cannot check for successful logins (Wazuh indexer not configured or unavailable)"
    if success:
        return "a successful login from this IP was seen, the attack may have succeeded"
    return None


async def _auto_close(session: AsyncSession, record: AlertRecord, ip: str, action: ResponseAction) -> str:
    hosts = ", ".join(t.get("name") or t.get("id") for t in action.targets or [] if t.get("ok"))
    note = (f"Automatically closed by SIEMantics: brute force from {ip} was blocked on {hosts} for "
            f"{action.duration_seconds // 3600} h, and no successful login from this IP was seen in the "
            f"{settings.auto_close_success_lookback_hours} h before the block. TPNI.")
    return await close_case_tpni(session, record.iris_case_id, note)


async def close_case_tpni(session: AsyncSession, case_id: int, note: str) -> str:
    # Lezaras az IRIS-ben (note, tag, kimenet, annotacio) es a SIEMantics-ben (cimke: auto, nem elemzoi itelet).
    try:
        await iris_client.add_case_notes(case_id, "auto-close (SIEMantics)", [("Closed automatically", note)])
        await iris_client.add_case_tags(case_id, ["auto-closed"])
        await iris_client.set_case_outcome(case_id, OUTCOME_TP_NO_IMPACT)
        await iris_client.set_closure_annotation(case_id, note)
        await iris_client.close_case(case_id)
    except Exception as exc:
        logger.warning("auto close of IRIS case %s failed: %s", case_id, exc)
        return f"case #{case_id} could not be closed in IRIS: {exc}"
    now = datetime.utcnow()
    for member in await get_records_in_cases(session, {case_id}):
        member.ground_truth = GroundTruth.TRUE_POSITIVE
        member.label_source = "auto"
        member.labeled_at = now
        member.case_closed_at = now
        member.case_closure_note = note
    await session.commit()
    logger.warning("auto close: IRIS case %s closed as true positive without impact", case_id)
    return f"case #{case_id} closed as true positive without impact"


async def maybe_auto_block(session: AsyncSession, record: AlertRecord) -> ResponseAction | None:
    # Csak a rendszer altal eszkalalt riasztasra; hiba eseten nem akasztja meg a triazst.
    if settings.auto_block_mode == "off" or not wazuh_client.enabled:
        return None
    if record.status != AlertStatus.ESCALATED or record.auto_status != AlertStatus.ESCALATED:
        return None
    ip = record.source_ip
    try:
        reason = await _skip_reason(session, record, ip)
        if reason is not None:
            logger.info("auto block skipped for %s (%s): %s", record.display_id, ip, reason)
            status.record_success("auto_block", {"alert": record.display_id, "ip": ip, "decision": f"skipped: {reason}"})
            return None
        dry_run = settings.auto_block_mode == "dry_run"
        action = await block_ip(
            session, record, ip, settings.auto_block_scope, settings.auto_block_duration_hours * 3600, None,
            dry_run=dry_run, reason="dry run: AUTO_BLOCK_MODE=dry_run, nothing was sent" if dry_run else None,
        )
    except Exception as exc:
        logger.exception("auto block of %s for %s failed", ip, record.display_id)
        status.record_failure("auto_block", exc)
        return None
    decision = "would block (dry run)" if action.status == "dry_run" else f"blocked ({action.status})"
    try:
        close_reason = await _close_skip_reason(session, record, ip)
        if close_reason is not None:
            decision += f"; case not closed: {close_reason}"
        elif action.status == "dry_run":
            decision += f"; would close case #{record.iris_case_id} as true positive without impact"
        elif action.status == "sent":
            decision += "; " + await _auto_close(session, record, ip, action)
    except Exception as exc:
        logger.exception("auto close after blocking %s failed", ip)
        decision += f"; case not closed: {exc}"
    status.record_success("auto_block", {"alert": record.display_id, "ip": ip, "decision": decision})
    return action


# --- Regebbi nyitott brute force esetek idoszakos lezarasa

_SWEEP_LIMIT = 50


async def _active_block_ips(session: AsyncSession, ips: set[str]) -> set[str]:
    now = datetime.utcnow()
    result = await session.execute(select(ResponseAction.ip).where(
        ResponseAction.action == "block_ip", ResponseAction.ip.in_(ips), ResponseAction.expires_at > now,
        ResponseAction.status.in_(("sent", "partial"))))
    return set(result.scalars())


async def close_candidates(session: AsyncSession) -> list[dict]:
    # Nyitott, csak brute force riasztasokat tartalmazo, felelos nelkuli esetek, a lezarhatosag indoklasaval.
    wanted = {g.strip().lower() for g in settings.auto_block_rule_groups.split(",") if g.strip()}
    result = await session.execute(select(AlertRecord).where(
        AlertRecord.iris_case_id.is_not(None), AlertRecord.case_closed_at.is_(None)))
    cases: dict[int, list[AlertRecord]] = {}
    for record in result.scalars():
        cases.setdefault(record.iris_case_id, []).append(record)
    assigned = await get_case_assignments(session, list(cases))
    now = datetime.utcnow()
    out = []
    for case_id, members in sorted(cases.items()):
        if any(not (wanted & _groups(m)) for m in members):
            continue
        ips = {m.source_ip for m in members if m.source_ip}
        last = max(m.received_at for m in members)
        first = min(m.received_at for m in members)
        item = {"case_id": case_id, "ips": sorted(ips), "hosts": sorted({m.agent_name for m in members if m.agent_name}),
                "alerts": len(members), "first_alert": first, "last_alert": last, "closable": False, "reason": None}
        out.append(item)
        if case_id in assigned:
            item["reason"] = "the case has an assignee"
            continue
        if not ips:
            item["reason"] = "no source IP"
            continue
        blocked = await _active_block_ips(session, ips)
        item["blocked"] = sorted(blocked)
        quiet = now - last >= timedelta(hours=settings.auto_close_stale_hours)
        if not quiet and blocked != ips:
            item["reason"] = f"attack seen in the last {settings.auto_close_stale_hours} h and IP not blocked"
            continue
        since = first - timedelta(hours=settings.auto_close_success_lookback_hours)
        checks = [await _successful_login(ip, now, since) for ip in sorted(ips)]
        if any(c is None for c in checks):
            item["reason"] = "cannot check for successful logins (Wazuh indexer not configured or unavailable)"
            continue
        if any(checks):
            item["reason"] = "a successful login from this IP was seen, the attack may have succeeded"
            continue
        item["closable"] = True
        item["quiet_hours"] = int((now - last).total_seconds() // 3600)
    return out


def _stale_note(item: dict) -> str:
    blocked = f"; blocked: {', '.join(item['blocked'])}" if item.get("blocked") else ""
    return (f"Automatically closed by SIEMantics: brute force from {', '.join(item['ips'])} against "
            f"{', '.join(item['hosts']) or 'the host'} ({item['alerts']} alert(s)) stopped {item['quiet_hours']} h ago"
            f"{blocked}, and no successful login from these IPs was seen since "
            f"{item['first_alert']:%Y-%m-%d %H:%M} UTC (minus {settings.auto_close_success_lookback_hours} h). TPNI.")


async def sweep_open_cases(session: AsyncSession, *, enforce: bool) -> dict:
    # A lezarhato jeloltek; enforce eseten le is zarja oket (IRIS-ben meg nyitott esetek, legfeljebb _SWEEP_LIMIT).
    candidates = await close_candidates(session)
    closable = [c for c in candidates if c["closable"]][:_SWEEP_LIMIT]
    closed, failed = [], []
    if enforce:
        for item in closable:
            try:
                if not await iris_client.is_open(item["case_id"]):
                    continue
            except Exception as exc:
                failed.append({"case_id": item["case_id"], "error": str(exc)})
                continue
            result = await close_case_tpni(session, item["case_id"], _stale_note(item))
            (closed if "closed as true positive" in result else failed).append(
                {"case_id": item["case_id"], "result": result})
    summary = {"mode": "enforce" if enforce else "dry_run", "candidates": len(candidates),
               "closable": [c["case_id"] for c in closable], "closed": [c["case_id"] for c in closed],
               "failed": failed}
    status.record_success("auto_close", summary)
    return {**summary, "items": candidates}


class AutoCloseSweeper:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if settings.auto_close_mode != "off" and settings.auto_close_sweep_minutes > 0:
            self._task = asyncio.create_task(self._run(settings.auto_close_sweep_minutes * 60))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self, interval_seconds: int) -> None:
        while True:
            try:
                async with async_session() as session:
                    await sweep_open_cases(session, enforce=settings.auto_close_mode == "enforce")
            except Exception as exc:
                logger.exception("auto close sweep failed")
                status.record_failure("auto_close", exc)
            await asyncio.sleep(interval_seconds)


auto_close_sweeper = AutoCloseSweeper()
