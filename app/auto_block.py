# Automatikus IP blokkolas: eszkalalt brute force riasztas publikus, rossz hiru forras IP-jere (dry_run / enforce).

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
from app.repository import get_records_in_cases
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


async def _successful_login(ip: str, until: datetime) -> bool | None:
    # Volt-e sikeres belepes az IP-rol a blokkolas elott (a 3-as szintu esemenyek csak az indexerben vannak).
    if not indexer_client.enabled:
        return None
    since = until - timedelta(hours=settings.auto_close_success_lookback_hours)
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
    # A megfekezett brute force eset lezarasa az IRIS-ben es a SIEMantics-ben (cimke: auto, nem elemzoi itelet).
    case_id = record.iris_case_id
    hosts = ", ".join(t.get("name") or t.get("id") for t in action.targets or [] if t.get("ok"))
    note = (f"Automatically closed by SIEMantics: brute force from {ip} was blocked on {hosts} for "
            f"{action.duration_seconds // 3600} h, and no successful login from this IP was seen in the "
            f"{settings.auto_close_success_lookback_hours} h before the block. TPNI.")
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
    logger.warning("auto close: IRIS case %s closed as true positive without impact (%s)", case_id, ip)
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
