# Automatikus IP blokkolas: eszkalalt brute force riasztas publikus, rossz hiru forras IP-jere (dry_run / enforce).

import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import status
from app.config import settings
from app.enrichment import enrich_ip
from app.enums import AlertStatus
from app.models import AlertRecord, ResponseAction
from app.response import ResponseError, block_ip, validate_ip
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
    active = await session.scalar(select(func.count()).select_from(ResponseAction).where(
        ResponseAction.action == "block_ip", ResponseAction.ip == ip, ResponseAction.expires_at > now,
        ResponseAction.status.in_(counted)))
    if active:
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
    status.record_success("auto_block", {"alert": record.display_id, "ip": ip, "decision": decision})
    return action
