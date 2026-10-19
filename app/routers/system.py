import time
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import status
from app.auth import require_context_editor
from app.config import settings
from app.db import get_session
from app.enums import AlertStatus
from app.iris_client import iris_client
from app.llm_engine import configured_models, key_info, llm_configured, second_opinion_enabled
from app.models import AlertRecord, IpBan, LoginFailure, ResponseAction
from app.pipeline import alert_queue
from app.routers.alerts import ignored_counter
from app.surrounding import indexer_client
from app.auto_block import sweep_open_cases
from app.wazuh_client import wazuh_client

router = APIRouter(prefix="/api/v1/system", tags=["system"], dependencies=[Depends(require_context_editor)])

# A Rendszerallapot fulon latszo, nem titkos beallitasok.
_VISIBLE_SETTINGS = (
    "openrouter_model", "openrouter_timeout_seconds", "second_opinion_model", "require_fp_corroboration",
    "history_min_agreement", "review_confidence_threshold", "review_severity_floor", "triage_workers",
    "triage_settle_seconds", "llm_retry_max_hours", "dedup_window_hours", "flood_threshold", "flood_window_minutes",
    "correlation_window_hours", "correlation_host_window_minutes", "correlation_max_alerts", "ignored_rule_groups",
    "context_rule_groups", "iris_sync_interval_seconds", "host_sync_interval_minutes", "iris_base_url",
    "iris_verify_ssl", "wazuh_api_url", "wazuh_api_verify_ssl", "wazuh_indexer_url", "wazuh_indexer_indices",
    "wazuh_indexer_verify_ssl", "wazuh_indexer_via_dashboard", "surrounding_minutes", "surrounding_max_events", "enrichment_max_iocs",
    "login_max_failures", "login_failure_window_minutes", "login_ban_minutes", "login_ban_max_minutes",
    "trusted_proxy_ips", "login_ban_exempt", "auto_block_mode", "auto_block_rule_groups",
    "auto_block_min_abuse_score", "auto_block_duration_hours", "auto_block_scope", "auto_block_max_per_hour",
    "auto_close_after_block", "auto_close_success_lookback_hours", "auto_close_mode", "auto_close_stale_hours",
    "auto_close_sweep_minutes",
    "session_ttl_hours",
)
# Titkok: csak az latszik, hogy be vannak-e allitva.
_SECRETS = ("openrouter_api_key", "iris_api_key", "wazuh_webhook_token", "wazuh_api_password", "wazuh_indexer_password",
            "virustotal_api_key", "abuseipdb_api_key")


async def _scalar(session: AsyncSession, stmt):
    return (await session.execute(stmt)).scalar()


@router.get("/status")
async def system_status(session: AsyncSession = Depends(get_session)):
    now = datetime.utcnow()
    queued = AlertRecord.status == AlertStatus.QUEUED
    day_ago = now - timedelta(hours=24)
    return {
        "generated_at": now,
        "llm": {
            "configured": llm_configured(),
            "models": configured_models(),
            "second_opinion": settings.second_opinion_model if second_opinion_enabled() else None,
            "paused_seconds": round(alert_queue.pause_remaining()),
            **status.snapshot("llm"),
        },
        "queue": {
            "queued": await _scalar(session, select(func.count()).where(queued)),
            "waiting_for_llm": await _scalar(session, select(func.count()).where(
                queued, AlertRecord.error_detail.like("waiting for the LLM%"))),
            "oldest_queued_at": await _scalar(session, select(func.min(AlertRecord.received_at)).where(queued)),
            "in_memory": alert_queue.size(),
            "workers": settings.triage_workers,
        },
        "ingest": {
            "last_alert_at": await _scalar(session, select(func.max(AlertRecord.received_at))),
            "alerts_24h": await _scalar(session, select(func.count()).where(AlertRecord.received_at >= day_ago)),
            "context_24h": await _scalar(session, select(func.count()).where(
                AlertRecord.received_at >= day_ago, AlertRecord.triage_engine == "context")),
            "ignored_since_start": ignored_counter["count"],
        },
        "iris_sync": {"interval_seconds": settings.iris_sync_interval_seconds, **status.snapshot("iris_sync")},
        "host_sync": {"interval_minutes": settings.host_sync_interval_minutes, "enabled": wazuh_client.enabled,
                      **status.snapshot("host_sync")},
        "indexer": {"enabled": indexer_client.enabled, "indices": settings.wazuh_indexer_indices,
                    **status.snapshot("indexer")},
        "login_protection": {
            "enabled": settings.login_max_failures > 0,
            "active_bans": await _scalar(session, select(func.count()).select_from(IpBan).where(
                IpBan.until > now, IpBan.lifted_at.is_(None))),
            "bans_24h": await _scalar(session, select(func.count()).select_from(IpBan).where(IpBan.created_at >= day_ago)),
            "failures_24h": await _scalar(session, select(func.count()).select_from(LoginFailure).where(
                LoginFailure.attempted_at >= day_ago)),
            "trusted_proxies": bool(settings.trusted_proxy_ips.strip()),
            **status.snapshot("login_proxy"),
        },
        "auto_block": {
            "mode": settings.auto_block_mode,
            "enabled": settings.auto_block_mode != "off" and wazuh_client.enabled,
            "actions_24h": await _scalar(session, select(func.count()).select_from(ResponseAction).where(
                ResponseAction.automatic.is_(True), ResponseAction.created_at >= day_ago)),
            **status.snapshot("auto_block"),
        },
        "auto_close": {"mode": settings.auto_close_mode, "after_block": settings.auto_close_after_block,
                       **status.snapshot("auto_close")},
        "settings": {name: getattr(settings, name) for name in _VISIBLE_SETTINGS},
        "secrets_set": {name: bool(getattr(settings, name)) for name in _SECRETS},
    }


async def _check(name: str, coro_factory) -> dict:
    started = time.perf_counter()
    try:
        detail = await coro_factory()
        ok = True
    except Exception as exc:
        detail, ok = str(exc)[:300], False
    return {"name": name, "ok": ok, "latency_ms": round((time.perf_counter() - started) * 1000), "detail": detail}


@router.post("/test-connections")
async def test_connections():
    # IRIS ping, Wazuh API bejelentkezes, OpenRouter kulcs adatai; egyik sem fogyaszt LLM kvotat.
    results = [await _check("DFIR-IRIS", iris_client.ping)]
    if wazuh_client.enabled:
        async def wazuh():
            info = await wazuh_client.api_info()
            return f"API {info.get('api_version', '?')} @ {info.get('hostname', '?')}"
        results.append(await _check("Wazuh API", wazuh))
    else:
        results.append({"name": "Wazuh API", "ok": None, "latency_ms": None, "detail": "not configured"})
    if indexer_client.enabled:
        results.append(await _check("Wazuh indexer", indexer_client.describe))
    else:
        results.append({"name": "Wazuh indexer", "ok": None, "latency_ms": None, "detail": "not configured"})
    if llm_configured():
        async def openrouter():
            info = await key_info()
            tier = "free tier (no credits)" if info.get("is_free_tier") else "credits purchased"
            return f"{tier}, usage {info.get('usage')}, limit {info.get('limit')}"
        results.append(await _check("OpenRouter", openrouter))
    else:
        results.append({"name": "OpenRouter", "ok": None, "latency_ms": None, "detail": "not configured (mock engine)"})
    return results


@router.get("/auto-close")
async def auto_close_candidates(session: AsyncSession = Depends(get_session)):
    # A regebbi nyitott brute force esetek lezarhatosaga (semmit nem zar le).
    return await sweep_open_cases(session, enforce=False)


@router.post("/auto-close/run")
async def auto_close_now(session: AsyncSession = Depends(get_session)):
    # Jovahagyott lezaras most, az uzemmodtol fuggetlenul: a lezarhato jeloltek TPNI-vel.
    return await sweep_open_cases(session, enforce=True)
