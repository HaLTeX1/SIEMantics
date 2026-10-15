# Kornyezo esemenyek a Wazuh indexerbol: ugyanannak a hostnak (vagy forras IP-nek) a riasztas koruli esemenyei.

import logging
from datetime import datetime, timedelta, timezone

import httpx

from app import status
from app.config import settings
from app.iris_report import WAZUH_TS_FORMATS
from app.schemas import NormalizedAlert

logger = logging.getLogger("siemantics.surrounding")

_SOURCE_FIELDS = ["timestamp", "id", "rule.id", "rule.level", "rule.description", "rule.groups", "agent.name",
                  "agent.id", "data.srcip", "data.dstuser", "full_log", "location", "decoder.name"]
_LOG_LIMIT = 240


class IndexerClient:
    @property
    def enabled(self) -> bool:
        return bool(settings.wazuh_indexer_url and settings.wazuh_indexer_user and settings.wazuh_indexer_password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=settings.wazuh_indexer_url.rstrip("/"),
            auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
            verify=settings.wazuh_indexer_verify_ssl,
            timeout=10,
        )

    async def info(self) -> dict:
        async with self._client() as client:
            resp = await client.get("/")
            resp.raise_for_status()
            return resp.json()

    async def search(self, body: dict) -> list[dict]:
        async with self._client() as client:
            resp = await client.post(f"/{settings.wazuh_indexer_indices}/_search", json=body)
            resp.raise_for_status()
            return [hit["_source"] for hit in resp.json().get("hits", {}).get("hits", [])]


indexer_client = IndexerClient()


def alert_time(alert: NormalizedAlert) -> datetime:
    # A Wazuh timestamp UTC-re, kulonben a beerkezes ideje.
    for fmt in WAZUH_TS_FORMATS:
        try:
            return datetime.strptime(alert.timestamp or "", fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    return alert.received_at.replace(tzinfo=timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _scope_filter(alert: NormalizedAlert) -> dict | None:
    # A manager (000) riasztasai mas eszkozrol jonnek: ott a forras IP kapcsol ossze, maskor a host.
    if alert.agent_id != "000" and alert.agent_name:
        return {"term": {"agent.name": alert.agent_name}}
    if alert.source_ip:
        return {"term": {"data.srcip": alert.source_ip}}
    return None


def _compact(event: dict, own_id: str | None) -> dict:
    rule = event.get("rule") or {}
    data = event.get("data") or {}
    log = str(event.get("full_log") or "").strip()
    return {
        "time": event.get("timestamp"),
        "this_alert": bool(own_id) and event.get("id") == own_id,
        "rule_id": rule.get("id"),
        "level": rule.get("level"),
        "rule": rule.get("description"),
        "groups": (rule.get("groups") or [])[:4],
        "agent": (event.get("agent") or {}).get("name"),
        "srcip": data.get("srcip"),
        "user": data.get("dstuser"),
        "location": event.get("location"),
        "log": log[:_LOG_LIMIT] + ("..." if len(log) > _LOG_LIMIT else ""),
    }


async def surrounding_events(
    alert: NormalizedAlert, minutes: int | None = None, max_events: int | None = None, *, include_self: bool = False
) -> list[dict]:
    # A triazshoz: hibanal ures lista, hogy az indexer kiesese ne akassza meg a dontest.
    try:
        return await fetch_surrounding(alert, minutes, max_events, include_self=include_self)
    except Exception as exc:
        logger.warning("surrounding events for %s could not be read: %s", alert.alert_id, exc)
        return []


async def fetch_surrounding(
    alert: NormalizedAlert, minutes: int | None = None, max_events: int | None = None, *, include_self: bool = False
) -> list[dict]:
    # A riasztashoz legkozelebbi esemenyek idorendben (felerol elotte, felerol utana); hibanal kivetel.
    if not indexer_client.enabled:
        return []
    scope = _scope_filter(alert)
    if scope is None:
        return []
    minutes = minutes or settings.surrounding_minutes
    half = max((max_events or settings.surrounding_max_events) // 2, 1)
    center = alert_time(alert)
    window = timedelta(minutes=minutes)

    def query(gte: datetime, lte: datetime, order: str) -> dict:
        return {
            "size": half,
            "sort": [{"timestamp": {"order": order}}],
            "_source": _SOURCE_FIELDS,
            "query": {"bool": {"filter": [scope, {"range": {"timestamp": {"gte": _iso(gte), "lte": _iso(lte)}}}]}},
        }

    try:
        before = await indexer_client.search(query(center - window, center, "desc"))
        after = await indexer_client.search(query(center + timedelta(milliseconds=1), center + window, "asc"))
    except Exception as exc:
        status.record_failure("indexer", exc)
        raise
    status.record_success("indexer", {"events": len(before) + len(after)})
    events = [_compact(e, alert.alert_id) for e in reversed(before)] + [_compact(e, alert.alert_id) for e in after]
    return events if include_self else [e for e in events if not e["this_alert"]]
