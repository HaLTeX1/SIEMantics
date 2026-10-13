import asyncio
import logging
import re

import httpx

from app.config import settings

logger = logging.getLogger("siemantics.enrichment")

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_TIMEOUT = 10.0


async def _query_virustotal(client: httpx.AsyncClient, ip: str) -> dict | None:
    if not settings.virustotal_api_key:
        return None
    try:
        resp = await client.get(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
        }
    except Exception as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", ip, exc)
        return None


async def _query_abuseipdb(client: httpx.AsyncClient, ip: str) -> dict | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


async def enrich_ip(client: httpx.AsyncClient, ip: str) -> dict:
    virustotal, abuseipdb = await asyncio.gather(
        _query_virustotal(client, ip),
        _query_abuseipdb(client, ip),
    )
    return {"ioc": ip, "virustotal": virustotal, "abuseipdb": abuseipdb}


async def enrich_iocs(iocs: list[str]) -> list[dict]:
    # IP IoC-k enrichmentje VirusTotal/AbuseIPDB-vel; kulcs nelkul kimarad, hiba nem blokkol.

    if not settings.virustotal_api_key and not settings.abuseipdb_api_key:
        return []

    unique_ips = list(dict.fromkeys(ioc for ioc in iocs if _IP_RE.match(ioc)))
    unique_ips = unique_ips[: settings.enrichment_max_iocs]
    if not unique_ips:
        return []

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(enrich_ip(client, ip) for ip in unique_ips))
    return list(results)
