# Host kontextus: Wazuh-bol szinkronizalt host adatok, kezi szerep, ismert halozatok; az LLM promptjaba kerul.

import asyncio
import ipaddress
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import status
from app.db import async_session
from app.models import HostProfile, KnownNetwork
from app.wazuh_client import wazuh_client

logger = logging.getLogger("siemantics.hosts")

CRITICALITIES = ("low", "medium", "high", "critical")
_MAX_PORTS = 40


def _ports_summary(items: list[dict]) -> list[str]:
    # "tcp/22 sshd" alak; TCP-bol csak a figyelok, egyedi port + protokoll szerint.
    seen: dict[tuple[str, int], str] = {}
    for item in items:
        protocol = str(item.get("protocol") or "").lower()
        state = str(item.get("state") or "").lower()
        if protocol.startswith("tcp") and state not in ("listening", "listen"):
            continue
        port = (item.get("local") or {}).get("port")
        if port is None:
            continue
        key = (protocol.rstrip("6") or protocol, int(port))
        seen.setdefault(key, str(item.get("process") or "").strip())
    ordered = sorted(seen.items(), key=lambda kv: (kv[0][1], kv[0][0]))
    return [f"{proto}/{port}" + (f" {proc}" if proc else "") for (proto, port), proc in ordered][:_MAX_PORTS]


def _wazuh_fields(agent: dict) -> dict:
    os_info = agent.get("os") or {}
    return {
        "status": agent.get("status"),
        "ip": agent.get("ip"),
        "os": " ".join(p for p in (os_info.get("name"), os_info.get("version")) if p) or None,
        "platform": os_info.get("platform"),
        "groups": agent.get("group") or [],
        "agent_version": agent.get("version"),
        "last_keepalive": agent.get("lastKeepAlive"),
    }


async def sync_hosts(session: AsyncSession) -> dict:
    # Az eredmeny (vagy a hiba) a Rendszerallapot fulre is.
    try:
        result = await _sync_hosts(session)
    except Exception as exc:
        status.record_failure("host_sync", exc)
        raise
    status.record_success("host_sync", result)
    return result


async def _sync_hosts(session: AsyncSession) -> dict:
    # Wazuh agentek -> HostProfile; a kezi mezok erintetlenek, a Wazuh-bol eltunt hostok jelolest kapnak.
    agents = await wazuh_client.list_agents_detailed()
    profiles = {p.agent_name: p for p in (await session.execute(select(HostProfile))).scalars()}
    now = datetime.utcnow()
    seen: set[str] = set()
    created = 0
    for agent in agents:
        name = agent.get("name")
        if not name:
            continue
        seen.add(name)
        fields = _wazuh_fields(agent)
        if agent.get("status") == "active":
            try:
                fields["listening_ports"] = _ports_summary(await wazuh_client.listening_ports(agent["id"]))
            except Exception as exc:
                logger.warning("host sync: ports of %s could not be read: %s", name, exc)
        profile = profiles.get(name)
        if profile is None:
            profile = HostProfile(agent_name=name)
            session.add(profile)
            created += 1
        elif "listening_ports" not in fields and profile.wazuh:
            # Nem aktiv agentnel a korabbi portlista megmarad.
            fields["listening_ports"] = profile.wazuh.get("listening_ports") or []
        profile.agent_id = agent.get("id")
        profile.wazuh = fields
        profile.in_wazuh = True
        profile.synced_at = now
    removed = 0
    for name, profile in profiles.items():
        if name not in seen and profile.in_wazuh:
            profile.in_wazuh = False
            removed += 1
    await session.commit()
    logger.info("host sync: %d agent(s), %d new, %d no longer in Wazuh", len(seen), created, removed)
    return {"hosts": len(seen), "created": created, "removed": removed}


def _network(cidr: str):
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None


def _as_ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def profile_ips(profile: HostProfile) -> set[str]:
    # Kezi IP-k es a Wazuh altal ismert agent IP ("any" nelkul).
    ips = {ip for ip in (profile.ips or []) if ip}
    wazuh_ip = _as_ip((profile.wazuh or {}).get("ip") or "")
    if wazuh_ip:
        ips.add(wazuh_ip)
    return ips


async def load_profiles(session: AsyncSession) -> list[HostProfile]:
    return list((await session.execute(select(HostProfile))).scalars())


def host_by_ip(profiles: list[HostProfile], ip: str | None) -> HostProfile | None:
    ip = _as_ip(ip) if ip else None
    return next((p for p in profiles if ip and ip in profile_ips(p)), None) if ip else None


def describe_host(profile: HostProfile, matched_by: str | None = None) -> dict:
    context = {"name": profile.agent_name, "role": profile.role, "criticality": profile.criticality,
               "notes": profile.notes, "ips": sorted(profile.ips or []) or None, "matched_by": matched_by}
    context.update({k: v for k, v in (profile.wazuh or {}).items() if k not in ("agent_version", "last_keepalive")})
    return {k: v for k, v in context.items() if v not in (None, "", [])}


async def ip_context(session: AsyncSession, ip: str | None, profiles: list[HostProfile] | None = None) -> dict | None:
    # A legszukebb ismert halozat cimkeje (es ha ismert host IP-je, a host), kulonben a cim tipusa.
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    host = host_by_ip(profiles if profiles is not None else await load_profiles(session), ip)
    host_info = {"host": host.agent_name, "host_role": host.role} if host else {}
    networks = (await session.execute(select(KnownNetwork))).scalars()
    matches = [(net, n) for n in networks if (net := _network(n.cidr)) and address.version == net.version and address in net]
    if matches:
        net, best = max(matches, key=lambda m: m[0].prefixlen)
        return {"ip": ip, "known_as": best.label, "network": str(net), "trusted": best.trusted,
                **{k: v for k, v in host_info.items() if v}}
    scope = "public" if address.is_global else "private/internal, not documented"
    if host:
        scope = "internal host in the inventory"
    return {"ip": ip, "known_as": None, "scope": scope, **{k: v for k, v in host_info.items() if v}}


def _event_field(alert, *keys: str) -> str | None:
    return next((alert.event_fields[k] for k in keys if alert.event_fields.get(k)), None)


async def host_context(session: AsyncSession, alert, profiles: list[HostProfile] | None = None) -> dict | None:
    # A riasztast ado eszkoz: agent neve; a manager altal tovabbitottnal a kuldo IP (location) vagy hostname.
    profiles = profiles if profiles is not None else await load_profiles(session)
    if alert.agent_id != "000" and alert.agent_name:
        profile = next((p for p in profiles if p.agent_name == alert.agent_name), None)
        if profile is not None:
            return describe_host(profile)
        # Agentes host, de ismeretlen nev: az agent IP-je meg azonosithatja.
        by_ip = host_by_ip(profiles, alert.agent_ip)
        if by_ip is not None:
            return describe_host(by_ip, matched_by=f"agent IP {alert.agent_ip}")
        return {"name": alert.agent_name, "profile": "unknown host, no inventory data"}
    location_ip = _as_ip(alert.location or "")
    by_location = host_by_ip(profiles, location_ip)
    if by_location is not None:
        return describe_host(by_location, matched_by=f"syslog sender {location_ip}")
    hostname = (_event_field(alert, "predecoder.hostname") or "").strip().lower()
    if hostname:
        by_name = next((p for p in profiles if p.agent_name.lower() == hostname), None)
        if by_name is not None:
            return describe_host(by_name, matched_by=f"hostname {hostname}")
    return None


async def destination_host(session: AsyncSession, alert, profiles: list[HostProfile] | None = None) -> dict | None:
    # A forgalom celja, ha ismert host (pl. Suricata riasztasnal a megtamadott gep).
    ip = _event_field(alert, "data.dstip", "data.dest_ip", "data.dst_ip")
    profile = host_by_ip(profiles if profiles is not None else await load_profiles(session), ip)
    return describe_host(profile, matched_by=f"destination IP {ip}") if profile else None


class HostSyncer:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    def start(self, interval_minutes: int) -> None:
        if interval_minutes > 0 and wazuh_client.enabled:
            self._task = asyncio.create_task(self._run(interval_minutes * 60))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self, interval_seconds: int) -> None:
        while True:
            try:
                async with async_session() as session:
                    await sync_hosts(session)
            except Exception:
                logger.exception("host sync failed")
            await asyncio.sleep(interval_seconds)


host_syncer = HostSyncer()
