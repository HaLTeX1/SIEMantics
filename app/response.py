# Valaszlepes: tamado IP blokkolasa a Wazuh Active Response-szal (Linux: firewall-drop, Windows: netsh).

import ipaddress
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.iris_client import iris_client
from app.models import AlertRecord, ResponseAction, User
from app.wazuh_client import wazuh_client

logger = logging.getLogger("siemantics.response")

# Az ossec.conf <active-response> blokkjainak timeoutjai; az ar.conf parancsnev: <parancs><timeout>.
DURATIONS_SECONDS = (3600, 86400, 604800)
_LINUX_COMMAND = "firewall-drop"
_WINDOWS_COMMAND = "netsh"


class ResponseError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _protected_networks() -> list:
    # Beallitott halozatok, plusz az IRIS, a Wazuh es a SIEMantics sajat IP-je, ha IP-vel van megadva.
    entries = [e.strip() for e in settings.response_protected_networks.split(",") if e.strip()]
    for url in (settings.iris_base_url, settings.wazuh_api_url, settings.siemantics_public_url):
        host = urlparse(url).hostname if url else None
        if host:
            entries.append(host)
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return networks


def validate_ip(value: str) -> str:
    # Csak publikus, nem vedett cim blokkolhato, hogy ne zarjuk ki magunkat.
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ResponseError(422, f"invalid IP address: {value}") from exc
    if not ip.is_global:
        raise ResponseError(422, f"{ip} is not a public address, it cannot be blocked")
    if any(ip.version == net.version and ip in net for net in _protected_networks()):
        raise ResponseError(422, f"{ip} is in a protected network")
    return str(ip)


def _command_for(agent: dict, seconds: int) -> str:
    platform = ((agent.get("os") or {}).get("platform") or "").lower()
    return f"{_WINDOWS_COMMAND if platform == 'windows' else _LINUX_COMMAND}{seconds}"


async def _targets(record: AlertRecord, scope: str) -> list[dict]:
    if scope == "all":
        agents = await wazuh_client.get_agents(active_only=True)
        if not agents:
            raise ResponseError(409, "no active Wazuh agent")
        return agents
    agent_id = (((record.raw_payload or {}).get("agent") or {}).get("id") or "").strip()
    if not agent_id or agent_id == "000":
        # A manager riasztasai (tuzfal, felho, Suricata) mas eszkozrol jonnek: ott a host nem a vedett gep.
        raise ResponseError(422, "the alert has no own agent, block on all agents instead")
    agents = await wazuh_client.get_agents([agent_id])
    if not agents:
        raise ResponseError(404, f"Wazuh agent {agent_id} not found")
    if agents[0].get("status") != "active":
        raise ResponseError(409, f"Wazuh agent {agents[0].get('name') or agent_id} is not active")
    return agents


def _note(action: ResponseAction, record: AlertRecord, username: str) -> str:
    hours = action.duration_seconds // 3600
    rows = "\n".join(
        f"| {t['name']} ({t['id']}) | `{t['command']}` | {'ok' if t['ok'] else 'failed: ' + (t.get('error') or '')} |"
        for t in action.targets or []
    )
    return (
        f"**{action.ip}** blocked by **{username}** from SIEMantics ({record.display_id}) for {hours} h, "
        f"until {action.expires_at:%Y-%m-%d %H:%M} UTC.\n\n"
        f"| Agent | Command | Result |\n|---|---|---|\n{rows}\n\n"
        "The block is lifted automatically by the Wazuh agent when it expires."
    )


async def block_ip(
    session: AsyncSession, record: AlertRecord, ip: str, scope: str, duration_seconds: int, user: User
) -> ResponseAction:
    if not wazuh_client.enabled:
        raise ResponseError(503, "Wazuh API is not configured (WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD)")
    if duration_seconds not in DURATIONS_SECONDS:
        raise ResponseError(422, f"duration must be one of {DURATIONS_SECONDS} seconds")
    ip = validate_ip(ip)
    try:
        agents = await _targets(record, scope)
        by_command: dict[str, list[dict]] = {}
        for agent in agents:
            by_command.setdefault(_command_for(agent, duration_seconds), []).append(agent)

        targets = []
        for command, group in by_command.items():
            ok, failed = await wazuh_client.run_command(command, [a["id"] for a in group], {"data": {"srcip": ip}})
            for agent in group:
                error = failed.get(agent["id"]) or (None if agent["id"] in ok else "no confirmation from Wazuh")
                targets.append({"id": agent["id"], "name": agent.get("name"), "command": command,
                                "ok": error is None, "error": error})
    except ResponseError:
        raise
    except Exception as exc:
        logger.exception("blocking %s failed", ip)
        raise ResponseError(502, f"Wazuh API unavailable: {exc}") from exc

    succeeded = sum(1 for t in targets if t["ok"])
    now = datetime.utcnow()
    action = ResponseAction(
        alert_record_id=record.id,
        action="block_ip",
        ip=ip,
        scope=scope,
        duration_seconds=duration_seconds,
        targets=targets,
        status="sent" if succeeded == len(targets) else "partial" if succeeded else "failed",
        error_detail="; ".join(f"{t['name']}: {t['error']}" for t in targets if not t["ok"]) or None,
        requested_by_id=user.id,
        created_at=now,
        expires_at=now + timedelta(seconds=duration_seconds),
        iris_case_id=record.iris_case_id,
        iris_noted=False,
    )
    session.add(action)
    await session.flush()

    if record.iris_case_id and succeeded:
        try:
            await iris_client.add_case_notes(
                record.iris_case_id, f"response ({user.username})", [(f"IP blocked: {ip}", _note(action, record, user.username))]
            )
            action.iris_noted = True
        except Exception:
            logger.warning("response note to IRIS case %s failed", record.iris_case_id, exc_info=True)
    await session.commit()
    logger.warning("%s blocked %s on %d/%d agent(s) for %d s (%s)",
                   user.username, ip, succeeded, len(targets), duration_seconds, record.display_id)
    return action


async def list_actions(session: AsyncSession, record: AlertRecord) -> list[ResponseAction]:
    result = await session.execute(
        select(ResponseAction).where(ResponseAction.alert_record_id == record.id).order_by(ResponseAction.created_at.desc())
    )
    return list(result.scalars())
