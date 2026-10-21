# Valaszlepes: tamado IP blokkolasa a Wazuh Active Response-szal (Linux: firewall-drop, Windows: netsh).

import ipaddress
import logging
import time
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
    who = "automatically by SIEMantics" if action.automatic else f"by **{username}** from SIEMantics"
    rows = "\n".join(
        f"| {t['name']} ({t['id']}) | `{t['command']}` | {'ok' if t['ok'] else 'failed: ' + (t.get('error') or '')} |"
        for t in action.targets or []
    )
    return (
        f"**{action.ip}** blocked {who} ({record.display_id}) for {hours} h, "
        f"until {action.expires_at:%Y-%m-%d %H:%M} UTC.\n\n"
        f"| Agent | Command | Result |\n|---|---|---|\n{rows}\n\n"
        "The block is lifted automatically by the Wazuh agent when it expires."
    )


async def block_ip(
    session: AsyncSession,
    record: AlertRecord,
    ip: str,
    scope: str,
    duration_seconds: int,
    user: User | None,
    *,
    dry_run: bool = False,
    reason: str | None = None,
) -> ResponseAction:
    # user None: automatikus blokkolas; dry_run: a celpontokat kiszamolja, de nem kuld parancsot.
    actor = user.username if user else "SIEMantics (automatic)"
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
            if dry_run:
                targets += [{"id": a["id"], "name": a.get("name"), "command": command, "ok": None, "error": None}
                            for a in group]
                continue
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
    if dry_run:
        status = "dry_run"
    else:
        status = "sent" if succeeded == len(targets) else "partial" if succeeded else "failed"
    now = datetime.utcnow()
    action = ResponseAction(
        alert_record_id=record.id,
        action="block_ip",
        ip=ip,
        scope=scope,
        duration_seconds=duration_seconds,
        targets=targets,
        status=status,
        error_detail=reason if dry_run else (
            "; ".join(f"{t['name']}: {t['error']}" for t in targets if not t["ok"]) or None),
        requested_by_id=user.id if user else None,
        automatic=user is None,
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
                record.iris_case_id, f"response ({actor})", [(f"IP blocked: {ip}", _note(action, record, actor))]
            )
            action.iris_noted = True
        except Exception:
            logger.warning("response note to IRIS case %s failed", record.iris_case_id, exc_info=True)
    await session.commit()
    logger.warning("%s %s %s on %d agent(s) for %d s (%s)", actor, "would block" if dry_run else "blocked",
                   ip, len(targets), duration_seconds, record.display_id)
    return action


async def list_actions(session: AsyncSession, record: AlertRecord) -> list[ResponseAction]:
    result = await session.execute(
        select(ResponseAction).where(ResponseAction.alert_record_id == record.id).order_by(ResponseAction.created_at.desc())
    )
    actions = list(result.scalars())
    # Az agent mashonnan (masik riasztasbol, Kornyezet fulrol) inditott izolalasa is az allapothoz tartozik.
    agent_id = _record_agent_id(record)
    if agent_id:
        seen = {a.id for a in actions}
        actions += [a for a in (await isolation_actions(session, {agent_id})).get(agent_id, []) if a.id not in seen]
        actions.sort(key=lambda a: (a.created_at, a.id), reverse=True)
    return actions


# --- Gep izolalas: a wazuh/active-response/ script az agenten, csak a Wazuh manager (es a megadott cimek) marad elerheto

_LINUX_ISOLATE = "siemantics-isolate"
_WINDOWS_ISOLATE = "win-siemantics-isolate"


def isolation_allowlist() -> list[str]:
    # A beallitott cimek es a Wazuh manager IP-je; nelkule nem izolalunk (az agent nem erne el a managert).
    entries = [e.strip() for e in settings.response_isolation_allow.split(",") if e.strip()]
    host = urlparse(settings.wazuh_api_url).hostname if settings.wazuh_api_url else None
    if host:
        entries.append(host)
    allowed = []
    for entry in entries:
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            continue
        if ip.version == 4 and str(ip) not in allowed:
            allowed.append(str(ip))
    if not allowed:
        raise ResponseError(503, "no IPv4 address to keep reachable: set RESPONSE_ISOLATION_ALLOW to the Wazuh manager IP")
    return allowed


def _isolate_command(agent: dict) -> str:
    platform = ((agent.get("os") or {}).get("platform") or "").lower()
    return _WINDOWS_ISOLATE if platform == "windows" else _LINUX_ISOLATE


def _record_agent_id(record: AlertRecord) -> str:
    return (((record.raw_payload or {}).get("agent") or {}).get("id") or "").strip()


async def _isolation_target(agent_id: str) -> dict:
    if not agent_id or agent_id == "000":
        raise ResponseError(422, "no own agent (the Wazuh manager cannot be isolated)")
    agents = await wazuh_client.get_agents([agent_id])
    if not agents:
        raise ResponseError(404, f"Wazuh agent {agent_id} not found")
    agent = agents[0]
    protected = {h.strip().lower() for h in settings.response_protected_hosts.split(",") if h.strip()}
    if (agent.get("name") or "").lower() in protected:
        raise ResponseError(422, f"{agent.get('name')} is a protected host and cannot be isolated")
    return agent


def _isolation_note(action: ResponseAction, source: str, username: str, allowed: list[str]) -> str:
    target = (action.targets or [{}])[0]
    if action.action == "release_host":
        return (f"Host **{target.get('name')}** released from isolation by **{username}** from SIEMantics "
                f"({source}).")
    hours = action.duration_seconds // 3600
    return (
        f"Host **{target.get('name')}** isolated by **{username}** from SIEMantics ({source}) for {hours} h, "
        f"until {action.expires_at:%Y-%m-%d %H:%M} UTC. Only {', '.join(allowed)} stays reachable.\n\n"
        "The agent lifts the isolation by itself when it expires; it can also be released earlier from SIEMantics."
    )


async def _run_isolation(
    session: AsyncSession, agent_id: str, record: AlertRecord | None, user: User, *, release: bool,
    duration_seconds: int = 0, confirm_hostname: str | None = None,
) -> ResponseAction:
    # A riasztas nelkuli (Kornyezet fulrol inditott) lepes nem kerul IRIS esetbe.
    source = record.display_id if record else "Environment tab"
    if not wazuh_client.enabled:
        raise ResponseError(503, "Wazuh API is not configured (WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD)")
    if not release and duration_seconds not in DURATIONS_SECONDS:
        raise ResponseError(422, f"duration must be one of {DURATIONS_SECONDS} seconds")
    allowed = isolation_allowlist()
    try:
        agent = await _isolation_target(agent_id)
        if not release:
            if (confirm_hostname or "").strip().lower() != (agent.get("name") or "").lower():
                raise ResponseError(422, f"type the host name ({agent.get('name')}) to confirm the isolation")
            if agent.get("status") != "active":
                raise ResponseError(409, f"Wazuh agent {agent.get('name')} is not active")
        command = f"{_isolate_command(agent)}{0 if release else duration_seconds}"
        # A lejarat ideje a Windows ertesito ablakhoz (a Linux script figyelmen kivul hagyja).
        until = int(time.time()) + duration_seconds
        arguments = ["release"] if release else ["isolate", *allowed, f"until={until}"]
        ok, failed = await wazuh_client.run_command(command, [agent["id"]], {"data": {}}, arguments)
    except ResponseError:
        raise
    except Exception as exc:
        logger.exception("host isolation request failed for %s", source)
        raise ResponseError(502, f"Wazuh API unavailable: {exc}") from exc

    error = failed.get(agent["id"]) or (None if agent["id"] in ok else "no confirmation from Wazuh")
    now = datetime.utcnow()
    action = ResponseAction(
        alert_record_id=record.id if record else None,
        action="release_host" if release else "isolate_host",
        ip=str(agent.get("ip") or "-"),
        scope="agent",
        duration_seconds=0 if release else duration_seconds,
        targets=[{"id": agent["id"], "name": agent.get("name"), "command": command, "ok": error is None, "error": error}],
        status="sent" if error is None else "failed",
        error_detail=error,
        requested_by_id=user.id,
        created_at=now,
        expires_at=now if release else now + timedelta(seconds=duration_seconds),
        iris_case_id=record.iris_case_id if record else None,
        iris_noted=False,
        automatic=False,
    )
    session.add(action)
    await session.flush()
    if record and record.iris_case_id and error is None:
        title = f"Host released: {agent.get('name')}" if release else f"Host isolated: {agent.get('name')}"
        try:
            await iris_client.add_case_notes(record.iris_case_id, f"response ({user.username})",
                                             [(title, _isolation_note(action, source, user.username, allowed))])
            action.iris_noted = True
        except Exception:
            logger.warning("isolation note to IRIS case %s failed", record.iris_case_id, exc_info=True)
    await session.commit()
    logger.warning("%s %s host %s (%s): %s", user.username, "released" if release else "isolated",
                   agent.get("name"), source, action.status)
    return action


async def isolate_host(
    session: AsyncSession, record: AlertRecord, duration_seconds: int, user: User, confirm_hostname: str
) -> ResponseAction:
    return await _run_isolation(session, _record_agent_id(record), record, user, release=False,
                                duration_seconds=duration_seconds, confirm_hostname=confirm_hostname)


async def release_host(session: AsyncSession, record: AlertRecord, user: User) -> ResponseAction:
    return await _run_isolation(session, _record_agent_id(record), record, user, release=True)


async def isolate_agent(
    session: AsyncSession, agent_id: str, duration_seconds: int, user: User, confirm_hostname: str
) -> ResponseAction:
    return await _run_isolation(session, agent_id, None, user, release=False, duration_seconds=duration_seconds,
                                confirm_hostname=confirm_hostname)


async def release_agent(session: AsyncSession, agent_id: str, user: User) -> ResponseAction:
    return await _run_isolation(session, agent_id, None, user, release=True)


async def isolation_actions(session: AsyncSession, agent_ids: set[str]) -> dict[str, list[ResponseAction]]:
    # Agentenkent az izolalas / feloldas lepesek, a legujabb elol (barhonnan inditottak).
    rows = (await session.execute(
        select(ResponseAction).where(ResponseAction.action.in_(("isolate_host", "release_host")))
        .order_by(ResponseAction.created_at.desc(), ResponseAction.id.desc())
    )).scalars()
    out: dict[str, list[ResponseAction]] = {}
    for action in rows:
        agent_id = ((action.targets or [{}])[0] or {}).get("id")
        if agent_id in agent_ids:
            out.setdefault(agent_id, []).append(action)
    return out


def active_isolation(actions: list[ResponseAction]) -> ResponseAction | None:
    # A legutobbi sikeres lepes szamit: le nem jart izolalas, vagy feloldas.
    for action in actions:
        if action.status != "sent":
            continue
        if action.action == "isolate_host" and action.expires_at > datetime.utcnow():
            return action
        return None
    return None
