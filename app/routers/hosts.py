import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_context_editor
from app.db import get_session
from app.hosts import sync_hosts
from app.models import HostProfile, KnownNetwork, User
from app.repository import get_users_by_ids
from app.schemas import AssigneeOut, HostCreate, HostProfileOut, HostUpdate, KnownNetworkIn, KnownNetworkOut
from app.wazuh_client import wazuh_client

router = APIRouter(prefix="/api/v1", tags=["environment"])


async def _hosts_out(session: AsyncSession, hosts: list[HostProfile]) -> list[HostProfileOut]:
    users = await get_users_by_ids(session, [h.updated_by_id for h in hosts if h.updated_by_id is not None])
    out = []
    for host in hosts:
        item = HostProfileOut.model_validate(host)
        if host.updated_by_id in users:
            item.updated_by = AssigneeOut.model_validate(users[host.updated_by_id])
        out.append(item)
    return out


def _apply(host: HostProfile, body: HostUpdate, user: User) -> None:
    for field in ("role", "criticality", "notes"):
        value = getattr(body, field)
        if value is not None:
            setattr(host, field, value.strip() or None)
    if body.ips is not None:
        host.ips = body.ips or None
    host.updated_by_id = user.id
    host.updated_at = datetime.utcnow()


@router.get("/hosts", response_model=list[HostProfileOut], dependencies=[Depends(get_current_user)])
async def list_hosts(session: AsyncSession = Depends(get_session)):
    hosts = (await session.execute(select(HostProfile).order_by(HostProfile.agent_name))).scalars()
    return await _hosts_out(session, list(hosts))


@router.post("/hosts/sync", dependencies=[Depends(require_context_editor)])
async def sync_now(session: AsyncSession = Depends(get_session)):
    # Azonnali szinkron a Wazuh API-bol (alapbol orankent a hatterben is fut).
    if not wazuh_client.enabled:
        raise HTTPException(status_code=503, detail="Wazuh API is not configured")
    try:
        return await sync_hosts(session)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh API unavailable: {exc}") from exc


@router.post("/hosts", response_model=HostProfileOut, status_code=status.HTTP_201_CREATED)
async def add_host(
    body: HostCreate, user: User = Depends(require_context_editor), session: AsyncSession = Depends(get_session)
):
    name = body.agent_name.strip()
    exists = (await session.execute(select(HostProfile).where(HostProfile.agent_name == name))).scalars().first()
    if exists is not None:
        raise HTTPException(status_code=409, detail="host already exists")
    host = HostProfile(agent_name=name, in_wazuh=False)
    _apply(host, body, user)
    session.add(host)
    await session.commit()
    return (await _hosts_out(session, [host]))[0]


@router.patch("/hosts/{host_id}", response_model=HostProfileOut)
async def update_host(
    host_id: int, body: HostUpdate, user: User = Depends(require_context_editor),
    session: AsyncSession = Depends(get_session),
):
    host = await session.get(HostProfile, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    _apply(host, body, user)
    await session.commit()
    return (await _hosts_out(session, [host]))[0]


@router.delete("/hosts/{host_id}", dependencies=[Depends(require_context_editor)])
async def delete_host(host_id: int, session: AsyncSession = Depends(get_session)):
    # Csak a Wazuh-ban nem (mar nem) levo host torolheto; a tobbit a szinkron ugyis visszahozna.
    host = await session.get(HostProfile, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    if host.in_wazuh:
        raise HTTPException(status_code=409, detail="host is an active Wazuh agent, it would come back on the next sync")
    await session.delete(host)
    await session.commit()
    return {"deleted": host.agent_name}


@router.get("/networks", response_model=list[KnownNetworkOut], dependencies=[Depends(get_current_user)])
async def list_networks(session: AsyncSession = Depends(get_session)):
    return list((await session.execute(select(KnownNetwork).order_by(KnownNetwork.cidr))).scalars())


def _normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid IP address or network: {value}") from exc


@router.post("/networks", response_model=KnownNetworkOut, status_code=status.HTTP_201_CREATED)
async def add_network(
    body: KnownNetworkIn, user: User = Depends(require_context_editor), session: AsyncSession = Depends(get_session)
):
    cidr = _normalize_cidr(body.cidr)
    if (await session.execute(select(KnownNetwork).where(KnownNetwork.cidr == cidr))).scalars().first():
        raise HTTPException(status_code=409, detail="network already exists")
    network = KnownNetwork(cidr=cidr, label=body.label.strip(), trusted=body.trusted, created_by_id=user.id)
    session.add(network)
    await session.commit()
    return network


@router.put("/networks/{network_id}", response_model=KnownNetworkOut, dependencies=[Depends(require_context_editor)])
async def update_network(network_id: int, body: KnownNetworkIn, session: AsyncSession = Depends(get_session)):
    network = await session.get(KnownNetwork, network_id)
    if network is None:
        raise HTTPException(status_code=404, detail="network not found")
    network.cidr = _normalize_cidr(body.cidr)
    network.label = body.label.strip()
    network.trusted = body.trusted
    await session.commit()
    return network


@router.delete("/networks/{network_id}", dependencies=[Depends(require_context_editor)])
async def delete_network(network_id: int, session: AsyncSession = Depends(get_session)):
    network = await session.get(KnownNetwork, network_id)
    if network is None:
        raise HTTPException(status_code=404, detail="network not found")
    await session.delete(network)
    await session.commit()
    return {"deleted": network.cidr}
