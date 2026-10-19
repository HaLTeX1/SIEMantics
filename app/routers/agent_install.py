from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from app import agent_install
from app.agent_install import InstallError
from app.auth import require_admin
from app.config import settings
from app.wazuh_client import wazuh_client

# A telepito scripteket a gepek bejelentkezes nelkul toltik le (titkot nem tartalmaznak).
public = APIRouter(prefix="/agent-install", tags=["agent install"])
admin = APIRouter(prefix="/api/v1/agent-install", tags=["agent install"], dependencies=[Depends(require_admin)])

_NO_STORE = {"Cache-Control": "no-store"}
_version_cache: dict[str, str] = {}


class CommandRequest(BaseModel):
    os: Literal["linux", "windows"]
    name: str = Field(default="", max_length=64)
    group: str = Field(default="", max_length=256)
    manager: str = Field(default="", max_length=253)
    version: str = Field(default="", max_length=16)


def _base_url(request: Request) -> str:
    return (settings.siemantics_public_url or str(request.base_url)).rstrip("/")


async def _default_version() -> str:
    # A Wazuh API verzioja (az agent nem lehet ujabb a managernel), kulonben a beallitas.
    if settings.wazuh_agent_version:
        return settings.wazuh_agent_version
    if "api" not in _version_cache and wazuh_client.enabled:
        try:
            _version_cache["api"] = str((await wazuh_client.api_info()).get("api_version") or "").lstrip("v")
        except Exception:
            return ""
    return _version_cache.get("api", "")


async def _resolve(manager: str, version: str) -> tuple[str, str]:
    manager = manager or agent_install.default_manager()
    version = version or await _default_version()
    try:
        agent_install.validate("", "", manager, version)
    except InstallError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return manager, version


@public.get("/linux.sh", response_class=PlainTextResponse)
async def linux_script(request: Request, manager: str = "", version: str = ""):
    manager, version = await _resolve(manager, version)
    return PlainTextResponse(agent_install.linux_script(_base_url(request), manager, version),
                             media_type="text/x-shellscript", headers=_NO_STORE)


@public.get("/windows.ps1", response_class=PlainTextResponse)
async def windows_script(request: Request, manager: str = "", version: str = ""):
    manager, version = await _resolve(manager, version)
    return PlainTextResponse(agent_install.windows_script(_base_url(request), manager, version),
                             media_type="text/plain", headers=_NO_STORE)


@public.get("/files/{name}")
async def ar_file(name: str):
    # Bajtra pontosan (a .ps1 BOM-javal), csak a felsorolt fajlok.
    try:
        data = agent_install.ar_file(name)
    except InstallError as exc:
        raise HTTPException(status_code=404, detail="file not found") from exc
    return Response(content=data, media_type="application/octet-stream", headers=_NO_STORE)


@admin.get("/defaults")
async def defaults(request: Request):
    return {"manager": agent_install.default_manager(), "version": await _default_version(),
            "base_url": _base_url(request),
            "files": {name: agent_install.sha256(name) for name in agent_install.AR_FILES}}


@admin.post("/command")
async def make_command(body: CommandRequest, request: Request):
    manager, version = await _resolve(body.manager.strip(), body.version.strip())
    try:
        command = agent_install.command(body.os, _base_url(request), body.name.strip(), body.group.strip(),
                                        manager, version)
    except InstallError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"os": body.os, "command": command, "manager": manager, "version": version}
