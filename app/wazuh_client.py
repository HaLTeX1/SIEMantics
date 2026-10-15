import logging
import time

import httpx

from app.config import settings

logger = logging.getLogger("siemantics.wazuh")

# A JWT alapbol 900 mp-ig el, elotte ujat kerunk.
_TOKEN_TTL_SECONDS = 600


class WazuhApiError(Exception):
    pass


class WazuhClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._token_at = 0.0

    @property
    def enabled(self) -> bool:
        return bool(settings.wazuh_api_url and settings.wazuh_api_user and settings.wazuh_api_password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=settings.wazuh_api_url.rstrip("/"), timeout=20, verify=settings.wazuh_api_verify_ssl
        )

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            "/security/user/authenticate", auth=(settings.wazuh_api_user, settings.wazuh_api_password)
        )
        if resp.status_code != 200:
            raise WazuhApiError(f"Wazuh API authentication failed (HTTP {resp.status_code})")
        self._token = resp.json()["data"]["token"]
        self._token_at = time.monotonic()
        return self._token

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        # Lejart tokennel (401) egyszer ujra hitelesit.
        async with self._client() as client:
            for attempt in (1, 2):
                token = self._token
                if token is None or time.monotonic() - self._token_at > _TOKEN_TTL_SECONDS:
                    token = await self._authenticate(client)
                resp = await client.request(method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs)
                if resp.status_code == 401 and attempt == 1:
                    self._token = None
                    continue
                if resp.status_code >= 400:
                    raise WazuhApiError(f"Wazuh API {method} {path} failed: HTTP {resp.status_code} {resp.text[:300]}")
                return resp.json()
        raise WazuhApiError("Wazuh API authentication failed")

    async def get_agents(self, agent_ids: list[str] | None = None, *, active_only: bool = False) -> list[dict]:
        params: dict = {"select": "id,name,status,os.platform", "limit": 10000}
        if agent_ids:
            params["agents_list"] = ",".join(agent_ids)
        if active_only:
            params["status"] = "active"
        body = await self._request("GET", "/agents", params=params)
        return body["data"]["affected_items"]

    async def run_command(self, command: str, agent_ids: list[str], alert: dict) -> tuple[list[str], dict[str, str]]:
        # (sikeres agent ID-k, {agent ID: hiba}).
        body = await self._request(
            "PUT", "/active-response", params={"agents_list": ",".join(agent_ids)},
            json={"command": command, "alert": alert},
        )
        data = body.get("data") or {}
        failed: dict[str, str] = {}
        for item in data.get("failed_items") or []:
            message = (item.get("error") or {}).get("message") or "failed"
            for agent_id in item.get("id") or []:
                failed[str(agent_id)] = message
        return [str(a) for a in data.get("affected_items") or []], failed


wazuh_client = WazuhClient()
