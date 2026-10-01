import logging

import httpx

from app.config import settings
from app.iris_report import (
    CaseContext,
    asset_description,
    asset_os,
    case_description,
    case_name,
    case_notes,
    case_tags,
    ioc_description,
    ioc_tags,
    ioc_type_name,
)
from app.schemas import IrisCaseResult, NormalizedAlert, TriageResult

logger = logging.getLogger("siemantics.iris")

NOTE_GROUP_TITLE = "SIEMantics"

# IRIS alap ID-k: TLP:AMBER es "To be done" statusz.
_TLP_AMBER = 2
_ANALYSIS_TO_BE_DONE = 2

# IRIS alap severity nevek.
_IRIS_SEVERITY = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

# IRIS alap asset tipusok OS szerint.
_IRIS_ASSET_TYPE = {"windows": "Windows - Computer", "linux": "Linux - Server"}


class IrisClient:
    def __init__(self) -> None:
        self._base_url = settings.iris_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.iris_api_key}",
            "Content-Type": "application/json",
        }
        # Tipus ID cache, hogy ne kelljen minden hivasnal lekerdezni.
        self._ioc_type_ids: dict[str, int] | None = None
        self._asset_type_ids: dict[str, int] | None = None
        self._severity_ids: dict[str, int] | None = None

    async def create_case_from_alert(
        self,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None = None,
        *,
        display_id: str,
        escalated_by: str | None = None,
        raw_payload: dict | None = None,
    ) -> IrisCaseResult:
        ctx = CaseContext(
            display_id=display_id,
            alert=alert,
            triage=triage,
            enrichment=enrichment or [],
            raw=raw_payload or {},
            escalated_by=escalated_by,
        )
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        ) as client:
            case_id = await self._create_case(client, ctx)

            group_id = await self._create_note_group(client, case_id, display_id)
            for title, content in case_notes(ctx):
                await self._add_note(client, case_id, group_id, title, content)

            # Az eset mar letezik, ezert innentol a hibakat csak logoljuk.
            for ioc in triage.iocs:
                await self._best_effort(f"IOC {ioc!r}", self._add_ioc(client, case_id, ctx, ioc), case_id)
            if ctx.agent.get("name") or alert.agent_name:
                await self._best_effort("asset", self._add_asset(client, case_id, ctx), case_id)
            await self._best_effort("severity/tags", self._update_case_meta(client, case_id, ctx), case_id)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(self, client: httpx.AsyncClient, ctx: CaseContext) -> int:
        payload = {
            "case_name": case_name(ctx),
            "case_description": case_description(ctx),
            "case_soc_id": ctx.alert.alert_id,
            "case_customer": settings.iris_customer_id,
        }
        resp = await self._post(client, "/manage/cases/add", json=payload)
        return resp.json()["data"]["case_id"]

    async def _create_note_group(self, client: httpx.AsyncClient, case_id: int, display_id: str) -> int:
        # A group title max 256 karakter.
        resp = await self._post(
            client,
            "/case/notes/groups/add",
            params={"cid": case_id},
            json={"group_title": f"{NOTE_GROUP_TITLE} {display_id}"},
        )
        return resp.json()["data"]["group_id"]

    async def _add_note(self, client: httpx.AsyncClient, case_id: int, group_id: int, title: str, content: str) -> None:
        payload = {"group_id": group_id, "note_title": title, "note_content": content}
        await self._post(client, "/case/notes/add", params={"cid": case_id}, json=payload)

    async def _lookup(self, client: httpx.AsyncClient, path: str, name_key: str, id_key: str) -> dict[str, int]:
        resp = await self._get(client, path)
        return {row[name_key]: row[id_key] for row in resp.json()["data"]}

    async def _add_ioc(self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext, ioc_value: str) -> None:
        if self._ioc_type_ids is None:
            self._ioc_type_ids = await self._lookup(client, "/manage/ioc-types/list", "type_name", "type_id")
        ioc_type_id = self._ioc_type_ids.get(ioc_type_name(ioc_value), self._ioc_type_ids.get("other"))
        if ioc_type_id is None:
            return

        payload = {
            "ioc_value": ioc_value,
            "ioc_type_id": ioc_type_id,
            "ioc_tlp_id": _TLP_AMBER,
            "ioc_description": ioc_description(ctx, ioc_value),
            "ioc_tags": ioc_tags(ctx),
        }
        await self._post(client, "/case/ioc/add", params={"cid": case_id}, json=payload)

    async def _add_asset(self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext) -> None:
        if self._asset_type_ids is None:
            self._asset_type_ids = await self._lookup(client, "/manage/asset-type/list", "asset_name", "asset_id")
        asset_type_id = self._asset_type_ids.get(_IRIS_ASSET_TYPE[asset_os(ctx)])
        if asset_type_id is None:
            return

        payload = {
            "asset_name": ctx.agent.get("name") or ctx.alert.agent_name,
            "asset_type_id": asset_type_id,
            "analysis_status_id": _ANALYSIS_TO_BE_DONE,
            "asset_description": asset_description(ctx),
            "asset_tags": ioc_tags(ctx),
        }
        if ctx.agent.get("ip"):
            payload["asset_ip"] = ctx.agent["ip"]
        await self._post(client, "/case/assets/add", params={"cid": case_id}, json=payload)

    async def _update_case_meta(self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext) -> None:
        if self._severity_ids is None:
            self._severity_ids = await self._lookup(client, "/manage/severities/list", "severity_name", "severity_id")
        payload: dict = {"case_tags": ",".join(case_tags(ctx))}
        severity_id = self._severity_ids.get(_IRIS_SEVERITY[ctx.severity])
        if severity_id is not None:
            payload["severity_id"] = severity_id
        await self._post(client, f"/manage/cases/update/{case_id}", json=payload)

    @staticmethod
    async def _best_effort(what: str, coro, case_id: int) -> None:
        try:
            await coro
        except Exception as exc:
            logger.warning("IRIS case %s: adding %s failed: %s", case_id, what, exc)

    @staticmethod
    async def _post(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
        resp = await client.post(path, **kwargs)
        # Cookie torles, kulonben a kovetkezo hivas 403-at kap.
        client.cookies.clear()
        resp.raise_for_status()
        return resp

    @staticmethod
    async def _get(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
        resp = await client.get(path, **kwargs)
        client.cookies.clear()
        resp.raise_for_status()
        return resp


iris_client = IrisClient()
