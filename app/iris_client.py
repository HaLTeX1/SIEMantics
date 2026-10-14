import logging
import re

import httpx

from app.config import settings
from app.iris_report import (
    TIMELINE_DEFAULT_CATEGORY,
    CaseContext,
    asset_description,
    asset_os,
    case_description,
    case_name,
    case_notes,
    case_tags,
    event_time,
    ioc_description,
    ioc_tags,
    ioc_type_name,
    raise_case_name,
    severity_rank,
    timeline_category,
    timeline_content,
    timeline_raw,
    timeline_source,
    timeline_title,
)
from app.schemas import IrisCaseResult, NormalizedAlert, TriageResult

logger = logging.getLogger("siemantics.iris")

NOTE_GROUP_TITLE = "SIEMantics"

# IRIS alap ID-k: TLP:AMBER es "To be done" statusz.
_TLP_AMBER = 2
_ANALYSIS_TO_BE_DONE = 2

# IRIS eset kimenetel (status_id): 1 false positive, 2/4 true positive, 5 legitimate.
OUTCOME_FALSE_POSITIVE = 1
OUTCOME_TRUE_POSITIVE = (2, 4)
OUTCOME_LEGITIMATE = 5

# IRIS alap severity nevek.
_IRIS_SEVERITY = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

# Az IRIS az eset nevet "#<id> - " elotaggal adja vissza es menteskor maga teszi ele.
_CASE_NUMBER_PREFIX = re.compile(r"^#\d+ - ")

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
        self._event_category_ids: dict[str, int] | None = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        )

    def case_url(self, case_id: int) -> str:
        return f"{self._base_url}/case?cid={case_id}"

    def _result(self, case_id: int) -> IrisCaseResult:
        return IrisCaseResult(case_id=case_id, case_url=self.case_url(case_id))

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
        async with self._client() as client:
            case_id = await self._create_case(client, ctx)
            await self._add_alert_content(client, case_id, ctx, existing_iocs={}, existing_assets={})
            await self._best_effort("severity/tags", self._update_case_meta(client, case_id, ctx), case_id)
            return self._result(case_id)

    async def add_alert_to_case(
        self,
        case_id: int,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None = None,
        *,
        display_id: str,
        correlated_with: str,
        escalated_by: str | None = None,
        raw_payload: dict | None = None,
    ) -> IrisCaseResult | None:
        # Korrelalt riasztas hozzaadasa egy meglevo esethez, None ha az eset lezart vagy nem olvashato.
        ctx = CaseContext(
            display_id=display_id,
            alert=alert,
            triage=triage,
            enrichment=enrichment or [],
            raw=raw_payload or {},
            escalated_by=escalated_by,
            correlated_with=correlated_with,
        )
        async with self._client() as client:
            case = await self._get_case(client, case_id)
            if case is None or case.get("close_date"):
                return None

            existing_iocs = await self._existing(client, case_id, "/case/ioc/list", "ioc", "ioc_value", "ioc_id")
            existing_assets = await self._existing(
                client, case_id, "/case/assets/list", "assets", "asset_name", "asset_id"
            )
            await self._add_alert_content(client, case_id, ctx, existing_iocs, existing_assets)
            await self._best_effort("severity/tags", self._update_case_meta(client, case_id, ctx, case), case_id)
            return self._result(case_id)

    async def is_open(self, case_id: int) -> bool:
        async with self._client() as client:
            case = await self._get_case(client, case_id)
            return case is not None and not case.get("close_date")

    async def add_case_notes(self, case_id: int, group_label: str, notes: list[tuple[str, str]]) -> None:
        # Uj "SIEMantics <label>" note-csoport a megadott note-okkal.
        async with self._client() as client:
            group_id = await self._create_note_group(client, case_id, group_label)
            for title, content in notes:
                await self._add_note(client, case_id, group_id, title, content)

    async def add_case_tags(self, case_id: int, tags: list[str]) -> None:
        async with self._client() as client:
            case = await self._get_case(client, case_id)
            name = _CASE_NUMBER_PREFIX.sub("", (case or {}).get("case_name") or "")
            if not name:
                raise RuntimeError(f"IRIS case {case_id} not readable")
            old = [t for t in str(case.get("case_tags") or "").split(",") if t]
            payload = {"case_name": name, "case_tags": ",".join(dict.fromkeys(old + tags))}
            await self._post(client, f"/manage/cases/update/{case_id}", json=payload)

    async def get_case(self, case_id: int) -> dict | None:
        # Az eset adatai (close_date, status_id, case_tags); None, ha nem letezik.
        async with self._client() as client:
            resp = await client.get(f"/manage/cases/{case_id}")
            client.cookies.clear()
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()["data"]

    async def set_case_outcome(self, case_id: int, status_id: int) -> None:
        async with self._client() as client:
            case = await self._get_case(client, case_id)
            name = _CASE_NUMBER_PREFIX.sub("", (case or {}).get("case_name") or "")
            if not name:
                raise RuntimeError(f"IRIS case {case_id} not readable")
            await self._post(client, f"/manage/cases/update/{case_id}", json={"case_name": name, "status_id": status_id})

    async def close_case(self, case_id: int) -> None:
        async with self._client() as client:
            await self._post(client, f"/manage/cases/close/{case_id}")

    async def _add_alert_content(
        self,
        client: httpx.AsyncClient,
        case_id: int,
        ctx: CaseContext,
        existing_iocs: dict[str, int],
        existing_assets: dict[str, int],
    ) -> None:
        group_id = await self._create_note_group(client, case_id, ctx.display_id)
        for title, content in case_notes(ctx):
            await self._add_note(client, case_id, group_id, title, content)

        # Az eset mar letezik, ezert innentol a hibakat csak logoljuk.
        ioc_ids = []
        for ioc in ctx.triage.iocs:
            ioc_id = existing_iocs.get(ioc)
            if ioc_id is None:
                ioc_id = await self._best_effort(f"IOC {ioc!r}", self._add_ioc(client, case_id, ctx, ioc), case_id)
            if ioc_id is not None:
                ioc_ids.append(ioc_id)

        asset_id = None
        host = ctx.agent.get("name") or ctx.alert.agent_name
        if host:
            asset_id = existing_assets.get(host)
            if asset_id is None:
                asset_id = await self._best_effort("asset", self._add_asset(client, case_id, ctx), case_id)
        await self._best_effort(
            "timeline event", self._add_timeline_event(client, case_id, ctx, asset_id, ioc_ids), case_id
        )

    async def _get_case(self, client: httpx.AsyncClient, case_id: int) -> dict | None:
        try:
            resp = await self._get(client, f"/manage/cases/{case_id}")
            return resp.json()["data"]
        except Exception as exc:
            logger.warning("IRIS case %s could not be read, opening a new case instead: %s", case_id, exc)
            return None

    async def _existing(
        self, client: httpx.AsyncClient, case_id: int, path: str, list_key: str, name_key: str, id_key: str
    ) -> dict[str, int]:
        # A mar meglevo IoC-k / assetek, hogy ne vegyuk fel oket ujra.
        try:
            resp = await self._get(client, path, params={"cid": case_id})
            data = resp.json()["data"]
            rows = data.get(list_key, []) if isinstance(data, dict) else data
            return {row[name_key]: row[id_key] for row in rows}
        except Exception as exc:
            logger.warning("IRIS case %s: listing %s failed: %s", case_id, path, exc)
            return {}

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

    async def _add_ioc(self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext, ioc_value: str) -> int | None:
        if self._ioc_type_ids is None:
            self._ioc_type_ids = await self._lookup(client, "/manage/ioc-types/list", "type_name", "type_id")
        ioc_type_id = self._ioc_type_ids.get(ioc_type_name(ioc_value), self._ioc_type_ids.get("other"))
        if ioc_type_id is None:
            return None

        payload = {
            "ioc_value": ioc_value,
            "ioc_type_id": ioc_type_id,
            "ioc_tlp_id": _TLP_AMBER,
            "ioc_description": ioc_description(ctx, ioc_value),
            "ioc_tags": ioc_tags(ctx),
        }
        resp = await self._post(client, "/case/ioc/add", params={"cid": case_id}, json=payload)
        return resp.json()["data"]["ioc_id"]

    async def _add_asset(self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext) -> int | None:
        if self._asset_type_ids is None:
            self._asset_type_ids = await self._lookup(client, "/manage/asset-type/list", "asset_name", "asset_id")
        asset_type_id = self._asset_type_ids.get(_IRIS_ASSET_TYPE[asset_os(ctx)])
        if asset_type_id is None:
            return None

        payload = {
            "asset_name": ctx.agent.get("name") or ctx.alert.agent_name,
            "asset_type_id": asset_type_id,
            "analysis_status_id": _ANALYSIS_TO_BE_DONE,
            "asset_description": asset_description(ctx),
            "asset_tags": ioc_tags(ctx),
        }
        if ctx.agent.get("ip"):
            payload["asset_ip"] = ctx.agent["ip"]
        resp = await self._post(client, "/case/assets/add", params={"cid": case_id}, json=payload)
        return resp.json()["data"]["asset_id"]

    async def _add_timeline_event(
        self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext, asset_id: int | None, ioc_ids: list[int]
    ) -> None:
        if self._event_category_ids is None:
            self._event_category_ids = await self._lookup(client, "/manage/event-categories/list", "name", "id")
        category_id = self._event_category_ids.get(
            timeline_category(ctx), self._event_category_ids.get(TIMELINE_DEFAULT_CATEGORY)
        )
        event_date, event_tz = event_time(ctx)

        payload = {
            "event_title": timeline_title(ctx),
            "event_date": event_date,
            "event_tz": event_tz,
            "event_content": timeline_content(ctx),
            "event_raw": timeline_raw(ctx),
            "event_source": timeline_source(ctx),
            "event_tags": ioc_tags(ctx),
            "event_assets": [asset_id] if asset_id is not None else [],
            "event_iocs": ioc_ids,
            "event_in_summary": True,
            "event_in_graph": True,
        }
        if category_id is not None:
            payload["event_category_id"] = category_id
        await self._post(client, "/case/timeline/events/add", params={"cid": case_id}, json=payload)

    async def _update_case_meta(
        self, client: httpx.AsyncClient, case_id: int, ctx: CaseContext, existing: dict | None = None
    ) -> None:
        if self._severity_ids is None:
            self._severity_ids = await self._lookup(client, "/manage/severities/list", "severity_name", "severity_id")
        tags = case_tags(ctx)
        # Az IRIS (2.3.7) case_name nelkul elutasitja az update-et, ezert mindig kuldjuk.
        payload: dict = {}

        if existing is None:
            payload["case_name"] = case_name(ctx)
            payload["case_tags"] = ",".join(tags)
            raise_severity = True
        else:
            # Meglevo esetnel a tageket bovitjuk, a severity-t csak emeljuk.
            name = _CASE_NUMBER_PREFIX.sub("", existing.get("case_name") or "")
            if not name:
                logger.warning("IRIS case %s has no name, severity/tags not updated", case_id)
                return
            if existing.get("case_tags") is not None:
                old = [t for t in str(existing["case_tags"]).split(",") if t]
                payload["case_tags"] = ",".join(dict.fromkeys(old + tags))
            names = {v: k for k, v in self._severity_ids.items()}
            current = names.get(existing.get("severity_id"))
            raise_severity = severity_rank(_IRIS_SEVERITY[ctx.severity]) > severity_rank(current)
            payload["case_name"] = raise_case_name(name, ctx) if raise_severity else name

        severity_id = self._severity_ids.get(_IRIS_SEVERITY[ctx.severity])
        if raise_severity and severity_id is not None:
            payload["severity_id"] = severity_id
        await self._post(client, f"/manage/cases/update/{case_id}", json=payload)

    @staticmethod
    async def _best_effort(what: str, coro, case_id: int):
        try:
            return await coro
        except Exception as exc:
            logger.warning("IRIS case %s: adding %s failed: %s", case_id, what, exc)
            return None

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
