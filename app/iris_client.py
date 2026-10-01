import logging

import httpx

from app.config import settings
from app.schemas import IrisCaseResult, NormalizedAlert, RelatedAlert, TriageResult
from app.ticket import classify_ioc, render_case_description, render_case_name, render_case_note

logger = logging.getLogger("siemantics.iris")

NOTE_GROUP_TITLE = "SIEMantics"


class IrisClient:
    def __init__(self) -> None:
        self._base_url = settings.iris_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.iris_api_key}",
            "Content-Type": "application/json",
        }
        # IOC nevekhez tartozó típus azonosítók cache-elése, hogy ne kelljen minden egyes IOC-hoz lekérdezni a típusokat
        self._ioc_type_ids: dict[str, int] | None = None
        self._asset_type_ids: dict[str, int] | None = None
        self._analysis_status_ids: dict[str, int] | None = None

    async def create_case_from_alert(
        self,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None = None,
        *,
        display_id: str,
        escalated_by: str | None = None,
        related_alerts: list[RelatedAlert] | None = None,
    ) -> IrisCaseResult:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        ) as client:
            case_id = await self._create_case(client, alert, triage, display_id)

            group_id = await self._create_note_group(client, case_id)
            note = render_case_note(
                alert,
                triage,
                enrichment,
                display_id=display_id,
                escalated_by=escalated_by,
                related=related_alerts,
                related_window_hours=settings.correlation_window_hours,
                alert_url=_alert_url(display_id),
            )
            await self._add_note(client, case_id, group_id, note)

            for ioc in triage.iocs:
                await self._add_ioc(client, case_id, ioc)

            await self._add_asset(client, case_id, alert)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(
        self, client: httpx.AsyncClient, alert: NormalizedAlert, triage: TriageResult, display_id: str
    ) -> int:
        # Max 256 karakter lehet a case name (render_case_name levágja)
        payload = {
            "case_name": render_case_name(alert, display_id),
            "case_description": render_case_description(alert, triage),
            "case_soc_id": alert.alert_id,
            "case_customer": settings.iris_customer_id,
        }
        resp = await self._post(client, "/manage/cases/add", json=payload)
        return resp.json()["data"]["case_id"]

    async def _create_note_group(self, client: httpx.AsyncClient, case_id: int) -> int:
        # Max 256 karakter lehet a group title
        resp = await self._post(
            client,
            "/case/notes/groups/add",
            params={"cid": case_id},
            json={"group_title": NOTE_GROUP_TITLE},
        )
        return resp.json()["data"]["group_id"]

    async def _add_note(self, client: httpx.AsyncClient, case_id: int, group_id: int, note_content: str) -> None:
        payload = {
            "group_id": group_id,
            "note_title": "SIEMantics Triage Analysis",
            "note_content": note_content,
        }
        await self._post(client, "/case/notes/add", params={"cid": case_id}, json=payload)

    async def _ioc_type_id(self, client: httpx.AsyncClient, ioc_value: str) -> int | None:
        if self._ioc_type_ids is None:
            resp = await self._get(client, "/manage/ioc-types/list")
            self._ioc_type_ids = {row["type_name"]: row["type_id"] for row in resp.json()["data"]}

        return self._ioc_type_ids.get(classify_ioc(ioc_value), self._ioc_type_ids.get("other"))

    async def _add_ioc(self, client: httpx.AsyncClient, case_id: int, ioc_value: str) -> None:
        ioc_type_id = await self._ioc_type_id(client, ioc_value)
        if ioc_type_id is None:
            return

        payload = {
            "ioc_value": ioc_value,
            "ioc_type_id": ioc_type_id,
            "ioc_tlp_id": 2,  # TLP:AMBER
        }
        await self._post(client, "/case/ioc/add", params={"cid": case_id}, json=payload)

    async def _add_asset(self, client: httpx.AsyncClient, case_id: int, alert: NormalizedAlert) -> None:
        """Registers the alerting host as a case asset. Best effort: the case and
        the note already exist, so a failure here (e.g. an IRIS version with
        different asset types) is only logged."""

        # agent 000 is the Wazuh manager itself (firewall/cloud integrations), not the affected host
        if not alert.agent_name or alert.agent_id == "000":
            return
        try:
            if self._asset_type_ids is None:
                resp = await self._get(client, "/manage/asset-type/list")
                self._asset_type_ids = {row["asset_name"]: row["asset_id"] for row in resp.json()["data"]}
            if self._analysis_status_ids is None:
                resp = await self._get(client, "/manage/analysis-status/list")
                self._analysis_status_ids = {row["name"]: row["id"] for row in resp.json()["data"]}

            windows = alert.decoder == "windows_eventchannel" or alert.location == "EventChannel"
            type_name = "Windows - Computer" if windows else "Linux - Server"
            asset_type_id = self._asset_type_ids.get(type_name)
            analysis_status_id = self._analysis_status_ids.get("To be done") or self._analysis_status_ids.get(
                "Unspecified"
            )
            if asset_type_id is None or analysis_status_id is None:
                logger.warning("IRIS asset type %r or analysis status not found, asset not added", type_name)
                return

            payload = {
                "asset_name": alert.agent_name,
                "asset_type_id": asset_type_id,
                "analysis_status_id": analysis_status_id,
                "asset_description": f"Wazuh agent {alert.agent_id or '-'} that raised the alert",
            }
            if alert.agent_ip:
                payload["asset_ip"] = alert.agent_ip
            await self._post(client, "/case/assets/add", params={"cid": case_id}, json=payload)
        except Exception as exc:
            logger.warning("could not add asset %s to IRIS case %s: %s", alert.agent_name, case_id, exc)

    @staticmethod
    async def _post(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
        resp = await client.post(path, **kwargs)
        # 403 Forbidden elkerülése (ha a session cookie-t nem töröljük, akkor a következő hívásnál a cookie miatt 403 Forbidden lesz)
        client.cookies.clear()
        resp.raise_for_status()
        return resp

    @staticmethod
    async def _get(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
        resp = await client.get(path, **kwargs)
        client.cookies.clear()
        resp.raise_for_status()
        return resp


def _alert_url(display_id: str) -> str | None:
    if not settings.siemantics_base_url:
        return None
    return f"{settings.siemantics_base_url.rstrip('/')}/ui/alert.html?id={display_id.lstrip('#')}"


iris_client = IrisClient()
