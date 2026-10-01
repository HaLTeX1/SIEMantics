import re

import httpx

from app.config import settings
from app.schemas import IrisCaseResult, NormalizedAlert, TriageResult

NOTE_GROUP_TITLE = "SIEMantics"

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _format_enrichment(enrichment: list[dict]) -> str:
    lines = []
    for entry in enrichment:
        ioc = entry["ioc"]
        vt = entry.get("virustotal")
        abuse = entry.get("abuseipdb")

        parts = []
        if vt:
            parts.append(
                f"VT: {vt['malicious']} malicious / {vt['suspicious']} suspicious "
                f"(reputation {vt.get('reputation')}, {vt.get('country') or '?'})"
            )
        if abuse:
            parts.append(
                f"AbuseIPDB: {abuse['abuse_confidence_score']}% confidence, "
                f"{abuse.get('total_reports', 0)} reports ({abuse.get('country_code') or '?'}, "
                f"{abuse.get('isp') or 'unknown ISP'})"
            )
        if not parts:
            parts.append("no enrichment data available")

        lines.append(f"- **{ioc}** - " + "; ".join(parts))
    return "\n".join(lines)


class IrisClient:
    def __init__(self) -> None:
        self._base_url = settings.iris_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.iris_api_key}",
            "Content-Type": "application/json",
        }
        # IOC nevekhez tartozó típus azonosítók cache-elése, hogy ne kelljen minden egyes IOC-hoz lekérdezni a típusokat
        self._ioc_type_ids: dict[str, int] | None = None

    async def create_case_from_alert(
        self,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None = None,
        *,
        display_id: str,
        escalated_by: str | None = None,
    ) -> IrisCaseResult:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        ) as client:
            case_id = await self._create_case(client, alert, triage, display_id)

            group_id = await self._create_note_group(client, case_id)
            await self._add_note(client, case_id, group_id, alert, triage, enrichment, display_id, escalated_by)

            for ioc in triage.iocs:
                await self._add_ioc(client, case_id, ioc)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(
        self, client: httpx.AsyncClient, alert: NormalizedAlert, triage: TriageResult, display_id: str
    ) -> int:
        # Max 256 karakter lehet a case name
        payload = {
            "case_name": f"[SIEMantics {display_id}] {alert.rule_description}"[:256],
            "case_description": triage.reasoning,
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

    async def _add_note(
        self,
        client: httpx.AsyncClient,
        case_id: int,
        group_id: int,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None,
        display_id: str,
        escalated_by: str | None,
    ) -> None:
        header = f"SIEMantics alert: **{display_id}** (Wazuh alert ID: {alert.alert_id})\n\n"
        if escalated_by:
            header += f"**Manually escalated by {escalated_by}** - the automatic triage did not escalate this alert.\n\n"
        note_content = (
            header
            + f"## LLM Triage\n\n"
            f"- Engine: {triage.engine}\n"
            f"- Model: {triage.model or '-'}\n"
            f"- Confidence: {triage.confidence}\n"
            f"- Recommended severity: {triage.recommended_severity}\n\n"
            f"{triage.reasoning}\n\n"
            f"## Original log snippet\n```\n{alert.log_snippet}\n```"
        )
        if enrichment:
            note_content += "\n\n## Threat Intelligence\n\n" + _format_enrichment(enrichment)
        payload = {
            "group_id": group_id,
            "note_title": "SIEMantics LLM Analysis",
            "note_content": note_content,
        }
        await self._post(client, "/case/notes/add", params={"cid": case_id}, json=payload)

    async def _ioc_type_id(self, client: httpx.AsyncClient, ioc_value: str) -> int | None:
        if self._ioc_type_ids is None:
            resp = await self._get(client, "/manage/ioc-types/list")
            self._ioc_type_ids = {row["type_name"]: row["type_id"] for row in resp.json()["data"]}

        type_name = "ip-any" if _IP_RE.match(ioc_value) else "other"
        return self._ioc_type_ids.get(type_name, self._ioc_type_ids.get("other"))

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


iris_client = IrisClient()
