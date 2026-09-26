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
        # ioc_type_id seed values vary per IRIS instance/version, so they're looked
        # up dynamically via /manage/ioc-types/list instead of being hardcoded.
        self._ioc_type_ids: dict[str, int] | None = None

    async def create_case_from_alert(
        self,
        alert: NormalizedAlert,
        triage: TriageResult,
        enrichment: list[dict] | None = None,
    ) -> IrisCaseResult:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        ) as client:
            case_id = await self._create_case(client, alert, triage)

            group_id = await self._create_note_group(client, case_id)
            await self._add_note(client, case_id, group_id, alert, triage, enrichment)

            for ioc in triage.iocs:
                await self._add_ioc(client, case_id, ioc)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(
        self, client: httpx.AsyncClient, alert: NormalizedAlert, triage: TriageResult
    ) -> int:
        # POST /manage/cases/add - the legacy case API. /api/v2/cases doesn't exist
        # on every iris-web version (confirmed 404 on 2.3.7), so this targets the
        # route that's been stable since early iris-web releases. Field names
        # verified against CaseSchema in iris-web's app/schema/marshables.py:
        # case_customer (not case_customer_id) is the field actually read on the
        # wire, and case_soc_id maps to a String(256) column - any alert_id works.
        payload = {
            "case_name": f"[SIEMantics] {alert.rule_description}"[:256],
            "case_description": triage.reasoning,
            "case_soc_id": alert.alert_id,
            "case_customer": settings.iris_customer_id,
        }
        resp = await self._post(client, "/manage/cases/add", json=payload)
        return resp.json()["data"]["case_id"]

    async def _create_note_group(self, client: httpx.AsyncClient, case_id: int) -> int:
        # Notes are organized into "groups" (not "directories") pre-v3 iris-web.
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
        enrichment: list[dict] | None = None,
    ) -> None:
        note_content = (
            f"## LLM Triage\n\n"
            f"- Engine: {triage.engine}\n"
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
            "ioc_tlp_id": 2,  # green, standard TLP seed data
        }
        await self._post(client, "/case/ioc/add", params={"cid": case_id}, json=payload)

    @staticmethod
    async def _post(client: httpx.AsyncClient, path: str, **kwargs) -> httpx.Response:
        resp = await client.post(path, **kwargs)
        # This is a stateless, bearer-token-authenticated API client: any session
        # cookie IRIS sets on a response must not be replayed on the next request,
        # since ac_api_case_requires() demands a CSRF token whenever a "session"
        # cookie is present on a POST - which we never send, causing a spurious
        # "Invalid CSRF token" 400 on every request after the first.
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
