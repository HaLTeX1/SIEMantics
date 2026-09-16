import httpx

from app.config import settings
from app.schemas import IrisCaseResult, NormalizedAlert, TriageResult

NOTE_DIRECTORY_NAME = "SIEMantics"


class IrisClient:
    def __init__(self) -> None:
        self._base_url = settings.iris_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.iris_api_key}",
            "Content-Type": "application/json",
        }

    async def create_case_from_alert(
        self, alert: NormalizedAlert, triage: TriageResult
    ) -> IrisCaseResult:
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=15,
            verify=settings.iris_verify_ssl,
        ) as client:
            case_id = await self._create_case(client, alert, triage)

            directory_id = await self._create_note_directory(client, case_id)
            await self._add_note(client, case_id, directory_id, alert, triage)

            for ioc in triage.iocs:
                await self._add_ioc(client, case_id, ioc)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(
        self, client: httpx.AsyncClient, alert: NormalizedAlert, triage: TriageResult
    ) -> int:
        # POST /api/v2/cases - field names verified against iris-web's
        # CaseSchemaForAPIV2 (app/schema/marshables.py): case_customer (not
        # case_customer_id) is the field actually read on the wire.
        payload = {
            "case_name": f"[SIEMantics] {alert.rule_description}"[:256],
            "case_description": triage.reasoning,
            "case_soc_id": alert.alert_id,
            "case_customer": settings.iris_customer_id,
        }
        resp = await client.post("/api/v2/cases", json=payload)
        resp.raise_for_status()
        return resp.json()["case_id"]

    async def _create_note_directory(self, client: httpx.AsyncClient, case_id: int) -> int:
        # Legacy (v1) endpoint - notes have no v2 route yet in iris-web.
        # The case id is a query param (?cid=), not a body field.
        resp = await client.post(
            "/case/notes/directories/add",
            params={"cid": case_id},
            json={"name": NOTE_DIRECTORY_NAME},
        )
        resp.raise_for_status()
        return resp.json()["data"]["id"]

    async def _add_note(
        self,
        client: httpx.AsyncClient,
        case_id: int,
        directory_id: int,
        alert: NormalizedAlert,
        triage: TriageResult,
    ) -> None:
        note_content = (
            f"## LLM Triage\n\n"
            f"- Engine: {triage.engine}\n"
            f"- Confidence: {triage.confidence}\n"
            f"- Recommended severity: {triage.recommended_severity}\n\n"
            f"{triage.reasoning}\n\n"
            f"## Original log snippet\n```\n{alert.log_snippet}\n```"
        )
        payload = {
            "directory_id": directory_id,
            "note_title": "SIEMantics LLM Analysis",
            "note_content": note_content,
        }
        resp = await client.post("/case/notes/add", params={"cid": case_id}, json=payload)
        resp.raise_for_status()

    async def _add_ioc(self, client: httpx.AsyncClient, case_id: int, ioc_value: str) -> None:
        # POST /api/v2/cases/{case_id}/iocs - ioc_type_id deliberately omitted:
        # it's optional, and IOC type seed IDs vary per IRIS instance/version,
        # so guessing one risks a 400 "Invalid IOC type ID" rejection.
        payload = {
            "ioc_value": ioc_value,
            "ioc_tlp_id": 2,  # green, standard TLP seed data
        }
        resp = await client.post(f"/api/v2/cases/{case_id}/iocs", json=payload)
        resp.raise_for_status()


iris_client = IrisClient()
