import httpx

from app.config import settings
from app.schemas import IrisCaseResult, NormalizedAlert, TriageResult

_IOC_TYPE_MAP = {
    "ip": 76,  # ip-any
    "hash": 90,  # md5/sha - IRIS resolves generically via type id in real deployments
    "domain": 20,
    "default": 22,  # other
}


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
        async with httpx.AsyncClient(base_url=self._base_url, headers=self._headers, timeout=15) as client:
            case = await self._create_case(client, alert, triage)
            case_id = case["data"]["case_id"]

            await self._add_note(client, case_id, alert, triage)
            for ioc in triage.iocs:
                await self._add_ioc(client, case_id, ioc)

            return IrisCaseResult(
                case_id=case_id,
                case_url=f"{self._base_url}/case?cid={case_id}",
            )

    async def _create_case(
        self, client: httpx.AsyncClient, alert: NormalizedAlert, triage: TriageResult
    ) -> dict:
        payload = {
            "case_name": f"[SIEMantics] {alert.rule_description}",
            "case_description": triage.reasoning,
            "case_customer": settings.iris_customer_id,
            "case_classification": 1,
            "soc_id": alert.alert_id,
        }
        resp = await client.post("/manage/cases/add", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def _add_note(
        self, client: httpx.AsyncClient, case_id: int, alert: NormalizedAlert, triage: TriageResult
    ) -> None:
        note_content = (
            f"## LLM Triage\n\n"
            f"- Confidence: {triage.confidence}\n"
            f"- Recommended severity: {triage.recommended_severity}\n\n"
            f"{triage.reasoning}\n\n"
            f"## Original log snippet\n```\n{alert.log_snippet}\n```"
        )
        payload = {
            "note_title": "SIEMantics LLM Analysis",
            "note_content": note_content,
            "cid": case_id,
        }
        resp = await client.post("/case/notes/add", json=payload)
        resp.raise_for_status()

    async def _add_ioc(self, client: httpx.AsyncClient, case_id: int, ioc_value: str) -> None:
        payload = {
            "ioc_value": ioc_value,
            "ioc_type_id": _IOC_TYPE_MAP["default"],
            "ioc_tlp_id": 2,
            "cid": case_id,
        }
        resp = await client.post("/case/ioc/add", json=payload)
        resp.raise_for_status()


iris_client = IrisClient()
