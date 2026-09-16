import json
import logging

from openai import AsyncOpenAI

from app.config import settings
from app.mock_engine import mock_triage
from app.schemas import NormalizedAlert, TriageResult

logger = logging.getLogger("siemantics.llm_engine")

_client = AsyncOpenAI(api_key=settings.openai_api_key) if settings.openai_api_key else None

_SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst. Assess the alert below and decide if it is a "
    "true positive requiring incident response, or a false positive/noise. "
    "Extract any concrete IoCs (IPs, hashes, domains, filenames) mentioned in the log. "
    "Be conservative: only flag true positive when the evidence supports it."
)

_RESPONSE_SCHEMA = {
    "name": "triage_result",
    "schema": {
        "type": "object",
        "properties": {
            "is_true_positive": {"type": "boolean"},
            "confidence": {"type": "number"},
            "reasoning": {"type": "string"},
            "iocs": {"type": "array", "items": {"type": "string"}},
            "recommended_severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
        },
        "required": ["is_true_positive", "confidence", "reasoning", "iocs"],
        "additionalProperties": False,
    },
}


async def _openai_triage(alert: NormalizedAlert) -> TriageResult:
    user_prompt = (
        f"Rule: {alert.rule_description}\n"
        f"Severity (Wazuh level): {alert.severity}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Agent: {alert.agent_name}\n"
        f"Log snippet:\n{alert.log_snippet}"
    )

    response = await _client.chat.completions.create(
        model=settings.openai_model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_schema", "json_schema": _RESPONSE_SCHEMA},
        temperature=0,
    )

    raw = response.choices[0].message.content
    data = json.loads(raw)
    return TriageResult(**data, engine="openai")


async def triage_alert(alert: NormalizedAlert) -> TriageResult:
    """Triage via OpenAI, falling back to the deterministic mock engine if
    no API key is configured or the call fails (network, quota, timeout, ...)."""

    if _client is None:
        logger.warning("OPENAI_API_KEY not set, using mock triage engine for alert %s", alert.alert_id)
        return mock_triage(alert)

    try:
        return await _openai_triage(alert)
    except Exception as exc:
        logger.warning("OpenAI triage failed for alert %s (%s), falling back to mock engine", alert.alert_id, exc)
        return mock_triage(alert)
