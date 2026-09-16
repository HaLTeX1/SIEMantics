import json

from openai import AsyncOpenAI

from app.config import settings
from app.schemas import NormalizedAlert, TriageResult

_client = AsyncOpenAI(api_key=settings.openai_api_key)

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


async def triage_alert(alert: NormalizedAlert) -> TriageResult:
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
    return TriageResult.model_validate(json.loads(raw))
