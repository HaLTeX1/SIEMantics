import json
import logging

from openai import AsyncOpenAI

from app.config import settings
from app.mock_engine import mock_triage
from app.schemas import NormalizedAlert, TriageResult

logger = logging.getLogger("siemantics.llm_engine")

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


_model_is_free = settings.openrouter_model == "openrouter/free" or settings.openrouter_model.endswith(":free")
if settings.openrouter_api_key and not _model_is_free:
    logger.error(
        "OPENROUTER_MODEL=%s is not a free model (must be 'openrouter/free' or end with ':free'); "
        "refusing to call OpenRouter and using the mock triage engine instead",
        settings.openrouter_model,
    )

_client = (
    AsyncOpenAI(
        api_key=settings.openrouter_api_key,
        base_url=OPENROUTER_BASE_URL,
        default_headers={
            "HTTP-Referer": "https://github.com/siemantics",
            "X-Title": "SIEMantics",
        },
    )
    if settings.openrouter_api_key and _model_is_free
    else None
)

# A prompt ami alapján a tényleges triázs történni fog. Angol, mivel a promptokat angolul jobban kezelik az LLM-ek.
_SYSTEM_PROMPT = (
    "You are a SOC tier-2 analyst triaging a single Wazuh alert. Decide if it is a true "
    "positive requiring incident response, or a false positive/noise, and extract any "
    "concrete IoCs (IPs, hashes, domains, filenames) mentioned in the log.\n\n"
    "Weigh technique risk, not just destination/impact evidence: encoded or obfuscated "
    "commands (e.g. `powershell -enc`/-EncodedCommand, base64-wrapped scripts), "
    "living-off-the-land binaries used for execution or download (certutil, mshta, "
    "rundll32, regsvr32, wscript/cscript), credential dumping, and disabling of security "
    "tooling are high-risk techniques on their own - flag these as true positive (at least "
    "medium/high severity) even with no other IoCs and even on an internal host, unless the "
    "log gives a concrete, specific reason to believe it's authorized activity. Don't let the "
    "absence of a malicious IP/hash alone justify calling it noise.\n\n"
    "Reserve false positive/low severity for genuinely benign, low-signal events (routine "
    "scans, expected admin tools with no suspicious flags or obfuscation).\n\n"
    "Respond with a single JSON object only, no prose, no markdown fences, matching this shape: "
    '{"is_true_positive": boolean, "confidence": number (0-1), "reasoning": string, '
    '"iocs": string[], "recommended_severity": "low"|"medium"|"high"|"critical"}'
)


def _parse_json_response(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    return json.loads(raw)


async def _openrouter_triage(alert: NormalizedAlert) -> TriageResult:
    user_prompt = (
        f"Rule: {alert.rule_description}\n"
        f"Severity (Wazuh level): {alert.severity}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Agent: {alert.agent_name}\n"
        f"Log snippet:\n{alert.log_snippet}"
    )

    response = await _client.chat.completions.create(
        model=settings.openrouter_model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0,
    )

    raw = response.choices[0].message.content
    data = _parse_json_response(raw)
    return TriageResult(**data, engine="openrouter")


async def triage_alert(alert: NormalizedAlert) -> TriageResult:
    """Triage via OpenRouter (free-tier only), falling back to the deterministic
    mock engine if no API key is configured, the model isn't a free model, or the
    call fails (network, rate limit, timeout, ...)."""

    if _client is None:
        logger.warning("OpenRouter not configured/available, using mock triage engine for alert %s", alert.alert_id)
        return mock_triage(alert)

    try:
        return await _openrouter_triage(alert)
    except Exception as exc:
        logger.warning("OpenRouter triage failed for alert %s (%s), falling back to mock engine", alert.alert_id, exc)
        return mock_triage(alert)
