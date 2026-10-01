import re

from app.config import settings
from app.schemas import NormalizedAlert, TriageResult

_IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_SUSPICIOUS_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"<script",
    r"\.\./\.\./",
    r"base64_decode",
    r"powershell\s+-enc",
    r"/etc/passwd",
    r"wget\s+http",
    r"curl\s+http.*\|\s*sh",
]
_SUSPICIOUS_RE = re.compile("|".join(_SUSPICIOUS_PATTERNS), re.IGNORECASE)


def _severity_bucket(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def has_suspicious_pattern(text: str) -> bool:
    return bool(_SUSPICIOUS_RE.search(text))


def mock_triage(alert: NormalizedAlert) -> TriageResult:
    """Deterministic rule-based fallback - no API key or network call needed."""

    text = alert.searchable_text()
    pattern_hit = has_suspicious_pattern(text)
    is_true_positive = alert.severity >= settings.llm_mock_severity_threshold or pattern_hit

    confidence = (
        min(0.5 + alert.severity / 20, 0.95)
        if is_true_positive
        else max(0.9 - alert.severity / 20, 0.5)
    )

    iocs = set(_IOC_IP_RE.findall(text))
    if alert.source_ip:
        iocs.add(alert.source_ip)

    reasoning = (
        f"[mock-engine] severity={alert.severity} (threshold={settings.llm_mock_severity_threshold}), "
        f"suspicious pattern match={pattern_hit}. Rule-based fallback, no LLM call made."
    )

    return TriageResult(
        is_true_positive=is_true_positive,
        confidence=round(confidence, 2),
        reasoning=reasoning,
        iocs=sorted(iocs),
        recommended_severity=_severity_bucket(alert.severity),
        engine="mock",
    )
