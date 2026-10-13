# Triazs itelet -> escalated / suppressed / needs_review, prompt injection vedohaloval.

import re

from app.config import settings
from app.enums import AlertStatus
from app.mock_engine import has_suspicious_pattern
from app.schemas import NormalizedAlert, TriageResult

# Prompt injection mintak; talalat eseten az LLM FP itelete NEEDS_REVIEW lesz.
_INJECTION_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules)",
    r"\b(classify|mark|treat|label|report)\s+(this|it|the\s+alert)\s+as\s+(benign|safe|harmless|a\s+false\s+positive|false\s+positive|noise)",
    r"\bis_true_positive\b",
    r"\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|language\s+model|soc\s+analyst)\b",
    r"</?\s*(alert_data|system|instructions?|prompt)\s*>",
    r"(^|\n)\s*(system|assistant)\s*:",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)


def looks_like_prompt_injection(alert: NormalizedAlert) -> bool:
    return any(
        _INJECTION_RE.search(text)
        for text in (alert.searchable_text(), alert.agent_name or "", alert.rule_description)
    )


def decide_status(alert: NormalizedAlert, triage: TriageResult) -> tuple[AlertStatus, str | None]:
    # (status, review_reason): TP mindig eszkalal, FP csak biztos es gyanumentes esetben suppressed.

    if triage.is_true_positive:
        return AlertStatus.ESCALATED, None

    reasons = []
    if triage.confidence < settings.review_confidence_threshold:
        reasons.append(f"low confidence ({triage.confidence:.2f} < {settings.review_confidence_threshold:.2f})")
    if looks_like_prompt_injection(alert):
        reasons.append("possible prompt injection: the alert text addresses the model")
    # A mock motor ezekre maga eszkalal, csak az LLM-nel szamit.
    if triage.engine == "openrouter":
        if has_suspicious_pattern(alert.searchable_text()):
            reasons.append("LLM said benign, but a rule-based suspicious pattern matched the log")
        if alert.severity >= settings.review_severity_floor:
            reasons.append(f"LLM said benign, but Wazuh severity {alert.severity} >= {settings.review_severity_floor}")

    if reasons:
        return AlertStatus.NEEDS_REVIEW, "; ".join(reasons)
    return AlertStatus.SUPPRESSED, None
