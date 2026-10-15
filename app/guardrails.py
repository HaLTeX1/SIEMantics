# Triazs itelet -> escalated / suppressed / needs_review, prompt injection vedohaloval.

import re
from dataclasses import dataclass

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


@dataclass
class Evidence:
    # Az LLM sajat confidence-en kivuli jelek: elemzoi itelet ugyanarra a szabalyra, masodik modell.

    history_fp: int = 0
    history_tp: int = 0
    # True: a masodik modell is FP-t mondott, False: TP-t, None: nem volt.
    second_opinion_fp: bool | None = None

    @classmethod
    def from_history(cls, history: list[dict]) -> "Evidence":
        verdicts = [h.get("analyst_verdict") for h in history]
        return cls(history_fp=verdicts.count("false_positive"), history_tp=verdicts.count("true_positive"))

    def analysts_say_benign(self) -> bool:
        return self.history_fp >= settings.history_min_agreement and self.history_tp == 0

    def fp_corroborated(self) -> bool:
        return self.analysts_say_benign() or self.second_opinion_fp is True


def decide_status(
    alert: NormalizedAlert, triage: TriageResult, evidence: Evidence | None = None
) -> tuple[AlertStatus, str | None]:
    # (status, review_reason): az onbevallott confidence keves, ezert elemzoi elozmeny / masodik velemeny is kell.

    if triage.is_true_positive:
        # Az LLM TP-t mond, de az elemzok ugyanezt rendre FP-kent zartak: ne nyisson uj esetet, emberi dontes.
        if (
            evidence is not None
            and triage.engine == "openrouter"
            and evidence.analysts_say_benign()
            and alert.severity < settings.review_severity_floor
            and not looks_like_prompt_injection(alert)
        ):
            return AlertStatus.NEEDS_REVIEW, (
                f"LLM said true positive, but analysts closed {evidence.history_fp} earlier alert(s) of this rule "
                "as false positive"
            )
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
        if evidence is not None and settings.require_fp_corroboration and not evidence.fp_corroborated():
            if evidence.second_opinion_fp is False:
                reasons.append("a second model disagreed (said true positive)")
            else:
                reasons.append("not corroborated: no analyst history of this rule as false positive yet")

    if reasons:
        return AlertStatus.NEEDS_REVIEW, "; ".join(reasons)
    return AlertStatus.SUPPRESSED, None
