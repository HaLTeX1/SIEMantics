import json
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.enums import AlertStatus, GroundTruth, UserRole


# --- Raw Wazuh alert payloads as received from the webhook integration.

class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    level: int = 0
    description: str = "No description provided"
    groups: list[str] = Field(default_factory=list)


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None


class WazuhAlertPayload(BaseModel):
    """Raw shape of a Wazuh alert as forwarded by the webhook integration."""

    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    timestamp: Optional[str] = None
    rule: WazuhRule
    agent: Optional[WazuhAgent] = None
    data: dict = Field(default_factory=dict)
    full_log: Optional[str] = None
    location: Optional[str] = None


# --- Normalized internal representation ---

class NormalizedAlert(BaseModel):
    alert_id: str
    source_ip: Optional[str] = None
    agent_name: Optional[str] = None
    rule_description: str
    severity: int
    log_snippet: str
    received_at: datetime = Field(default_factory=datetime.utcnow)

    # Context for the analyst/LLM, taken from the full Wazuh alert
    timestamp: Optional[str] = None
    rule_id: Optional[str] = None
    rule_groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    agent_id: Optional[str] = None
    agent_ip: Optional[str] = None
    location: Optional[str] = None
    decoder: Optional[str] = None
    # Flattened, size-capped event fields ("data.win.eventdata.commandLine" -> value)
    event_fields: dict[str, str] = Field(default_factory=dict)

    def searchable_text(self) -> str:
        """Log plus event field values (not keys) - what the pattern/injection checks scan."""
        return "\n".join([self.log_snippet, *self.event_fields.values()])


class RelatedAlert(BaseModel):
    """Another alert from the same host or source IP, for correlation."""

    display_id: str
    received_at: datetime
    rule_id: Optional[str] = None
    rule_description: str
    severity: int
    status: AlertStatus
    agent_name: Optional[str] = None
    source_ip: Optional[str] = None
    iris_case_id: Optional[int] = None
    log_excerpt: str = ""


# --- LLM triage output ---

_LIST_MAX_ITEMS = 12
_ITEM_MAX_LEN = 600
_TEXT_MAX_LEN = 4000


def _clip(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


class TriageResult(BaseModel):
    is_true_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    iocs: list[str] = Field(default_factory=list)
    recommended_severity: Optional[str] = None
    # "manual": built from a stored record when an analyst escalates by hand
    engine: Literal["openrouter", "mock", "manual"]
    # Concrete model that answered (None for the mock engine)
    model: Optional[str] = None

    # Structured ticket content (LLM only; empty for the mock engine)
    summary: Optional[str] = None
    potential_impact: Optional[str] = None
    benign_explanations: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    immediate_actions: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    escalation_criteria: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)

    @field_validator(
        "iocs", "benign_explanations", "mitre_techniques", "immediate_actions",
        "investigation_steps", "escalation_criteria", "missing_information",
        mode="before",
    )
    @classmethod
    def _coerce_list(cls, value):
        # Free models do not always follow the schema: accept a bare string or null
        if value is None:
            return []
        if isinstance(value, str):
            value = [line for line in value.splitlines() if line.strip()]
        if not isinstance(value, list):
            value = [value]
        items = [_clip(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False), _ITEM_MAX_LEN) for v in value]
        return [item for item in items if item][:_LIST_MAX_ITEMS]

    @field_validator("summary", "potential_impact", mode="before")
    @classmethod
    def _coerce_text(cls, value):
        if value is None:
            return None
        if isinstance(value, list):
            value = " ".join(str(v) for v in value)
        return _clip(str(value), _ITEM_MAX_LEN * 2) or None

    @field_validator("reasoning", mode="before")
    @classmethod
    def _clip_reasoning(cls, value):
        return _clip(value, _TEXT_MAX_LEN) if isinstance(value, str) else value

    def analysis(self) -> dict:
        """The non-empty structured ticket fields, as stored in AlertRecord.llm_analysis."""
        return {k: v for k, v in self.model_dump(include=set(ANALYSIS_FIELDS)).items() if v}


ANALYSIS_FIELDS = (
    "summary", "potential_impact", "benign_explanations", "mitre_techniques",
    "immediate_actions", "investigation_steps", "escalation_criteria", "missing_information",
)


# --- IRIS response ---

class IrisCaseResult(BaseModel):
    case_id: int
    case_url: str


# --- Decision log / evaluation dataset ---

class AssigneeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: Optional[str] = None


class AlertRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    # "#ID-<id>": unique, human-facing ID; the API also accepts it (as "ID-<id>") wherever it takes an alert reference
    display_id: str
    alert_id: str
    received_at: datetime
    source_ip: Optional[str] = None
    agent_name: Optional[str] = None
    rule_description: str
    severity: int
    status: AlertStatus
    llm_is_true_positive: Optional[bool] = None
    llm_confidence: Optional[float] = None
    llm_reasoning: Optional[str] = None
    llm_iocs: Optional[list[str]] = None
    llm_analysis: Optional[dict] = None
    triage_engine: Optional[str] = None
    iris_case_id: Optional[int] = None
    error_detail: Optional[str] = None
    processing_time_ms: float
    ground_truth: Optional[GroundTruth] = None
    labeled_at: Optional[datetime] = None
    ioc_enrichment: Optional[list[dict]] = None
    triage_model: Optional[str] = None
    review_reason: Optional[str] = None
    # Automatic decision; differs from `status` when an analyst escalated by hand
    auto_status: Optional[AlertStatus] = None
    escalated_by: Optional[AssigneeOut] = None
    escalated_at: Optional[datetime] = None
    # Owner of the IRIS case (only possible when iris_case_id is set)
    assignee: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None


class LabelRequest(BaseModel):
    ground_truth: GroundTruth


# --- Aggregate evaluation metrics (thesis ch. 6.3) ---

class TriageMetrics(BaseModel):
    sample_size: int
    labeled_size: int
    error_count: int
    needs_review_count: int
    # Labeled TP among NEEDS_REVIEW records: false negatives caught by the review queue
    needs_review_true_positive: int
    manually_escalated_count: int

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None

    avg_processing_time_ms: Optional[float] = None
    median_processing_time_ms: Optional[float] = None
    p95_processing_time_ms: Optional[float] = None


# --- Users / auth ---

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    full_name: Optional[str] = Field(default=None, max_length=128)
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    """Admin-side partial update; omitted fields are left unchanged."""

    full_name: Optional[str] = Field(default=None, max_length=128)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


# --- Case assignment ---

class CaseAssignRequest(BaseModel):
    """`user_id: null` removes the current assignee."""

    user_id: Optional[int] = None


class CaseAssignmentOut(BaseModel):
    iris_case_id: int
    assignee: Optional[AssigneeOut] = None
    assigned_by: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None
