import json
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.enums import AlertStatus, GroundTruth, UserRole


# --- Wazuh webhook payload ---

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
    # A webhook integracio altal tovabbitott Wazuh riasztas.

    model_config = ConfigDict(extra="allow")

    id: Optional[str] = None
    timestamp: Optional[str] = None
    rule: WazuhRule
    agent: Optional[WazuhAgent] = None
    data: dict = Field(default_factory=dict)
    full_log: Optional[str] = None
    location: Optional[str] = None


# --- Normalizalt riasztas (triazs, LLM, kiertekeles) ---

class NormalizedAlert(BaseModel):
    alert_id: str
    source_ip: Optional[str] = None
    agent_name: Optional[str] = None
    rule_description: str
    severity: int
    log_snippet: str
    received_at: datetime = Field(default_factory=datetime.utcnow)
    llm_is_true_positive: Optional[bool] = None
    llm_confidence: Optional[float] = None
    llm_reasoning: Optional[str] = None
    llm_iocs: Optional[list[str]] = None

    # Kontextus az analystnak / LLM-nek a teljes Wazuh riasztasbol.
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
    # Kilapitott, meretkorlatos esemenymezok (data.win.eventdata.commandLine -> ertek).
    event_fields: dict[str, str] = Field(default_factory=dict)

    def searchable_text(self) -> str:
        # Log es esemenymezo ertekek, ezeket nezik a minta- es injection ellenorzesek.
        return "\n".join([self.log_snippet, *self.event_fields.values()])


class RelatedAlert(BaseModel):
    # Kapcsolodo riasztas ugyanarrol a hostrol vagy IP-rol.

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


# --- LLM triazs eredmeny ---

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
    # manual: tarolt rekordbol epul, kezi eszkalacional.
    engine: Literal["openrouter", "mock", "manual"]
    # A valaszolo konkret modell (mock motornal None).
    model: Optional[str] = None

    # Strukturalt ticket tartalom (csak LLM, mock motornal ures).
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
        # A free modellek nem mindig kovetik a semat: string vagy null is jo.
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
        # A nem ures strukturalt mezok, ahogy az llm_analysis-ben tarolodnak.
        return {k: v for k, v in self.model_dump(include=set(ANALYSIS_FIELDS)).items() if v}


ANALYSIS_FIELDS = (
    "summary", "potential_impact", "benign_explanations", "mitre_techniques",
    "immediate_actions", "investigation_steps", "escalation_criteria", "missing_information",
)


# --- IRIS valasz ---

class IrisCaseResult(BaseModel):
    case_id: int
    case_url: str


# --- Dontesnaplo / kiertekelesi adathalmaz ---

class AssigneeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: Optional[str] = None


class AlertRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    # Egyedi riasztas azonosito ID-<szam> formaban (a Wazuh alert_id nem egyedi).
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
    # Automatikus dontes; kezi eszkalacional elterhet a status-tol.
    auto_status: Optional[AlertStatus] = None
    escalated_by: Optional[AssigneeOut] = None
    escalated_at: Optional[datetime] = None
    # Annak a riasztasnak az ID-ja, akinek az IRIS esetebe ez is bekerult.
    correlated_with: Optional[str] = None
    # Az IRIS eset felelose.
    assignee: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None


class LabelRequest(BaseModel):
    ground_truth: GroundTruth


class MergeRequest(BaseModel):
    # Riasztas hivatkozasok (ID-42 / Wazuh alert_id); a meglevo eseteik minden riasztasa is atkerul.
    alert_refs: list[str] = Field(min_length=2, max_length=500)


class MergeResult(BaseModel):
    iris_case_id: int
    case_url: Optional[str] = None
    target: str
    merged: list[str]
    closed_cases: list[int] = Field(default_factory=list)
    # Regi esetek, amiket az IRIS nem engedett lezarni (best effort)
    close_failed: list[int] = Field(default_factory=list)


class FalsePositiveRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=2000)


class FalsePositiveResult(BaseModel):
    iris_case_id: int
    labeled: list[str]
    # False, ha az eset mar le volt zarva az IRIS-ben (csak a cimkezes tortent meg)
    iris_closed: bool



# --- Triazs metrikak ---

class TriageMetrics(BaseModel):
    sample_size: int
    labeled_size: int
    error_count: int
    needs_review_count: int
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


# --- Felhasznalok / auth ---

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
    # Admin oldali reszleges modositas; a kihagyott mezok valtozatlanok.

    full_name: Optional[str] = Field(default=None, max_length=128)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


# --- Eset felelos ---

class CaseAssignRequest(BaseModel):
    # user_id: null torli a felelost.

    user_id: Optional[int] = None


class CaseAssignmentOut(BaseModel):
    iris_case_id: int
    assignee: Optional[AssigneeOut] = None
    assigned_by: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None
