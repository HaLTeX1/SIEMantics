from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, ConfigDict

from app.enums import AlertStatus, GroundTruth, UserRole


# --- Wazuh webhook payloads ---

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


# --- Normalizalt alert a triage loghoz, a LLM-hez es az evaluation datasethez. A Wazuh alert payloadja alapjan keszul, de a triage logban mar csak a fontos mezok szerepelnek.

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


# --- LLM triage output ---

class TriageResult(BaseModel):
    is_true_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    iocs: list[str] = Field(default_factory=list)
    recommended_severity: Optional[str] = None
    # manuualis escalalt riasztasoknal a ground_truth mezot az analyst allitja be, a system nem.
    engine: Literal["openrouter", "mock", "manual"]
    # Konkret LLM modell, ami a triage logot adta (pl. openrouter/free vagy openrouter/claude-v1). Ha a triage engine "manual", akkor ez None.
    model: Optional[str] = None


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
    # Egyedi riasztás-azonosító "ID-<szám>" formátumban (a Wazuh alert_id nem egyedi)
    display_id: str
    alert_id: str
    received_at: datetime
    source_ip: Optional[str] = None
    rule_description: str
    severity: int
    status: AlertStatus
    llm_is_true_positive: Optional[bool] = None
    llm_confidence: Optional[float] = None
    llm_reasoning: Optional[str] = None
    llm_iocs: Optional[list[str]] = None
    triage_engine: Optional[str] = None
    iris_case_id: Optional[int] = None
    error_detail: Optional[str] = None
    processing_time_ms: float
    ground_truth: Optional[GroundTruth] = None
    labeled_at: Optional[datetime] = None
    ioc_enrichment: Optional[list[dict]] = None
    triage_model: Optional[str] = None
    review_reason: Optional[str] = None
    # Automatikus döntés a riasztás státuszáról (ESCALATED, SUPPRESSED, NEEDS_REVIEW) - az analyst döntése nem számít bele a statisztikába.
    auto_status: Optional[AlertStatus] = None
    escalated_by: Optional[AssigneeOut] = None
    escalated_at: Optional[datetime] = None
    # Az IRIS a riasztas tulajdonosa
    assignee: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None


class LabelRequest(BaseModel):
    ground_truth: GroundTruth



# --- Triage metrics ---

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
    """Admin-oldali felhasználó update. A felhasználó saját profilját a /me endpointon keresztül tudja update-elni."""

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
