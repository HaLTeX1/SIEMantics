import ipaddress
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
    # Elemzoi itelet (ground truth) es lezarasi annotacio; az automatikus dontes nem bizonyitek.
    analyst_verdict: Optional[str] = None
    case_closure_note: Optional[str] = None
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
    engine: Literal["openrouter", "mock", "manual", "dedup", "flood", "suppression"]
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
    # SIEMantics csoport fo riasztasa es a csoport merete
    group: Optional[str] = None
    group_size: Optional[int] = None
    # Az IRIS eset felelose.
    assignee: Optional[AssigneeOut] = None
    assigned_at: Optional[datetime] = None
    rule_id: Optional[str] = None
    # Az elnyomo suppression szabaly ID-ja.
    suppression_rule_id: Optional[int] = None
    # Az IRIS eset lezarasa (IRIS-ben vagy SIEMantics-bol).
    case_closed_at: Optional[datetime] = None
    # Az IRIS eset lezarasi annotacioja.
    case_closure_note: Optional[str] = None
    # Lezart riasztas (lezart eset, vagy eset nelkul elemzoi itelettel); a dashboard alapbol elrejti.
    is_closed: bool = False


class LabelRequest(BaseModel):
    ground_truth: GroundTruth


class MergeRequest(BaseModel):
    # Riasztas hivatkozasok (ID-42 / Wazuh alert_id); a meglevo eseteik minden riasztasa is atkerul.
    alert_refs: list[str] = Field(min_length=2, max_length=500)


class MergeResult(BaseModel):
    # None, ha egyik tagnak sincs nyitott IRIS esete: ekkor csak SIEMantics csoport lesz.
    iris_case_id: Optional[int] = None
    case_url: Optional[str] = None
    target: str
    group: str
    merged: list[str]
    closed_cases: list[int] = Field(default_factory=list)
    # Regi esetek, amiket az IRIS nem engedett lezarni (best effort)
    close_failed: list[int] = Field(default_factory=list)


class FalsePositiveRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=2000)


class GroupFalsePositiveResult(BaseModel):
    group: Optional[str] = None
    labeled: list[str]
    closed_cases: list[int] = Field(default_factory=list)


class BulkRequest(BaseModel):
    # Tomeges muvelet a kijelolt riasztasokra (flood kezeles).
    alert_refs: list[str] = Field(min_length=1, max_length=5000)
    reason: Optional[str] = Field(default=None, max_length=2000)


class BulkFalsePositiveResult(BaseModel):
    labeled: list[str]
    closed_cases: list[int] = Field(default_factory=list)


class BulkDeleteResult(BaseModel):
    deleted: list[str]


class BlockIpRequest(BaseModel):
    ip: str = Field(min_length=2, max_length=64)
    # agent: a riasztas agentje, all: minden aktiv agent.
    scope: Literal["agent", "all"] = "agent"
    duration_hours: Literal[1, 24, 168] = 24


class ResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action: str
    ip: str
    scope: str
    duration_seconds: int
    targets: Optional[list[dict]] = None
    status: str
    error_detail: Optional[str] = None
    requested_by: Optional[AssigneeOut] = None
    created_at: datetime
    expires_at: datetime
    iris_case_id: Optional[int] = None
    iris_noted: bool
    automatic: bool = False

    @field_validator("automatic", mode="before")
    @classmethod
    def _none_is_manual(cls, value):
        return bool(value)


class HostProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_name: str
    agent_id: Optional[str] = None
    role: Optional[str] = None
    criticality: Optional[str] = None
    notes: Optional[str] = None
    ips: Optional[list[str]] = None
    wazuh: Optional[dict] = None
    in_wazuh: bool
    synced_at: Optional[datetime] = None
    updated_by: Optional[AssigneeOut] = None
    updated_at: Optional[datetime] = None


class HostUpdate(BaseModel):
    # Kezi kontextus; ures szoveg torli a mezot, ures lista az IP-ket.
    role: Optional[str] = Field(default=None, max_length=256)
    criticality: Optional[Literal["low", "medium", "high", "critical", ""]] = None
    notes: Optional[str] = Field(default=None, max_length=4000)
    ips: Optional[list[str]] = Field(default=None, max_length=32)

    @field_validator("ips")
    @classmethod
    def _valid_ips(cls, value):
        if value is None:
            return None
        out = []
        for item in value:
            item = item.strip()
            if not item:
                continue
            try:
                out.append(str(ipaddress.ip_address(item)))
            except ValueError as exc:
                raise ValueError(f"invalid IP address: {item}") from exc
        return list(dict.fromkeys(out))


class HostCreate(HostUpdate):
    # Wazuh agent nelkuli host (pl. agentless eszkoz, tuzfal), a riasztas agent neve szerint.
    agent_name: str = Field(min_length=1, max_length=128)


class KnownNetworkIn(BaseModel):
    cidr: str = Field(min_length=2, max_length=64)
    label: str = Field(min_length=1, max_length=256)
    trusted: bool = True


class KnownNetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cidr: str
    label: str
    trusted: bool
    created_at: datetime


class CaseInfoOut(BaseModel):
    # Az IRIS eset aktualis allapota a reszletpanelhez.
    iris_case_id: int
    case_url: str
    closed: bool
    close_date: Optional[str] = None
    outcome: Optional[str] = None
    closure_annotation: Optional[str] = None


class CaseSyncResult(BaseModel):
    checked: int
    closed_cases: list[int]
    labeled: list[str]


class SuppressRequest(BaseModel):
    # exact: azonos ujjlenyomat, rule_host: szabaly + host, rule: szabaly barmelyik hoston.
    alert_refs: list[str] = Field(min_length=1, max_length=5000)
    scope: Literal["exact", "rule_host", "rule"] = "exact"
    reason: Optional[str] = Field(default=None, max_length=2000)
    # None = lejarat nelkul.
    duration_hours: Optional[int] = Field(default=None, ge=1, le=24 * 365)
    # A meglevo, IRIS eset nelkuli egyezo riasztasok is elnyomva.
    apply_existing: bool = True


class SuppressionRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scope: str
    fingerprint: Optional[str] = None
    rule_id: Optional[str] = None
    agent_name: Optional[str] = None
    description: str
    reason: Optional[str] = None
    created_by: Optional[AssigneeOut] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool
    hit_count: int
    last_hit_at: Optional[datetime] = None


class SuppressResult(BaseModel):
    rules: list[SuppressionRuleOut]
    suppressed: list[str]


class FalsePositiveResult(BaseModel):
    iris_case_id: int
    labeled: list[str]
    # False, ha az eset mar le volt zarva az IRIS-ben (csak a cimkezes tortent meg)
    iris_closed: bool



# --- Triazs metrikak ---

class EngineMetrics(BaseModel):
    sample_size: int
    labeled_size: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    accuracy: Optional[float] = None
    false_positive_rate: Optional[float] = None
    recall: Optional[float] = None


class CalibrationBucket(BaseModel):
    range: str
    n: int
    correct: int
    accuracy: Optional[float] = None


class Calibration(BaseModel):
    # Mennyire jelzi az LLM onbevallott confidence-e, hogy az itelete helyes (cimkezett LLM dontesekbol).
    sample_size: int
    buckets: list[CalibrationBucket]
    mean_confidence_correct: Optional[float] = None
    mean_confidence_wrong: Optional[float] = None
    # A legkisebb kuszob, ami felett az FP iteletek legalabb 95%-a helyes (legalabb 5 iteletbol); None, ha nincs.
    suggested_fp_threshold: Optional[float] = None
    # Hany FP itelet van a javasolt kuszob felett: kis mintanal csak irany.
    suggested_fp_threshold_samples: int = 0
    current_threshold: float


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

    # Onallo dontesek (dedup/flood/elnyomas masolatai nelkul) es motoronkenti bontas.
    independent: Optional[EngineMetrics] = None
    by_engine: dict[str, EngineMetrics] = Field(default_factory=dict)
    calibration: Optional[Calibration] = None


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
    # Kulon valaszlepes engedely; a can_* mezok a szerepkorbol szamolt jogok.
    response_allowed: bool = False
    can_suppress: bool = False
    can_block_ip: bool = False
    can_edit_context: bool = False

    @field_validator("response_allowed", mode="before")
    @classmethod
    def _none_is_false(cls, value):
        return bool(value)


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
    response_allowed: bool = False


class UserUpdate(BaseModel):
    # Admin oldali reszleges modositas; a kihagyott mezok valtozatlanok.

    full_name: Optional[str] = Field(default=None, max_length=128)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    response_allowed: Optional[bool] = None
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
