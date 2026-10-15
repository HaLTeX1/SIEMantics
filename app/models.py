from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.enums import AlertStatus, GroundTruth, UserRole


class AlertRecord(Base):

    __tablename__ = "alert_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(128), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_description: Mapped[str] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer)

    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus))
    llm_is_true_positive: Mapped[bool | None] = mapped_column(nullable=True)
    llm_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_iocs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    triage_engine: Mapped[str | None] = mapped_column(String(16), nullable=True)

    iris_case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    processing_time_ms: Mapped[float] = mapped_column(Float)

    # Ground truth cimke a kiertekeleshez, az analyst allitja be.
    ground_truth: Mapped[GroundTruth | None] = mapped_column(Enum(GroundTruth), nullable=True)
    labeled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # VirusTotal / AbuseIPDB eredmenyek IP IoC-nkent, eszkalalt riasztasnal.
    ioc_enrichment: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Eredeti Wazuh payload, kesobbi eszkalaciohoz / ujrafeldolgozashoz.
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # A valaszolo konkret modell (az openrouter/free hivasonkent mas modellt valaszt).
    triage_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Miert lett NEEDS_REVIEW a SUPPRESSED helyett.
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Az automatikus dontes; kezi eszkalacional is valtozatlan, a metrikak ezt hasznaljak.
    auto_status: Mapped[AlertStatus | None] = mapped_column(Enum(AlertStatus), nullable=True)
    escalated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Korrelacios kulcs (kapcsolodo riasztasok ugyanarrol a hostrol).
    agent_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Az LLM strukturalt elemzese (osszefoglalo, teendok, vizsgalati lepesek).
    llm_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # A korabbi riasztas ID-ja, akinek az IRIS esetebe ez a riasztas bekerult.
    correlated_with_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # SIEMantics csoport: a csoport elso (fo) riasztasanak ID-ja, a fo riasztasnal a sajatja.
    group_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Normalizalt ujjlenyomat a duplikatum-szureshez (app/fingerprint.py).
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Wazuh szabaly ID, a flood szamlalashoz es a suppression szabalyokhoz.
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    # Az elnyomo suppression szabaly, ha szabaly nyomta el.
    suppression_rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    # Mikor latta a SIEMantics lezartnak az IRIS esetet; utana nem kerdezi le ujra.
    case_closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Az IRIS eset "Closure annotation" egyedi mezoje (lezarasi annotacio).
    case_closure_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def display_id(self) -> str:
        # Egyedi riasztas azonosito (a Wazuh alert_id nem egyedi).
        return f"ID-{self.id}"

    @property
    def correlated_with(self) -> str | None:
        return f"ID-{self.correlated_with_id}" if self.correlated_with_id else None

    @property
    def group(self) -> str | None:
        return f"ID-{self.group_id}" if self.group_id else None


class User(Base):
    # Dashboard felhasznalo; csak admin hozhat letre.

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.ANALYST)
    # Aktiv-e; deaktivalaskor a munkamenetei azonnal ervenytelenek.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Kulon engedely valaszlepesre (IP blokkolas) L2 szerepkor nelkul is.
    response_allowed: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def can_suppress(self) -> bool:
        # Elnyomo szabaly: L2 (es admin).
        return self.role in (UserRole.ADMIN, UserRole.L2)

    @property
    def can_block_ip(self) -> bool:
        # Valaszlepes: L2 (es admin), vagy kulon engedelyezett felhasznalo.
        return self.role in (UserRole.ADMIN, UserRole.L2) or bool(self.response_allowed)


class UserSession(Base):
    # Szerver oldali munkamenet; csak a cookie token SHA-256-ja tarolodik.

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class CaseAssignment(Base):
    # IRIS eset felelose; kulon tabla, mert egy esethez tobb riasztas tartozhat.

    __tablename__ = "case_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    iris_case_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ResponseAction(Base):
    # Wazuh Active Response lepes (IP blokkolas) naplozasa.

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(32))
    ip: Mapped[str] = mapped_column(String(64))
    # agent: a riasztas agentje, all: minden aktiv agent.
    scope: Mapped[str] = mapped_column(String(16))
    duration_seconds: Mapped[int] = mapped_column(Integer)
    # Agentenkent: {"id", "name", "command", "ok", "error"}.
    targets: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # sent, partial, failed
    status: Mapped[str] = mapped_column(String(16))
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    iris_case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    iris_noted: Mapped[bool] = mapped_column(Boolean, default=False)


class SuppressionRule(Base):
    # Elemzo altal felvett elnyomas: az egyezo riasztasok LLM nelkul SUPPRESSED-ek.

    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # exact: ujjlenyomat, rule_host: szabaly + host, rule: szabaly barmelyik hoston.
    scope: Mapped[str] = mapped_column(String(16))
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Az alapul szolgalo riasztas leirasa a listahoz.
    description: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def is_live(self, now: datetime) -> bool:
        return self.is_active and (self.expires_at is None or self.expires_at > now)
