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

    @property
    def display_id(self) -> str:
        # Egyedi riasztas azonosito (a Wazuh alert_id nem egyedi).
        return f"ID-{self.id}"

    @property
    def correlated_with(self) -> str | None:
        return f"ID-{self.correlated_with_id}" if self.correlated_with_id else None


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


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
