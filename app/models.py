from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.enums import AlertStatus, GroundTruth, UserRole


class AlertRecord(Base):
    """One row per processed alert - the evaluation dataset for chapter 6."""

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

    # Manually assigned during lab evaluation to build the labeled test set
    ground_truth: Mapped[GroundTruth | None] = mapped_column(Enum(GroundTruth), nullable=True)
    labeled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # VirusTotal / AbuseIPDB results per IP IoC, populated for escalated alerts
    ioc_enrichment: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Columns below were added later: they must stay nullable so init_db() can
    # add them to an existing table (see db._add_missing_columns).

    # Original Wazuh payload, so a record can be escalated/reprocessed later from the full log
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Concrete model that answered (openrouter/free routes to a different model per call)
    triage_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Why a false-positive verdict was routed to NEEDS_REVIEW instead of SUPPRESSED
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The automatic decision, kept unchanged when an analyst escalates by hand - metrics use this
    auto_status: Mapped[AlertStatus | None] = mapped_column(Enum(AlertStatus), nullable=True)
    escalated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Correlation key (related alerts from the same host)
    agent_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Structured LLM ticket content (summary, actions, investigation steps, ...)
    llm_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    @property
    def display_id(self) -> str:
        """Unique, human-facing alert ID (the Wazuh alert_id is not unique)."""
        return f"#ID-{self.id}"


class User(Base):
    """Dashboard user. Only an admin can create users (see routers/users.py)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.ANALYST)
    # Users are deactivated instead of deleted so case assignments keep a valid owner
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    """Server-side login session - only the SHA-256 of the cookie token is stored."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class CaseAssignment(Base):
    """Assigns a DFIR-IRIS case (AlertRecord.iris_case_id) to a user.

    Kept as a separate table instead of a column on alert_records so it is
    picked up by create_all() on existing databases without a migration.
    """

    __tablename__ = "case_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    iris_case_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
