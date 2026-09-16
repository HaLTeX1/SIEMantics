from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.enums import AlertStatus, GroundTruth


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

    iris_case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    processing_time_ms: Mapped[float] = mapped_column(Float)

    # Manually assigned during lab evaluation to build the labeled test set
    ground_truth: Mapped[GroundTruth | None] = mapped_column(Enum(GroundTruth), nullable=True)
    labeled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
