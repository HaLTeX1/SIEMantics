from sqlalchemy import MetaData, Table, create_engine, inspect, text

from app.db import _add_missing_columns
from app.models import AlertRecord

NEW_COLUMNS = {
    "raw_payload", "triage_model", "review_reason", "auto_status", "escalated_by_id", "escalated_at", "correlated_with_id",
}


def test_missing_nullable_columns_are_added_to_existing_table():
    engine = create_engine("sqlite://")
    # alert_records as it looked before the new columns existed
    old_table = Table(
        "alert_records",
        MetaData(),
        *(c.copy() for c in AlertRecord.__table__.columns if c.name not in NEW_COLUMNS),
    )
    with engine.begin() as conn:
        old_table.create(conn)
        conn.execute(text(
            "INSERT INTO alert_records (alert_id, received_at, rule_description, severity, status, processing_time_ms) "
            "VALUES ('old', '2026-01-01 00:00:00', 'r', 3, 'SUPPRESSED', 1.0)"
        ))

        _add_missing_columns(conn)
        _add_missing_columns(conn)  # idempotent

        columns = {c["name"] for c in inspect(conn).get_columns("alert_records")}
        assert NEW_COLUMNS <= columns
        # existing rows survive, new columns are NULL
        row = conn.execute(text("SELECT alert_id, auto_status FROM alert_records")).one()
        assert tuple(row) == ("old", None)
