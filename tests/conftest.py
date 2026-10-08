import os
import tempfile
from pathlib import Path

# Must be set before anything imports app.config: env vars take precedence over
# a developer's .env, so tests never call OpenRouter/VirusTotal/AbuseIPDB or touch a real DB.
_TMP_DIR = Path(tempfile.mkdtemp(prefix="siemantics-tests-"))
os.environ.update(
    OPENROUTER_API_KEY="",
    VIRUSTOTAL_API_KEY="",
    ABUSEIPDB_API_KEY="",
    IRIS_BASE_URL="https://iris.invalid",
    IRIS_API_KEY="test",
    WAZUH_WEBHOOK_TOKEN="test-token",
    ADMIN_USERNAME="admin",
    ADMIN_PASSWORD="admin-password",
    DATABASE_URL=f"sqlite+aiosqlite:///{(_TMP_DIR / 'test.db').as_posix()}",
    REVIEW_CONFIDENCE_THRESHOLD="0.7",
    REVIEW_SEVERITY_FLOOR="12",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import ensure_initial_admin  # noqa: E402
from app.db import Base, async_session, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AlertRecord  # noqa: E402
from app.pipeline import alert_queue, iris_client  # noqa: E402
from app.schemas import AlertRecordOut, IrisCaseResult, NormalizedAlert  # noqa: E402

WEBHOOK_HEADERS = {"X-Webhook-Token": "test-token"}


async def _reset_db() -> None:
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
    await ensure_initial_admin()


class FakeIris:
    """Records create_case_from_alert calls instead of talking to DFIR-IRIS."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail = False

    async def create_case_from_alert(self, alert: NormalizedAlert, triage, enrichment=None, **kwargs):
        if self.fail:
            raise RuntimeError("iris down")
        self.calls.append({"alert": alert, "triage": triage, **kwargs})
        case_id = 1000 + len(self.calls)
        return IrisCaseResult(case_id=case_id, case_url=f"https://iris.invalid/case?cid={case_id}")


@pytest.fixture
def iris(monkeypatch) -> FakeIris:
    fake = FakeIris()
    monkeypatch.setattr(iris_client, "create_case_from_alert", fake.create_case_from_alert)
    return fake


@pytest.fixture
def client(iris):
    with TestClient(app) as c:
        # startup re-queues QUEUED records left by the previous test: let them
        # finish before wiping the tables under the worker
        c.portal.call(alert_queue.join)
        c.portal.call(_reset_db)
        yield c
        # pooled aiosqlite connections are bound to this client's event loop
        c.portal.call(engine.dispose)


@pytest.fixture
def logged_in(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin-password"})
    assert res.status_code == 200, res.text
    return client


async def _record_out(record_id: int) -> dict:
    async with async_session() as session:
        record = await session.get(AlertRecord, record_id)
        return AlertRecordOut.model_validate(record).model_dump(mode="json")


def process_alert(client, payload) -> dict:
    """POST an alert to the webhook, wait for the background worker to triage it,
    and return the resulting decision log record (AlertRecordOut as JSON)."""
    res = client.post("/api/v1/alerts", json=payload, headers=WEBHOOK_HEADERS)
    assert res.status_code == 202, res.text
    assert res.json()["status"] == "queued"
    client.portal.call(alert_queue.join)
    return client.portal.call(_record_out, res.json()["record_id"])


def wazuh_alert(alert_id="a-1", level=3, log="benign event", description="Test rule", **extra) -> dict:
    payload = {
        "id": alert_id,
        "rule": {"id": "100", "level": level, "description": description},
        "agent": {"name": "web01", "ip": "10.0.0.5"},
        "data": {"srcip": "198.51.100.7"},
        "full_log": log,
    }
    payload.update(extra)
    return payload
