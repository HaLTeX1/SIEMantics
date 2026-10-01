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
from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.routers import alerts as alerts_router  # noqa: E402
from app.schemas import IrisCaseResult, NormalizedAlert  # noqa: E402

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
    monkeypatch.setattr(alerts_router.iris_client, "create_case_from_alert", fake.create_case_from_alert)
    return fake


@pytest.fixture
def client(iris):
    with TestClient(app) as c:
        c.portal.call(_reset_db)
        yield c
        # pooled aiosqlite connections are bound to this client's event loop
        c.portal.call(engine.dispose)


@pytest.fixture
def logged_in(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin-password"})
    assert res.status_code == 200, res.text
    return client


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
