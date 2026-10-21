import os
import tempfile
from pathlib import Path

# Az app.config importja elott: env felulirja a .env-et, igy nincs kulso hivas.
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
    # Alapbol ki, hogy az azonos riasztasokat kuldo tesztek a korrelaciot teszteljek.
    DEDUP_WINDOW_HOURS="0",
    # A hatter IRIS szinkront a tesztek kezzel hivjak.
    IRIS_SYNC_INTERVAL_SECONDS="0",
    HOST_SYNC_INTERVAL_MINUTES="0",
    TRIAGE_SETTLE_SECONDS="0",
    AUTO_CLOSE_SWEEP_MINUTES="0",
)

import pytest  # noqa: E402
from sqlalchemy import event  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import ensure_initial_admin  # noqa: E402
from app.db import Base, async_session, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AlertRecord  # noqa: E402
from app import status  # noqa: E402
from app.pipeline import alert_queue, case_state, iris_client  # noqa: E402
from app.schemas import AlertRecordOut, IrisCaseResult, NormalizedAlert  # noqa: E402

WEBHOOK_HEADERS = {"X-Webhook-Token": "test-token"}


@event.listens_for(engine.sync_engine, "connect")
def _sqlite_foreign_keys(dbapi_connection, _record) -> None:
    # Az eles MariaDB-hez hasonloan a kulso kulcsok ellenorizve, igy az FK hibak a tesztben is elojonnek.
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


async def _reset_db() -> None:
    # A FakeIris esetszamai tesztenkent ujraindulnak, a lezart esetek gyorsitotara se oroklodjon.
    case_state.clear()
    status.reset()
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
    await ensure_initial_admin()


class FakeIris:
    # create_case_from_alert hivasok rogzitese DFIR-IRIS helyett.

    def __init__(self) -> None:
        self.calls: list[dict] = []
        # Korrelalt riasztasok, amik meglevo esetbe kerultek.
        self.added: list[dict] = []
        self.closed: set[int] = set()
        self.fail = False
        # Eset-muveletek: (case_id, label, note-ok), tagek, lezaras.
        self.notes: list[tuple[int, str, list]] = []
        self.tags: dict[int, list[str]] = {}
        self.fail_notes = False
        # IRIS kimenetel (status_id) esetenkent.
        self.outcomes: dict[int, int] = {}
        # Lezarasi annotacio esetenkent; False: a mezo nincs definialva az IRIS-ben.
        self.annotations: dict[int, str] = {}
        self.has_closure_field = True

    async def create_case_from_alert(self, alert: NormalizedAlert, triage, enrichment=None, **kwargs):
        if self.fail:
            raise RuntimeError("iris down")
        self.calls.append({"alert": alert, "triage": triage, **kwargs})
        case_id = 1000 + len(self.calls)
        return IrisCaseResult(case_id=case_id, case_url=f"https://iris.invalid/case?cid={case_id}")

    async def add_alert_to_case(self, case_id: int, alert: NormalizedAlert, triage, enrichment=None, **kwargs):
        if self.fail:
            raise RuntimeError("iris down")
        if case_id in self.closed:
            return None
        self.added.append({"case_id": case_id, "alert": alert, "triage": triage, **kwargs})
        return IrisCaseResult(case_id=case_id, case_url=f"https://iris.invalid/case?cid={case_id}")

    async def is_open(self, case_id: int) -> bool:
        if self.fail:
            raise RuntimeError("iris down")
        return case_id not in self.closed

    async def add_case_notes(self, case_id: int, group_label: str, notes: list) -> None:
        if self.fail or self.fail_notes:
            raise RuntimeError("iris down")
        self.notes.append((case_id, group_label, notes))

    async def add_case_tags(self, case_id: int, tags: list[str]) -> None:
        self.tags.setdefault(case_id, []).extend(tags)

    async def close_case(self, case_id: int) -> None:
        if self.fail:
            raise RuntimeError("iris down")
        self.closed.add(case_id)

    async def get_case(self, case_id: int) -> dict | None:
        if self.fail:
            raise RuntimeError("iris down")
        return {
            "close_date": "2026-10-14" if case_id in self.closed else None,
            "status_id": self.outcomes.get(case_id, 0),
            "case_tags": ",".join(self.tags.get(case_id, [])),
            "custom_attributes": {"Closure": {"Closure annotation": {
                "type": "input_textfield", "value": self.annotations.get(case_id, "")}}}
            if self.has_closure_field else {},
        }

    async def set_closure_annotation(self, case_id: int, text: str) -> bool:
        if not self.has_closure_field:
            return False
        self.annotations[case_id] = text
        return True

    async def set_case_outcome(self, case_id: int, status_id: int) -> None:
        self.outcomes[case_id] = status_id


@pytest.fixture
def iris(monkeypatch) -> FakeIris:
    fake = FakeIris()
    monkeypatch.setattr(iris_client, "create_case_from_alert", fake.create_case_from_alert)
    monkeypatch.setattr(iris_client, "add_alert_to_case", fake.add_alert_to_case)
    for name in ("is_open", "add_case_notes", "add_case_tags", "close_case", "get_case", "set_case_outcome",
                 "set_closure_annotation"):
        monkeypatch.setattr(iris_client, name, getattr(fake, name))
    return fake


@pytest.fixture
def client(iris, monkeypatch):
    # A tesztek a mock motorral triazsolnak, itt a metrikaknak szamitaniuk kell.
    monkeypatch.setattr("app.metrics._NOT_PREDICTIONS", ("analyst", "context"))
    with TestClient(app) as c:
        # Az indulas ujra sorba allitja az elozo teszt QUEUED rekordjait, megvarjuk oket.
        c.portal.call(alert_queue.join)
        c.portal.call(_reset_db)
        yield c
        # Az aiosqlite kapcsolatok ehhez a kliens event loophoz kotottek.
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
    # Riasztas a webhookra, megvarja a hatter triazst, es visszaadja a rekordot.
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
