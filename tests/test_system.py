from fastapi.testclient import TestClient

from app import pipeline
from app.config import settings
from app.iris_client import iris_client
from app.llm_engine import LlmUnavailable
from app.main import app
from app.routers import system
from app.schemas import NormalizedAlert, TriageResult

from conftest import WEBHOOK_HEADERS, process_alert, wazuh_alert

STATUS = "/api/v1/system/status"


def test_status_needs_l2_or_admin(logged_in):
    logged_in.post("/api/v1/users", json={"username": "alice", "password": "analyst-pass", "role": "analyst"})
    alice = TestClient(app)
    alice.post("/api/v1/auth/login", json={"username": "alice", "password": "analyst-pass"})
    assert alice.get(STATUS).status_code == 403
    assert alice.post("/api/v1/system/test-connections").status_code == 403
    assert logged_in.get(STATUS).status_code == 200


def test_status_shows_ingest_queue_settings_without_secrets(logged_in, iris):
    process_alert(logged_in, wazuh_alert("s1"))
    sca = wazuh_alert("s2")
    sca["rule"]["groups"] = ["sca"]
    logged_in.post("/api/v1/alerts", json=sca, headers=WEBHOOK_HEADERS)

    body = logged_in.get(STATUS).json()
    assert body["ingest"]["alerts_24h"] == 1 and body["ingest"]["last_alert_at"] is not None
    assert body["ingest"]["ignored_since_start"] >= 1
    assert body["queue"]["queued"] == 0 and body["queue"]["workers"] == settings.triage_workers
    assert body["settings"]["review_severity_floor"] == 12
    # Titok nem kerul a valaszba, csak hogy be van-e allitva.
    assert body["secrets_set"]["iris_api_key"] is True
    assert all(name not in body["settings"] for name in body["secrets_set"])


def test_status_tracks_llm_outage_and_sync_results(logged_in, iris, monkeypatch):
    async def down(alert, *args, **kwargs):
        from app import status
        status.record_failure("llm", "429 rate limit", quota=True)
        raise LlmUnavailable("429 rate limit", quota=True)

    monkeypatch.setattr(pipeline, "triage_alert", down)
    monkeypatch.setattr(pipeline.alert_queue, "enqueue_later", lambda record_id, delay: None)
    try:
        logged_in.post("/api/v1/alerts", json=wazuh_alert("q1", level=5), headers=WEBHOOK_HEADERS)
        logged_in.portal.call(pipeline.alert_queue.join)
        logged_in.post("/api/v1/cases/sync")

        body = logged_in.get(STATUS).json()
        assert body["llm"]["last_error"] == "429 rate limit" and body["llm"]["quota"] is True
        assert body["llm"]["paused_seconds"] > 0
        assert body["queue"]["queued"] == 1 and body["queue"]["waiting_for_llm"] == 1
        assert body["iris_sync"]["last_result"] == {"checked": 0, "closed": 0, "labeled": 0, "unreadable": 0}
    finally:
        pipeline.alert_queue._paused_until = 0.0


def test_connection_tests(logged_in, monkeypatch):
    async def pong():
        return "pong"

    monkeypatch.setattr(iris_client, "ping", pong)
    monkeypatch.setattr(system, "llm_configured", lambda: True)

    async def key():
        return {"is_free_tier": True, "usage": 0, "limit": None}

    monkeypatch.setattr(system, "key_info", key)
    results = {r["name"]: r for r in logged_in.post("/api/v1/system/test-connections").json()}
    assert results["DFIR-IRIS"]["ok"] is True and results["DFIR-IRIS"]["detail"] == "pong"
    assert results["Wazuh API"]["ok"] is None
    assert results["OpenRouter"]["ok"] is True and "free tier" in results["OpenRouter"]["detail"]

    async def broken():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(iris_client, "ping", broken)
    results = {r["name"]: r for r in logged_in.post("/api/v1/system/test-connections").json()}
    assert results["DFIR-IRIS"]["ok"] is False and "refused" in results["DFIR-IRIS"]["detail"]


def test_llm_engine_records_success_and_failure(client, monkeypatch):
    from app import llm_engine, status

    alert = NormalizedAlert(alert_id="x", rule_description="r", severity=5, log_snippet="l")
    monkeypatch.setattr(llm_engine, "_client", object())

    async def ok(alert, prompt, model=None):
        return TriageResult(is_true_positive=False, confidence=0.9, reasoning="r", engine="openrouter", model="m:free")

    async def fail(alert, prompt, model=None):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(llm_engine, "_openrouter_triage", ok)
    client.portal.call(llm_engine.triage_alert, alert)
    assert status.snapshot("llm")["last_result"] == {"model": "m:free"}

    monkeypatch.setattr(llm_engine, "_openrouter_triage", fail)
    try:
        client.portal.call(llm_engine.triage_alert, alert)
    except LlmUnavailable:
        pass
    snap = status.snapshot("llm")
    assert "connection reset" in snap["last_error"] and snap["quota"] is False
