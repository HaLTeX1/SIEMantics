import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import pipeline
from app.config import settings
from app.db import async_session
from app.enums import AlertStatus
from app.main import app
from app.models import AlertRecord, SuppressionRule
from app.pipeline import alert_queue

from conftest import WEBHOOK_HEADERS, process_alert, wazuh_alert

SUPPRESS = "/api/v1/suppressions"
BULK_FP = "/api/v1/alerts/bulk/false-positive"
BULK_DELETE = "/api/v1/alerts/bulk/delete"


def alert(alert_id, level=6, host="h1", srcip="198.51.100.1", rule_id="5710"):
    payload = wazuh_alert(alert_id=alert_id, level=level, agent={"id": "001", "name": host, "ip": "10.0.0.5"},
                          data={"srcip": srcip})
    payload["rule"]["id"] = rule_id
    return payload


def get(client, display_id):
    return client.get(f"/api/v1/alerts/{display_id}").json()


@pytest.fixture
def triage_calls(monkeypatch) -> list:
    calls: list = []
    real = pipeline.triage_alert

    async def spy(alert, related=None):
        calls.append(alert.alert_id)
        return await real(alert, related)

    monkeypatch.setattr(pipeline, "triage_alert", spy)
    return calls


@pytest.fixture
def flood(monkeypatch):
    monkeypatch.setattr(settings, "flood_threshold", 3)
    monkeypatch.setattr(settings, "flood_window_minutes", 10)


# --- suppression szabalyok

def test_exact_rule_suppresses_repeats_without_llm(logged_in, triage_calls):
    first = process_alert(logged_in, alert("s1"))
    res = logged_in.post(SUPPRESS, json={"alert_refs": [first["display_id"]], "scope": "exact", "reason": "noisy"})
    assert res.status_code == 200, res.text
    rule = res.json()["rules"][0]
    assert rule["scope"] == "exact" and rule["created_by"]["username"] == "admin"
    # A meglevo needs_review riasztas is elnyomva.
    assert res.json()["suppressed"] == [first["display_id"]]

    repeat = process_alert(logged_in, alert("s2"))
    other_ip = process_alert(logged_in, alert("s3", srcip="198.51.100.99"))
    assert triage_calls == ["s1", "s3"]
    assert repeat["status"] == "suppressed" and repeat["triage_engine"] == "suppression"
    assert repeat["suppression_rule_id"] == rule["id"] and "noisy" in repeat["review_reason"]
    assert other_ip["triage_engine"] != "suppression"
    # A talalatok egy csoportba kerulnek.
    assert get(logged_in, repeat["display_id"])["group"] == first["display_id"]
    assert logged_in.get(SUPPRESS).json()[0]["hit_count"] == 2


def test_rule_host_scope_matches_other_fields_but_not_other_hosts(logged_in, triage_calls):
    first = process_alert(logged_in, alert("r1"))
    logged_in.post(SUPPRESS, json={"alert_refs": [first["display_id"]], "scope": "rule_host"})

    same_host = process_alert(logged_in, alert("r2", srcip="203.0.113.5"))
    other_host = process_alert(logged_in, alert("r3", host="h2"))
    assert same_host["triage_engine"] == "suppression"
    assert other_host["triage_engine"] != "suppression"


def test_rule_scope_matches_every_host(logged_in):
    first = process_alert(logged_in, alert("g1"))
    logged_in.post(SUPPRESS, json={"alert_refs": [first["display_id"]], "scope": "rule"})
    assert process_alert(logged_in, alert("g2", host="h9", srcip="203.0.113.9"))["status"] == "suppressed"
    assert process_alert(logged_in, alert("g3", rule_id="9999"))["triage_engine"] != "suppression"


def test_existing_escalated_alerts_are_not_touched(logged_in, iris):
    escalated = process_alert(logged_in, alert("e1", level=13))
    review = process_alert(logged_in, alert("e2", srcip="203.0.113.2"))
    body = logged_in.post(SUPPRESS, json={"alert_refs": [review["display_id"]], "scope": "rule"}).json()

    assert body["suppressed"] == [review["display_id"]]
    after = get(logged_in, review["display_id"])
    # Az automatikus dontes a metrikakhoz megmarad.
    assert after["status"] == "suppressed" and after["auto_status"] == "needs_review"
    assert get(logged_in, escalated["display_id"])["status"] == "escalated"


def test_apply_existing_can_be_skipped_and_rules_are_reused(logged_in):
    first = process_alert(logged_in, alert("x1"))
    req = {"alert_refs": [first["display_id"]], "scope": "exact", "apply_existing": False}
    a = logged_in.post(SUPPRESS, json=req).json()
    b = logged_in.post(SUPPRESS, json=req).json()
    assert a["suppressed"] == [] and a["rules"][0]["id"] == b["rules"][0]["id"]
    assert get(logged_in, first["display_id"])["status"] == "needs_review"


def test_deactivated_and_expired_rules_do_not_apply(logged_in):
    first = process_alert(logged_in, alert("d1"))
    rule = logged_in.post(SUPPRESS, json={"alert_refs": [first["display_id"]], "duration_hours": 1}).json()["rules"][0]
    assert logged_in.delete(f"{SUPPRESS}/{rule['id']}").json()["is_active"] is False
    assert logged_in.get(SUPPRESS).json() == []
    assert len(logged_in.get(SUPPRESS, params={"include_inactive": True}).json()) == 1
    assert process_alert(logged_in, alert("d2"))["triage_engine"] != "suppression"

    rule = logged_in.post(SUPPRESS, json={"alert_refs": [first["display_id"]], "duration_hours": 1}).json()["rules"][0]

    async def expire():
        async with async_session() as session:
            (await session.get(SuppressionRule, rule["id"])).expires_at = datetime.utcnow() - timedelta(minutes=1)
            await session.commit()

    logged_in.portal.call(expire)
    assert process_alert(logged_in, alert("d3"))["triage_engine"] != "suppression"


def test_suppress_unknown_alert_is_404(logged_in):
    assert logged_in.post(SUPPRESS, json={"alert_refs": ["ID-999999"]}).status_code == 404


# --- flood

def test_flood_takes_over_the_latest_decision(logged_in, iris, flood, triage_calls):
    # Mas forras IP, igy nem duplikatum, csak ugyanaz a szabaly es host.
    records = [process_alert(logged_in, alert(f"f{i}", level=13, srcip=f"203.0.113.{i}")) for i in range(1, 6)]
    assert triage_calls == ["f1", "f2"]
    flooded = records[2:]
    assert all(r["triage_engine"] == "flood" and r["status"] == "escalated" for r in flooded)
    # Az utolso dontes esetet kapja, uj IRIS eset nelkul.
    assert {r["iris_case_id"] for r in flooded} == {records[1]["iris_case_id"]}
    assert flooded[0]["correlated_with"] == records[1]["display_id"]


def test_flood_does_not_downgrade_a_higher_level_alert(logged_in, iris, flood, triage_calls):
    for i in (1, 2):
        process_alert(logged_in, alert(f"l{i}", level=3, srcip=f"203.0.113.{i}"))
    higher = process_alert(logged_in, alert("l3", level=13, srcip="203.0.113.3"))
    assert triage_calls == ["l1", "l2", "l3"]
    assert higher["status"] == "escalated" and higher["triage_engine"] != "flood"


def test_flood_is_per_host(logged_in, flood, triage_calls):
    for i in range(1, 4):
        process_alert(logged_in, alert(f"p{i}", host=f"h{i}", srcip=f"203.0.113.{i}"))
    assert triage_calls == ["p1", "p2", "p3"]


def test_identical_burst_is_triaged_once_with_parallel_workers(logged_in, monkeypatch):
    monkeypatch.setattr(settings, "dedup_window_hours", 24)
    triage_calls = []
    real = pipeline.triage_alert

    async def slow(alert, related=None):
        # Lassu LLM hivas, hogy a workerek tenylegesen parhuzamosan fussanak.
        triage_calls.append(alert.alert_id)
        await asyncio.sleep(0.05)
        return await real(alert, related)

    monkeypatch.setattr(pipeline, "triage_alert", slow)
    logged_in.portal.call(alert_queue.stop)
    logged_in.portal.call(alert_queue.start, 4)
    ids = []
    for i in range(6):
        res = logged_in.post("/api/v1/alerts", json=alert(f"b{i}"), headers=WEBHOOK_HEADERS)
        ids.append(res.json()["id"])
    logged_in.portal.call(alert_queue.join)
    assert len(triage_calls) == 1
    assert {get(logged_in, i)["triage_engine"] for i in ids[1:]} == {"dedup"}


# --- tomeges muveletek

async def _queued_record(alert_id: str) -> str:
    # Sorba nem allitott, triazsra varo rekord.
    async with async_session() as session:
        record = AlertRecord(alert_id=alert_id, rule_description="r", severity=5, status=AlertStatus.QUEUED,
                             processing_time_ms=0.0, raw_payload=alert(alert_id), rule_id="5710", agent_name="h1")
        session.add(record)
        await session.commit()
        return record.display_id


def test_bulk_false_positive_closes_cases_and_queued_alerts(logged_in, iris):
    escalated = process_alert(logged_in, alert("m1", level=13))
    review = process_alert(logged_in, alert("m2", host="h2", srcip="203.0.113.2"))
    queued = logged_in.portal.call(_queued_record, "m3")

    res = logged_in.post(BULK_FP, json={"alert_refs": [escalated["display_id"], review["display_id"], queued],
                                        "reason": "scanner flood"})
    assert res.status_code == 200, res.text
    assert sorted(res.json()["labeled"]) == sorted([escalated["display_id"], review["display_id"], queued])
    assert res.json()["closed_cases"] == [escalated["iris_case_id"]]
    assert escalated["iris_case_id"] in iris.closed

    assert get(logged_in, review["display_id"])["ground_truth"] == "false_positive"
    closed = get(logged_in, queued)
    assert closed["status"] == "suppressed" and closed["triage_engine"] == "analyst"
    # Triazs elott lezarva: nem predikcio.
    assert logged_in.get("/api/v1/metrics").json()["sample_size"] == 2


def test_bulk_delete_is_admin_only(logged_in):
    a = process_alert(logged_in, alert("z1"))
    b = process_alert(logged_in, alert("z2", srcip="203.0.113.2"))

    logged_in.post("/api/v1/users", json={"username": "alice", "password": "analyst-pass", "role": "analyst"})
    alice = TestClient(app)
    alice.post("/api/v1/auth/login", json={"username": "alice", "password": "analyst-pass"})
    assert alice.post(BULK_DELETE, json={"alert_refs": [a["display_id"]]}).status_code == 403

    res = logged_in.post(BULK_DELETE, json={"alert_refs": [a["display_id"], b["display_id"]]})
    assert res.status_code == 200 and sorted(res.json()["deleted"]) == sorted([a["display_id"], b["display_id"]])
    assert logged_in.get(f"/api/v1/alerts/{a['display_id']}").status_code == 404
