from datetime import datetime, timedelta

from sqlalchemy import update

from app.config import settings
from app.correlation import base_techniques, correlation_ip, is_similar
from app.db import async_session
from app.models import AlertRecord

from conftest import WEBHOOK_HEADERS, wazuh_alert


def tp_alert(alert_id, srcip="203.0.113.50", rule_id="5763", mitre=None, level=12, **extra):
    # Level 12 felett a mock motor mindig eszkalal.
    rule = {"id": rule_id, "level": level, "description": f"rule {rule_id}"}
    if mitre:
        rule["mitre"] = {"id": mitre, "tactic": ["Credential Access"], "technique": ["Brute Force"]}
    payload = wazuh_alert(alert_id=alert_id, level=level, rule=rule, **extra)
    payload["data"] = {"srcip": srcip} if srcip else {}
    return payload


def post(client, payload) -> dict:
    res = client.post("/api/v1/alerts", json=payload, headers=WEBHOOK_HEADERS)
    assert res.status_code == 202, res.text
    return res.json()


def test_similarity_rules():
    a = {"rule": {"id": "5763", "mitre": {"id": ["T1110.001"]}}, "data": {"srcip": "1.2.3.4"}}
    assert is_similar(a, {"rule": {"id": "5763"}})
    assert is_similar(a, {"rule": {"id": "60204", "mitre": {"id": ["T1110.003"]}}})
    assert not is_similar(a, {"rule": {"id": "31106", "mitre": {"id": ["T1190"]}}})
    assert not is_similar({"rule": {}}, {"rule": {}})
    assert base_techniques({"rule": {"mitre": {"id": "T1059.001"}}}) == {"T1059"}
    assert correlation_ip(a) == "1.2.3.4"
    # Az agent IP nem forras IP.
    assert correlation_ip({"agent": {"ip": "10.0.0.5"}, "data": {}}) is None


def test_same_ip_same_rule_goes_to_existing_case(client, iris, logged_in):
    first = post(client, tp_alert("c-1"))
    second = post(client, tp_alert("c-2"))

    assert first["correlated_with"] is None
    assert second["correlated_with"] == first["id"]
    assert second["case"]["case_id"] == first["case"]["case_id"]
    assert len(iris.calls) == 1
    assert iris.added[0]["correlated_with"] == first["id"]
    assert iris.added[0]["display_id"] == second["id"]

    record = client.get(f"/api/v1/alerts/{second['id']}").json()
    assert record["correlated_with"] == first["id"]
    assert record["iris_case_id"] == first["case"]["case_id"]


def test_shared_mitre_technique_is_similar(client, iris):
    first = post(client, tp_alert("c-1", rule_id="5763", mitre=["T1110.001"]))
    second = post(client, tp_alert("c-2", rule_id="60204", mitre=["T1110.003"]))
    assert second["correlated_with"] == first["id"]


def test_different_alert_from_same_ip_opens_new_case(client, iris):
    post(client, tp_alert("c-1", rule_id="5763", mitre=["T1110"]))
    second = post(client, tp_alert("c-2", rule_id="31106", mitre=["T1190"]))
    assert second["correlated_with"] is None
    assert len(iris.calls) == 2


def test_same_alert_from_other_ip_opens_new_case(client, iris):
    post(client, tp_alert("c-1", srcip="203.0.113.50"))
    second = post(client, tp_alert("c-2", srcip="203.0.113.51"))
    assert second["correlated_with"] is None


def test_alert_without_source_ip_is_not_correlated(client, iris):
    post(client, tp_alert("c-1", srcip=None))
    second = post(client, tp_alert("c-2", srcip=None))
    assert second["correlated_with"] is None
    assert len(iris.calls) == 2


def test_alert_outside_window_opens_new_case(client, iris):
    first = post(client, tp_alert("c-1"))

    async def age_first_record():
        async with async_session() as session:
            old = datetime.utcnow() - timedelta(hours=settings.correlation_window_hours + 1)
            await session.execute(update(AlertRecord).where(AlertRecord.id == first["record_id"]).values(received_at=old))
            await session.commit()

    client.portal.call(age_first_record)
    assert post(client, tp_alert("c-2"))["correlated_with"] is None


def test_correlation_can_be_disabled(client, iris, monkeypatch):
    monkeypatch.setattr(settings, "correlation_window_hours", 0)
    post(client, tp_alert("c-1"))
    assert post(client, tp_alert("c-2"))["correlated_with"] is None


def test_closed_case_opens_new_case(client, iris):
    first = post(client, tp_alert("c-1"))
    iris.closed.add(first["case"]["case_id"])
    second = post(client, tp_alert("c-2"))
    assert second["correlated_with"] is None
    assert second["case"]["case_id"] != first["case"]["case_id"]


def test_manual_escalation_is_correlated(client, iris, logged_in):
    first = post(client, tp_alert("c-1"))
    # Level 6, nincs minta: a mock motor needs_review-ra teszi.
    review = post(client, tp_alert("c-2", level=6))
    assert review["status"] == "needs_review"

    record = client.post(f"/api/v1/alerts/{review['id']}/escalate").json()
    assert record["correlated_with"] == first["id"]
    assert record["iris_case_id"] == first["case"]["case_id"]
    assert iris.added[0]["escalated_by"] == "admin"
