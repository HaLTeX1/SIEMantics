from datetime import datetime, timedelta

from sqlalchemy import update

from app.config import settings
from app.correlation import base_techniques, correlation_ip, is_similar
from app.db import async_session
from app.models import AlertRecord

from conftest import process_alert, wazuh_alert


def tp_alert(alert_id, srcip="203.0.113.50", rule_id="5763", mitre=None, level=12, **extra):
    # Level 12 felett a mock motor mindig eszkalal.
    rule = {"id": rule_id, "level": level, "description": f"rule {rule_id}"}
    if mitre:
        rule["mitre"] = {"id": mitre, "tactic": ["Credential Access"], "technique": ["Brute Force"]}
    payload = wazuh_alert(alert_id=alert_id, level=level, rule=rule, **extra)
    payload["data"] = {"srcip": srcip} if srcip else {}
    return payload


def post(client, payload) -> dict:
    # A webhook csak sorba allit, a feldolgozott rekordot adja vissza.
    return process_alert(client, payload)


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
    assert second["correlated_with"] == first["display_id"]
    assert second["iris_case_id"] == first["iris_case_id"]
    assert len(iris.calls) == 1
    assert iris.added[0]["correlated_with"] == first["display_id"]
    assert iris.added[0]["display_id"] == second["display_id"]

    record = client.get(f"/api/v1/alerts/{second['display_id']}").json()
    assert record["correlated_with"] == first["display_id"]
    assert record["iris_case_id"] == first["iris_case_id"]


def test_shared_mitre_technique_is_similar(client, iris):
    first = post(client, tp_alert("c-1", rule_id="5763", mitre=["T1110.001"]))
    second = post(client, tp_alert("c-2", rule_id="60204", mitre=["T1110.003"]))
    assert second["correlated_with"] == first["display_id"]


def test_different_alert_from_same_ip_opens_new_case(client, iris):
    post(client, tp_alert("c-1", rule_id="5763", mitre=["T1110"]))
    second = post(client, tp_alert("c-2", rule_id="31106", mitre=["T1190"]))
    assert second["correlated_with"] is None
    assert len(iris.calls) == 2


def test_same_alert_from_other_ip_opens_new_case(client, iris):
    post(client, tp_alert("c-1", srcip="203.0.113.50"))
    second = post(client, tp_alert("c-2", srcip="203.0.113.51"))
    assert second["correlated_with"] is None


def host_alert(alert_id, rule_id, agent=None):
    # Forras IP nelkuli riasztas (FIM, user/group valtozas), mint egy useradd riasztas-sorozata.
    return tp_alert(alert_id, srcip=None, rule_id=rule_id, agent=agent or {"id": "024", "name": "IAM_PROD"})


def test_alerts_without_source_ip_from_same_host_share_a_case(client, iris):
    # Egy useradd: FIM a passwd-n, majd "new user added" - mas szabaly, de ugyanaz a muvelet.
    first = post(client, host_alert("fim-1", "100405"))
    second = post(client, host_alert("user-1", "5902"))
    assert second["correlated_with"] == first["display_id"]
    assert second["iris_case_id"] == first["iris_case_id"]
    assert len(iris.calls) == 1 and len(iris.added) == 1


def test_alert_without_source_ip_from_other_host_opens_new_case(client, iris):
    post(client, host_alert("fim-1", "100405"))
    second = post(client, host_alert("fim-2", "100405", agent={"id": "025", "name": "pve1"}))
    assert second["correlated_with"] is None
    assert len(iris.calls) == 2


def test_wazuh_manager_alerts_are_not_correlated_by_host(client, iris):
    manager = {"id": "000", "name": "wazuh-manager"}
    post(client, host_alert("m-1", "100405", agent=manager))
    assert post(client, host_alert("m-2", "5902", agent=manager))["correlated_with"] is None


def test_same_host_alert_outside_host_window_opens_new_case(client, iris):
    first = post(client, host_alert("fim-1", "100405"))

    async def age_first_record():
        async with async_session() as session:
            old = datetime.utcnow() - timedelta(minutes=settings.correlation_host_window_minutes + 1)
            await session.execute(update(AlertRecord).where(AlertRecord.id == first["id"]).values(received_at=old))
            await session.commit()

    client.portal.call(age_first_record)
    assert post(client, host_alert("user-1", "5902"))["correlated_with"] is None


def test_host_correlation_can_be_disabled(client, iris, monkeypatch):
    monkeypatch.setattr(settings, "correlation_host_window_minutes", 0)
    post(client, host_alert("fim-1", "100405"))
    assert post(client, host_alert("user-1", "5902"))["correlated_with"] is None


def test_alert_with_source_ip_is_not_correlated_by_host_alone(client, iris):
    # Forras IP-s riasztasnal az IP szabaly dont: mas szabaly ugyanarrol a hostrol uj eset.
    post(client, host_alert("fim-1", "100405"))
    second = post(client, tp_alert("ssh-1", rule_id="31106", mitre=["T1190"], agent={"id": "024", "name": "IAM_PROD"}))
    assert second["correlated_with"] is None


def test_alert_outside_window_opens_new_case(client, iris):
    first = post(client, tp_alert("c-1"))

    async def age_first_record():
        async with async_session() as session:
            old = datetime.utcnow() - timedelta(hours=settings.correlation_window_hours + 1)
            await session.execute(update(AlertRecord).where(AlertRecord.id == first["id"]).values(received_at=old))
            await session.commit()

    client.portal.call(age_first_record)
    assert post(client, tp_alert("c-2"))["correlated_with"] is None


def test_correlation_can_be_disabled(client, iris, monkeypatch):
    monkeypatch.setattr(settings, "correlation_window_hours", 0)
    post(client, tp_alert("c-1"))
    assert post(client, tp_alert("c-2"))["correlated_with"] is None


def test_closed_case_opens_new_case(client, iris):
    first = post(client, tp_alert("c-1"))
    iris.closed.add(first["iris_case_id"])
    second = post(client, tp_alert("c-2"))
    assert second["correlated_with"] is None
    assert second["iris_case_id"] != first["iris_case_id"]


def test_manual_escalation_is_correlated(client, iris, logged_in):
    first = post(client, tp_alert("c-1"))
    # Level 6, nincs minta: a mock motor needs_review-ra teszi.
    review = post(client, tp_alert("c-2", level=6))
    assert review["status"] == "needs_review"

    record = client.post(f"/api/v1/alerts/{review['display_id']}/escalate").json()
    assert record["correlated_with"] == first["display_id"]
    assert record["iris_case_id"] == first["iris_case_id"]
    assert iris.added[0]["escalated_by"] == "admin"
